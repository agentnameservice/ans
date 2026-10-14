package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/ra/service"
)

type renewalAfterRead struct {
	port.RenewalStore
	once      sync.Once
	afterRead func()
}

func (s *renewalAfterRead) FindByAgentID(ctx context.Context, agentID string) (*domain.ServerCertificateRenewal, error) {
	r, err := s.RenewalStore.FindByAgentID(ctx, agentID)
	if err == nil {
		s.once.Do(s.afterRead)
	}
	return r, err
}

func TestCancelRenewal_ConcurrentCompletionPreservesPublishedRenewal(t *testing.T) {
	for _, kind := range []string{"CSR", "BYOC"} {
		t.Run(kind, func(t *testing.T) {
			fx := newRegFixture(t)
			id := registerAndActivate(t, fx, fx.svc)
			if _, err := fx.svc.SubmitServerCertRenewal(t.Context(), id, renewalInput(t, fx, kind)); err != nil {
				t.Fatal(err)
			}
			store := &renewalAfterRead{
				RenewalStore: fx.renewals,
				// Complete after cancellation has read the pending state but
				// before it starts changing the CSR or deleting the renewal.
				afterRead: func() {
					if _, err := fx.svc.VerifyRenewalACME(t.Context(), id); err != nil {
						t.Fatalf("complete renewal during cancellation: %v", err)
					}
				},
			}
			cancelSvc := service.NewRegistrationService(
				fx.agents, fx.endpoints, fx.certs, fx.byoc, store,
				fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow, fx.discoveryReg,
			)
			err := cancelSvc.CancelServerCertRenewal(t.Context(), id)
			mustErrCode(t, err, "RENEWAL_ALREADY_COMPLETED")
			completed, err := fx.renewals.FindByAgentID(t.Context(), id)
			if err != nil || completed.CompletedAt.IsZero() {
				t.Fatalf("cancellation removed the completed renewal: %+v err=%v", completed, err)
			}
			assertRenewalSnapshot(t, fx, "V2", 1, 2)
		})
	}
}

func TestCancelRenewal_ConcurrentReplacementIsPreserved(t *testing.T) {
	fx := newRegFixture(t)
	id := registerAndActivate(t, fx, fx.svc)
	first, err := fx.svc.SubmitServerCertRenewal(t.Context(), id, renewalInput(t, fx, "CSR"))
	if err != nil {
		t.Fatal(err)
	}
	store := &renewalAfterRead{
		RenewalStore: fx.renewals,
		afterRead: func() {
			if err := fx.svc.CancelServerCertRenewal(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			if _, err := fx.svc.SubmitServerCertRenewal(t.Context(), id, renewalInput(t, fx, "CSR")); err != nil {
				t.Fatal(err)
			}
		},
	}
	cancelSvc := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, fx.byoc, store,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow, fx.discoveryReg,
	)
	mustErrCode(t, cancelSvc.CancelServerCertRenewal(t.Context(), id), "RENEWAL_NOT_PENDING")
	replacement, err := fx.renewals.FindPendingByAgentID(t.Context(), id)
	if err != nil || replacement.ID == first.Renewal.ID {
		t.Fatalf("replacement renewal was not preserved: %+v err=%v", replacement, err)
	}
	assertNoRenewalOutbox(t, fx.outboxStore)
}

func TestCancelRenewal_StorageFailuresRollBackCSRAndRenewal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger string
	}{
		{"csr-update", `CREATE TRIGGER fail_cancel BEFORE UPDATE OF status ON agent_csrs
			WHEN NEW.status = 'REJECTED' BEGIN SELECT RAISE(FAIL, 'injected CSR failure'); END`},
		{"renewal-delete", `CREATE TRIGGER fail_cancel BEFORE DELETE ON server_cert_renewals
			BEGIN SELECT RAISE(FAIL, 'injected renewal failure'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRegFixture(t)
			id := registerAndActivate(t, fx, fx.svc)
			submitted, err := fx.svc.SubmitServerCertRenewal(t.Context(), id, renewalInput(t, fx, "CSR"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fx.db.DBX().ExecContext(t.Context(), tc.trigger); err != nil {
				t.Fatal(err)
			}
			if err := fx.svc.CancelServerCertRenewal(t.Context(), id); err == nil {
				t.Fatal("cancellation swallowed the storage failure")
			}
			if _, err := fx.renewals.FindPendingByAgentID(t.Context(), id); err != nil {
				t.Fatalf("failed cancellation removed the pending renewal: %v", err)
			}
			csr, err := fx.certs.FindCSRByID(t.Context(), id, submitted.CsrID)
			if err != nil || csr.Status != domain.CSRStatusPending {
				t.Fatalf("failed cancellation changed the CSR: %+v err=%v", csr, err)
			}
			assertNoRenewalOutbox(t, fx.outboxStore)
			if _, err := fx.db.DBX().ExecContext(t.Context(), "DROP TRIGGER fail_cancel"); err != nil {
				t.Fatal(err)
			}
			if err := fx.svc.CancelServerCertRenewal(t.Context(), id); err != nil {
				t.Fatalf("retry cancellation: %v", err)
			}
			if _, err := fx.renewals.FindByAgentID(t.Context(), id); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("successful cancellation retained the renewal: %v", err)
			}
			csr, err = fx.certs.FindCSRByID(t.Context(), id, submitted.CsrID)
			if err != nil || csr.Status != domain.CSRStatusRejected {
				t.Fatalf("successful cancellation did not reject the CSR: %+v err=%v", csr, err)
			}
		})
	}
}
