package service_test

import (
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

func TestRevokeCancelsPendingRenewalAndPoisonedPublication(t *testing.T) {
	for _, lane := range []string{"V1", "V2"} {
		t.Run(lane, func(t *testing.T) {
			ctx := t.Context()
			fx := newRegFixture(t)
			id := registerAndActivate(t, fx, fx.svc)
			stale, err := fx.agents.FindByAgentID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fx.svc.SubmitServerCertRenewal(ctx, id, renewalInput(t, fx, "CSR"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fx.outboxStore.Enqueue(ctx, "AGENT_RENEWED", id, lane, []byte(`{}`), time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			result, err := fx.svc.Revoke(ctx, id, service.RevokeInput{Reason: domain.RevocationCessationOfOperation, SchemaVersion: lane})
			if err != nil {
				t.Fatal(err)
			}
			if result.Registration.Status != domain.StatusRevoked {
				t.Fatal("registration not revoked")
			}
			rows, err := fx.outboxStore.Ready(ctx, 100)
			if err != nil || len(rows) != 1 || rows[0].EventType != "AGENT_REVOKED" || rows[0].SchemaVersion != lane {
				t.Fatalf("revocation not ready: %+v, %v", rows, err)
			}
			renewal, err := fx.renewals.FindByAgentID(ctx, id)
			if err != nil || renewal.CompletedAt.IsZero() || renewal.FailureReason != "Agent revoked" {
				t.Fatalf("pending renewal not cancelled: %+v, %v", renewal, err)
			}
			csr, err := fx.certs.FindCSRByID(ctx, id, renewal.ServerCsrID)
			if err != nil || csr.Status != domain.CSRStatusRejected {
				t.Fatalf("pending CSR not rejected: %+v, %v", csr, err)
			}
			if err := fx.agents.Save(ctx, stale); err == nil {
				t.Fatal("stale ACTIVE aggregate resurrected revocation")
			}
			if _, err := fx.svc.VerifyRenewalACME(ctx, id); err == nil {
				t.Fatal("cancelled renewal completed")
			}
			if _, err := fx.svc.Revoke(ctx, id, service.RevokeInput{Reason: domain.RevocationCessationOfOperation, SchemaVersion: lane}); err != nil {
				t.Fatal(err)
			}
			again, err := fx.outboxStore.Ready(ctx, 100)
			if err != nil || len(again) != 1 || again[0].ID != rows[0].ID {
				t.Fatalf("duplicate revocation enqueued: %+v, %v", again, err)
			}
		})
	}
}
