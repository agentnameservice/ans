package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/agentnameservice/ans/internal/adapter/dns"
	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/ra/service"
	"github.com/agentnameservice/ans/internal/tl/event"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
	tlservice "github.com/agentnameservice/ans/internal/tl/service"
)

// Exercise real SQLite transactions, issuance, and detached signatures across
// successive rotations. A snapshot must retain every still-valid certificate.
func TestCertificateRenewals_PublishSignedOverlapSnapshots(t *testing.T) {
	for _, lane := range []string{"V1", "V2"} {
		for _, kind := range []string{"CSR", "BYOC"} {
			t.Run(lane+"/"+kind, func(t *testing.T) {
				ctx := context.Background()
				fx := newRegFixture(t)
				id := registerAndActivate(t, fx, fx.svc)
				for round := 1; round <= 2; round++ {
					input := renewalInput(t, fx, kind)
					if _, err := fx.svc.SubmitServerCertRenewal(ctx, id, input); err != nil {
						t.Fatal(err)
					}
					if lane == "V1" {
						if _, err := fx.svc.VerifyRenewalACMEV1(ctx, id); err != nil {
							t.Fatal(err)
						}
					} else if _, err := fx.svc.VerifyRenewalACME(ctx, id); err != nil {
						t.Fatal(err)
					}
					assertRenewalSnapshot(t, fx, lane, round, round+1)

					csr := testCSR(t, fx.req.AnsName.String())
					if lane == "V1" {
						if _, err := fx.svc.SubmitIdentityCSRV1(ctx, id, csr); err != nil {
							t.Fatal(err)
						}
					} else if _, err := fx.svc.SubmitIdentityCSR(ctx, id, csr); err != nil {
						t.Fatal(err)
					}
					assertRenewalSnapshot(t, fx, lane, round+1, round+1)
				}
			})
		}
	}
}

func renewalInput(t *testing.T, fx *regFixture, kind string) service.SubmitRenewalInput {
	t.Helper()
	csr := testServerCSR(t, fx.req.AnsName.FQDN())
	if kind == "CSR" {
		return service.SubmitRenewalInput{ServerCsrPEM: csr}
	}
	ctx := context.Background()
	order, err := fx.serverCA.CreateOrder(ctx, fx.req.AnsName.FQDN())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := fx.serverCA.FinalizeOrder(ctx, port.FinalizeOrderRequest{
		OrderRef: order.OrderRef, CSRPEM: csr, FQDN: fx.req.AnsName.FQDN(),
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service.SubmitRenewalInput{
		ServerCertificatePEM: cert.CertPEM, ServerCertificateChainPEM: cert.ChainPEM,
	}
}

func assertRenewalSnapshot(t *testing.T, fx *regFixture, lane string, identities, servers int) {
	t.Helper()
	rows, err := fx.outboxStore.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("ready events = %d, want one per agent", len(rows))
	}
	row := rows[len(rows)-1]
	if row.SchemaVersion != lane || row.EventType != string(event.TypeAgentRenewed) {
		t.Fatalf("wrong outbox lane/type: %+v", row)
	}
	var payload service.OutboxPayload
	if err := json.Unmarshal(row.PayloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), fx.signer.KeyManager,
		payload.ProducerSignature, payload.InnerEventCanonical); err != nil {
		t.Fatalf("renewal signature: %v", err)
	}
	assertRenewalStatusSchema(t, lane, payload.InnerEventCanonical)
	if lane == "V1" {
		var inner eventv1.Event
		if err := json.Unmarshal(payload.InnerEventCanonical, &inner); err != nil {
			t.Fatal(err)
		}
		if inner.EventType != eventv1.TypeAgentRenewed || inner.RenewalStatus != "SUCCESS" ||
			len(inner.Attestations.ValidIdentityCerts) != identities ||
			len(inner.Attestations.ValidServerCerts) != servers {
			t.Fatalf("wrong V1 renewal snapshot: %s", payload.InnerEventCanonical)
		}
		latest, err := fx.byoc.FindLatestValidByAgentID(context.Background(), row.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		if inner.Attestations.ServerCert == nil ||
			inner.Attestations.ServerCert.Fingerprint != "SHA256:"+latest.Fingerprint {
			t.Fatal("V1 primary server certificate is not the replacement")
		}
	} else {
		var inner event.Event
		if err := json.Unmarshal(payload.InnerEventCanonical, &inner); err != nil {
			t.Fatal(err)
		}
		if inner.EventType != event.TypeAgentRenewed || inner.RenewalStatus != "SUCCESS" ||
			len(inner.Attestations.IdentityCerts) != identities ||
			len(inner.Attestations.ServerCerts) != servers {
			t.Fatalf("wrong V2 renewal snapshot: %s", payload.InnerEventCanonical)
		}
	}
	// A worker retry must read identical bytes/signatures before acknowledging.
	retry, err := fx.outboxStore.Claim(context.Background(), 100)
	if err != nil || len(retry) != 1 || !bytes.Equal(row.PayloadJSON, retry[0].PayloadJSON) {
		t.Fatalf("retry changed the signed outbox payload: %v", err)
	}
	if err := fx.outboxStore.MarkSent(context.Background(), row.ID, "test-renewal-log"); err != nil {
		t.Fatal(err)
	}
}

func assertRenewalStatusSchema(t *testing.T, lane string, raw []byte) {
	t.Helper()
	schemas, err := tlservice.NewSchemaService()
	if err != nil {
		t.Fatal(err)
	}
	schemaJSON, err := schemas.Get(t.Context(), lane)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatal(err)
	}
	var inner struct {
		RenewalStatus string `json:"renewalStatus"`
	}
	if err := json.Unmarshal(raw, &inner); err != nil {
		t.Fatal(err)
	}
	allowed := schema.Definitions["Event"].Properties["renewalStatus"].Enum
	if !slices.Contains(allowed, inner.RenewalStatus) {
		t.Fatalf("%s renewalStatus %q is outside the served TL schema enum %v", lane, inner.RenewalStatus, allowed)
	}
}

func TestBYOCRenewal_ChallengeAndCancellationDoNotChangeLiveCertificate(t *testing.T) {
	ctx := context.Background()
	fx := newRegFixture(t)
	id := registerAndActivate(t, fx, fx.svc)
	before, err := fx.byoc.FindLatestValidByAgentID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	svc := rebuildWithIssuer(fx, fx.serverCA, failingDNSVerifier{}, nil)
	if _, err := svc.SubmitServerCertRenewal(ctx, id, renewalInput(t, fx, "BYOC")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyRenewalACME(ctx, id); err == nil {
		t.Fatal("unpublished challenge accepted")
	}
	if err := svc.CancelServerCertRenewal(ctx, id); err != nil {
		t.Fatal(err)
	}
	live, err := fx.byoc.FindByAgentID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].Fingerprint != before.Fingerprint {
		t.Fatal("unverified or canceled certificate entered the live certificate set")
	}
	rows, err := fx.outboxStore.Claim(ctx, 100)
	if err != nil || len(rows) != 0 {
		t.Fatalf("canceled renewal published: rows=%d error=%v", len(rows), err)
	}
}

func TestCertificateRenewal_OutboxFailureRollsBackCertificateAndRenewal(t *testing.T) {
	for _, kind := range []string{"IDENTITY", "CSR", "BYOC"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			fx := newRegFixture(t)
			id := registerAndActivate(t, fx, fx.svc)
			svc := service.NewRegistrationService(
				fx.agents, fx.endpoints, fx.certs, fx.byoc, fx.renewals,
				fx.validator, fx.identityCA, fx.bus, failingOutbox{}, fx.uow, fx.discoveryReg,
			).WithSigner(fx.signer).WithServerCertificateIssuer(fx.serverCA).
				WithDNSVerifier(dns.NewNoopVerifier())
			if kind == "IDENTITY" {
				if _, err := svc.SubmitIdentityCSR(ctx, id, testCSR(t, fx.req.AnsName.String())); err == nil {
					t.Fatal("outbox failure was swallowed")
				}
			} else {
				if _, err := svc.SubmitServerCertRenewal(ctx, id, renewalInput(t, fx, kind)); err != nil {
					t.Fatal(err)
				}
				if _, err := svc.VerifyRenewalACME(ctx, id); err == nil {
					t.Fatal("outbox failure was swallowed")
				}
				r, err := fx.renewals.FindPendingByAgentID(ctx, id)
				if err != nil || !r.CompletedAt.IsZero() || r.Validation.Status == domain.ValidationVerified {
					t.Fatalf("renewal state escaped rollback: %+v, %v", r, err)
				}
			}
			identityCerts, err := fx.certs.FindIdentityCertificatesByAgent(ctx, id)
			if err != nil || len(identityCerts) != 1 {
				t.Fatalf("identity certificate escaped rollback: %d, %v", len(identityCerts), err)
			}
			serverCerts, err := fx.byoc.FindByAgentID(ctx, id)
			if err != nil || len(serverCerts) != 1 {
				t.Fatalf("server certificate escaped rollback: %d, %v", len(serverCerts), err)
			}
			assertNoRenewalOutbox(t, fx.outboxStore)
		})
	}
}

func assertNoRenewalOutbox(t *testing.T, store *sqlite.OutboxStore) {
	t.Helper()
	rows, err := store.Claim(context.Background(), 100)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatal("failed renewal published an event")
	}
}
