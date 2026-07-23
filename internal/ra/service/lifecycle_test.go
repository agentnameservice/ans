package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
	event "github.com/agentnameservice/ans/internal/tl/event"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
)

// TestVerifyACME_NoIdentityCSR_ReachesActiveNoCert covers the optional
// identity-CSR lifecycle: an agent registered without an identity CSR
// must drive through verify-acme → verify-dns to ACTIVE, with verify-acme
// skipping identity issuance entirely (no error, no identity cert).
func TestVerifyACME_NoIdentityCSR_ReachesActiveNoCert(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	req := fx.req
	req.IdentityCSRPEM = ""

	resp, err := fx.svc.RegisterAgent(context.Background(), req)
	if err != nil {
		t.Fatalf("precondition: register without identity CSR should succeed; got: %v", err)
	}
	agentID := resp.Registration.AgentID

	if _, err := fx.svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme must skip identity issuance, not error; got: %v", err)
	}
	if _, err := fx.svc.VerifyDNS(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-dns should drive to ACTIVE; got: %v", err)
	}

	got, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatalf("FindByAgentID: %v", err)
	}
	if got.Status != domain.StatusActive {
		t.Fatalf("agent registered without an identity CSR must reach ACTIVE; got %q", got.Status)
	}
	certs, err := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("FindIdentityCertificatesByAgent: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("no identity cert should be issued for an agent registered without an identity CSR; got %d", len(certs))
	}
}

// TestVerifyDNS_NoIdentityCSR_V2EventEmptyIdentityCerts pins the V2 wire
// shape for a no-identity-CSR agent: the emitted V2 event attests no
// identity certs. Because identityCerts is tagged omitempty, the field
// is absent on the wire (not an empty array) when there are none.
func TestVerifyDNS_NoIdentityCSR_V2EventEmptyIdentityCerts(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	req := fx.req
	req.IdentityCSRPEM = ""

	resp, err := fx.svc.RegisterAgent(context.Background(), req)
	if err != nil {
		t.Fatalf("precondition: register without identity CSR should succeed; got: %v", err)
	}
	agentID := resp.Registration.AgentID
	if _, err := fx.svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}
	if _, err := fx.svc.VerifyDNS(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-dns: %v", err)
	}

	rows, err := fx.outboxStore.Claim(context.Background(), 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least one emitted V2 event")
	}
	for _, row := range rows {
		var p service.OutboxPayload
		if err := json.Unmarshal(row.PayloadJSON, &p); err != nil {
			t.Fatalf("unmarshal OutboxPayload: %v", err)
		}
		var ev event.Event
		if err := json.Unmarshal(p.InnerEventCanonical, &ev); err != nil {
			t.Fatalf("unmarshal inner V2 event: %v", err)
		}
		if ev.Attestations != nil && len(ev.Attestations.IdentityCerts) != 0 {
			t.Fatalf("V2 event %q must attest no identityCerts (field absent or empty); got %d",
				ev.EventType, len(ev.Attestations.IdentityCerts))
		}
	}
}

// TestVerifyDNS_NoIdentityCSR_V1EventEmptyIdentityCert pins the V1 wire
// shape for a no-identity-CSR agent: the emitted V1 AGENT_REGISTERED
// event attests no identity certs. Both identityCert (singleton) and
// validIdentityCerts are tagged omitempty, so each field is absent on
// the wire (not a null singleton or empty array) when there are none.
func TestVerifyDNS_NoIdentityCSR_V1EventEmptyIdentityCert(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	req := fx.req
	req.IdentityCSRPEM = ""
	req.SchemaVersion = "V1"

	resp, err := fx.svc.RegisterAgent(context.Background(), req)
	if err != nil {
		t.Fatalf("precondition: V1 register without identity CSR should succeed; got: %v", err)
	}
	agentID := resp.Registration.AgentID
	if _, err := fx.svc.VerifyACME(context.Background(), agentID, service.VerifyInput{SchemaVersion: "V1"}); err != nil {
		t.Fatalf("verify-acme (V1): %v", err)
	}
	if _, err := fx.svc.VerifyDNS(context.Background(), agentID, service.VerifyInput{SchemaVersion: "V1"}); err != nil {
		t.Fatalf("verify-dns (V1): %v", err)
	}

	got, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatalf("FindByAgentID: %v", err)
	}
	if got.Status != domain.StatusActive {
		t.Fatalf("V1 agent registered without an identity CSR must reach ACTIVE; got %q", got.Status)
	}

	rows, err := fx.outboxStore.Claim(context.Background(), 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	sawV1 := false
	for _, row := range rows {
		if row.SchemaVersion != eventv1.SchemaVersion {
			continue
		}
		sawV1 = true
		var p service.OutboxPayload
		if err := json.Unmarshal(row.PayloadJSON, &p); err != nil {
			t.Fatalf("unmarshal OutboxPayload: %v", err)
		}
		var ev eventv1.Event
		if err := json.Unmarshal(p.InnerEventCanonical, &ev); err != nil {
			t.Fatalf("unmarshal inner V1 event: %v", err)
		}
		if ev.Attestations != nil {
			if ev.Attestations.IdentityCert != nil {
				t.Fatalf("V1 event must attest no identityCert (field absent or null); got %+v", ev.Attestations.IdentityCert)
			}
			if len(ev.Attestations.ValidIdentityCerts) != 0 {
				t.Fatalf("V1 event must attest no validIdentityCerts (field absent or empty); got %d", len(ev.Attestations.ValidIdentityCerts))
			}
		}
	}
	if !sawV1 {
		t.Fatal("expected a V1 AGENT_REGISTERED event in the outbox")
	}
}

// TestSubmitIdentityCSR_NoIdentityCSR_Rejected covers the no-add-later
// guard: an ACTIVE agent that registered without an identity CSR cannot
// obtain one via SubmitIdentityCSR. It must register a new version
// instead. The guard returns a 409 IDENTITY_CSR_NOT_PERMITTED conflict.
func TestSubmitIdentityCSR_NoIdentityCSR_Rejected(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	// Register without an identity CSR and drive to ACTIVE — only then
	// does the no-add-later guard apply (a pending agent gets the
	// AGENT_NOT_ACTIVE signal from the aggregate's own status check).
	req := fx.req
	req.IdentityCSRPEM = ""
	resp, err := fx.svc.RegisterAgent(ctx, req)
	if err != nil {
		t.Fatalf("precondition: register without identity CSR should succeed; got: %v", err)
	}
	agentID := resp.Registration.AgentID
	if _, err := fx.svc.VerifyACME(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}
	if _, err := fx.svc.VerifyDNS(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-dns: %v", err)
	}

	_, err = fx.svc.SubmitIdentityCSR(ctx, agentID, testCSR(t, fx.req.AnsName.String()))
	if err == nil {
		t.Fatal("agent registered without an identity CSR must not be allowed to add one later")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("expected a domain.Error; got %T: %v", err, err)
	}
	if de.Code != "IDENTITY_CSR_NOT_PERMITTED" {
		t.Fatalf("expected code IDENTITY_CSR_NOT_PERMITTED; got %q", de.Code)
	}
}
