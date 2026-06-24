package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/godaddy/ans/internal/adapter/dns"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
	event "github.com/godaddy/ans/internal/tl/event"
	eventv1 "github.com/godaddy/ans/internal/tl/event/v1"
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

	// AGENT_REGISTERED is sealed inline at activation (seal-before-success),
	// not enqueued to the outbox, so inspect what was sealed.
	sealed := fx.sealer.sealed()
	if len(sealed) == 0 {
		t.Fatal("expected at least one sealed V2 event")
	}
	for _, s := range sealed {
		var ev event.Event
		if err := json.Unmarshal(s.InnerCanonical, &ev); err != nil {
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

	// AGENT_REGISTERED is sealed inline at activation, not enqueued.
	sawV1 := false
	for _, s := range fx.sealer.sealed() {
		if s.SchemaVersion != eventv1.SchemaVersion {
			continue
		}
		sawV1 = true
		var ev eventv1.Event
		if err := json.Unmarshal(s.InnerCanonical, &ev); err != nil {
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
		t.Fatal("expected a V1 AGENT_REGISTERED event to be sealed")
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

// TestVerifyDNS_SealFailure_FailsClosed pins the seal-before-success
// contract for agent activation (ANS-1 §12.3: "the RA MUST NOT activate
// without a sealed event (step (d) is the point of no return)"). When
// the inline TL seal fails, verify-dns must NOT report ACTIVE: it
// surfaces the seal error and leaves the agent PENDING_DNS so the
// operator can retry once the TL is reachable. This is what guarantees a
// downstream catalog entry's SCITT-receipt and badge links can only ever
// point at a TL record that was actually written.
func TestVerifyDNS_SealFailure_FailsClosed(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	resp, err := fx.svc.RegisterAgent(ctx, fx.req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := resp.Registration.AgentID
	if _, err := fx.svc.VerifyACME(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}

	// Arm the sealer to fail as the tlclient would when the TL is
	// unreachable (transient → TL_UNAVAILABLE).
	fx.sealer.failErr = domain.NewUnavailableError("TL_UNAVAILABLE", "tl down")

	var de *domain.Error
	if _, err := fx.svc.VerifyDNS(ctx, agentID, service.VerifyInput{}); err == nil {
		t.Fatal("verify-dns must fail when the activation seal fails; got nil error")
	} else if !errors.As(err, &de) || de.Code != "TL_UNAVAILABLE" {
		t.Fatalf("expected TL_UNAVAILABLE domain error; got %T: %v", err, err)
	}

	// Fail-closed: the persisted agent must still be PENDING_DNS. ACTIVE
	// is the point of no return and must not be reached without a seal.
	got, err := fx.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		t.Fatalf("FindByAgentID: %v", err)
	}
	if got.Status != domain.StatusPendingDNS {
		t.Fatalf("agent must stay PENDING_DNS after a failed seal; got %q", got.Status)
	}

	// Nothing was recorded as durably sealed, and activation must never
	// fall back to the outbox.
	if n := len(fx.sealer.sealed()); n != 0 {
		t.Errorf("no event should be recorded as sealed on failure; got %d", n)
	}
	if rows, _ := fx.outboxStore.Claim(ctx, 100); len(rows) != 0 {
		t.Errorf("activation must not enqueue to the outbox; got %d rows", len(rows))
	}

	// Retry succeeds once the TL recovers — proving the failure left the
	// aggregate in a retryable PENDING_DNS state, not a wedged one.
	fx.sealer.failErr = nil
	if _, err := fx.svc.VerifyDNS(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-dns retry after TL recovers: %v", err)
	}
	got, err = fx.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		t.Fatalf("FindByAgentID after retry: %v", err)
	}
	if got.Status != domain.StatusActive {
		t.Fatalf("agent must reach ACTIVE on retry; got %q", got.Status)
	}
	if n := len(fx.sealer.sealed()); n != 1 {
		t.Errorf("retry must seal exactly one AGENT_REGISTERED; got %d sealed", n)
	}
}

// TestVerifyDNS_NilSealer_FailsClosed covers the no-sealer-configured
// branch of activation — the live fail-closed path when the RA runs with
// the TL client disabled (cmd/ans-ra/main.go leaves the sealer nil and
// only wires it when non-nil). With no sealer there is no "seal later"
// mode: activation must report TL_UNAVAILABLE and leave the agent
// PENDING_DNS rather than going ACTIVE without a sealed event. No signer
// is wired here either — the nil-sealer guard short-circuits before any
// event is built or signed.
func TestVerifyDNS_NilSealer_FailsClosed(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	// Reuse the fixture's stores/CAs but build a service with NO agent
	// sealer (and no signer) — mirroring a TL-disabled deployment. A DNS
	// verifier is still wired so verify-acme's challenge gate passes and
	// the flow reaches verify-dns, where the nil-sealer guard fires.
	svc := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, fx.byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow,
	).WithServerCertificateIssuer(fx.serverCA).
		WithDNSVerifier(dns.NewNoopVerifier())

	resp, err := svc.RegisterAgent(ctx, fx.req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := resp.Registration.AgentID
	if _, err := svc.VerifyACME(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}

	var de *domain.Error
	if _, err := svc.VerifyDNS(ctx, agentID, service.VerifyInput{}); err == nil {
		t.Fatal("verify-dns must fail closed when no sealer is configured; got nil error")
	} else if !errors.As(err, &de) || de.Code != "TL_UNAVAILABLE" {
		t.Fatalf("expected TL_UNAVAILABLE domain error; got %T: %v", err, err)
	}

	got, err := fx.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		t.Fatalf("FindByAgentID: %v", err)
	}
	if got.Status != domain.StatusPendingDNS {
		t.Fatalf("agent must stay PENDING_DNS with no sealer configured; got %q", got.Status)
	}
}
