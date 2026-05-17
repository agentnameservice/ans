package service

import (
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/tl/event"
)

// mustAnsName parses a string into a domain.AnsName or fails the test.
func mustAnsName(t *testing.T, s string) domain.AnsName {
	t.Helper()
	n, err := domain.ParseAnsName(s)
	if err != nil {
		t.Fatalf("parse ans name %q: %v", s, err)
	}
	return n
}

// Unit tests for the link-emission helpers. End-to-end coverage runs
// against the live demo stack in scripts/demo (see PR description for
// the live test plan). The store-coupled paths (LinkEquivalence
// itself) are exercised through that integration; these unit tests
// pin the anchor recovery + inner-event shape in isolation so a
// future field rename surfaces here.

func TestAnchorTypeFromRegistration_FQDNDefault(t *testing.T) {
	reg := &domain.AgentRegistration{AgentHost: "agent.test"}
	if got := anchorTypeFromRegistration(reg); got != "fqdn" {
		t.Errorf("got %q, want fqdn (default for missing AnchorClaim)", got)
	}
}

func TestAnchorTypeFromRegistration_LEI(t *testing.T) {
	reg := &domain.AgentRegistration{
		AgentHost: "agent.test",
		AnchorClaim: &domain.IdentityClaim{
			AnchorType: domain.AnchorTypeLEI,
			ResolvedID: "529900T8BM49AURSDO55",
		},
	}
	if got := anchorTypeFromRegistration(reg); got != "lei" {
		t.Errorf("got %q, want lei", got)
	}
}

func TestAnchorValueFromRegistration_LEI(t *testing.T) {
	reg := &domain.AgentRegistration{
		AgentHost: "ignored.test",
		AnchorClaim: &domain.IdentityClaim{
			AnchorType: domain.AnchorTypeLEI,
			ResolvedID: "529900T8BM49AURSDO55",
		},
	}
	if got := anchorValueFromRegistration(reg); got != "529900T8BM49AURSDO55" {
		t.Errorf("got %q, want LEI string from ResolvedID", got)
	}
}

func TestAnchorValueFromRegistration_FQDNFallsBackToHost(t *testing.T) {
	reg := &domain.AgentRegistration{AgentHost: "agent.test"}
	if got := anchorValueFromRegistration(reg); got != "agent.test" {
		t.Errorf("got %q, want agent.test (AgentHost fallback)", got)
	}
}

func TestEquivalenceInnerEvent_ShapeValidates(t *testing.T) {
	// The link inner event MUST pass internal/tl/event.Validate's
	// link-event branch: present Equivalence, no Agent, no
	// Attestations, non-empty linkedAnsId differing from ansId.
	primary := &domain.AgentRegistration{
		AgentID:   "primary-uuid",
		AgentHost: "primary.acme.com",
		AnsName:   mustAnsName(t, "ans://v1.0.0.primary.acme.com"),
	}
	linked := &domain.AgentRegistration{
		AgentID:   "linked-uuid",
		AgentHost: "ignored.test",
		AnsName:   mustAnsName(t, "ans://v1.0.0.linked.acme.com"),
		AnchorClaim: &domain.IdentityClaim{
			AnchorType: domain.AnchorTypeLEI,
			ResolvedID: "529900T8BM49AURSDO55",
		},
	}
	svc := &RegistrationService{
		signer: &EventSigner{RaID: "ans-ra-test"},
		clock:  func() time.Time { return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC) },
	}
	now := svc.clock()

	inner := svc.equivalenceInnerEvent(primary, linked, "operator-asserted", now)
	if err := inner.Validate(); err != nil {
		t.Fatalf("inner event Validate: %v", err)
	}

	if inner.EventType != event.TypeEquivalenceLink {
		t.Errorf("EventType: got %q, want EQUIVALENCE_LINK", inner.EventType)
	}
	if inner.Agent != nil {
		t.Error("Agent block must be absent on link events")
	}
	if inner.Attestations != nil {
		t.Error("Attestations must be absent on link events")
	}
	if inner.Equivalence == nil {
		t.Fatal("Equivalence block must be present on link events")
	}
	if inner.Equivalence.LinkedAnsID != "linked-uuid" {
		t.Errorf("LinkedAnsID: got %q", inner.Equivalence.LinkedAnsID)
	}
	if inner.Equivalence.LinkedAnchorType != "lei" {
		t.Errorf("LinkedAnchorType: got %q", inner.Equivalence.LinkedAnchorType)
	}
	if inner.Equivalence.LinkedAnchorResolvedID != "529900T8BM49AURSDO55" {
		t.Errorf("LinkedAnchorResolvedID: got %q", inner.Equivalence.LinkedAnchorResolvedID)
	}
	if inner.Equivalence.Rationale != "operator-asserted" {
		t.Errorf("Rationale: got %q", inner.Equivalence.Rationale)
	}
	if inner.RaID != "ans-ra-test" {
		t.Errorf("RaID: got %q", inner.RaID)
	}
	if inner.IssuedAt == "" || inner.Timestamp == "" {
		t.Error("IssuedAt and Timestamp must be set")
	}
}

func TestEquivalenceInnerEvent_FQDNToFQDN(t *testing.T) {
	// Same-anchor-type link still validates; the schema does not
	// require the two anchors to differ.
	primary := &domain.AgentRegistration{
		AgentID:   "p",
		AgentHost: "p.test",
		AnsName:   mustAnsName(t, "ans://v1.0.0.p.test"),
	}
	linked := &domain.AgentRegistration{
		AgentID:   "l",
		AgentHost: "l.test",
		AnsName:   mustAnsName(t, "ans://v1.0.0.l.test"),
	}
	svc := &RegistrationService{
		signer: &EventSigner{RaID: "ans-ra-test"},
		clock:  func() time.Time { return time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC) },
	}
	inner := svc.equivalenceInnerEvent(primary, linked, "", svc.clock())
	if err := inner.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if inner.Equivalence.LinkedAnchorType != "fqdn" {
		t.Errorf("LinkedAnchorType: got %q, want fqdn", inner.Equivalence.LinkedAnchorType)
	}
	if inner.Equivalence.LinkedAnchorResolvedID != "l.test" {
		t.Errorf("LinkedAnchorResolvedID: got %q, want l.test (host fallback)",
			inner.Equivalence.LinkedAnchorResolvedID)
	}
}
