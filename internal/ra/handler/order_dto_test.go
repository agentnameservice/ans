package handler

import (
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

func orderedReg(t *testing.T, state domain.OrderState) *domain.AgentRegistration {
	t.Helper()
	sv, _ := domain.ParseSemVer("1.0.0")
	ansName, _ := domain.NewAnsName(sv, "agent.example.com")
	return &domain.AgentRegistration{
		AgentID: "agent-1",
		AnsName: ansName,
		Status:  domain.StatusPendingValidation,
		CertOrder: domain.CertificateOrder{
			OrderRef: "ref-1",
			State:    state,
			Challenges: []domain.Challenge{
				{Type: domain.ChallengeTypeDNS01, Token: "dns-tok", KeyAuthorization: "dns-tok.kid", DNSRecordValue: "digest"},
				{Type: domain.ChallengeTypeHTTP01, Token: "http-tok", KeyAuthorization: "http-tok.kid"},
			},
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
}

// TestBuildRegistrationChallenges_RelaysProviderFields pins the
// challenge relay: provider-minted key authorizations, computed DNS
// digests, and HTTP paths reach the wire untouched.
func TestBuildRegistrationChallenges_RelaysProviderFields(t *testing.T) {
	out := buildRegistrationChallenges(orderedReg(t, domain.OrderStatePending))
	if len(out) != 2 {
		t.Fatalf("challenges: got %d want 2", len(out))
	}
	dns01 := out[0]
	if dns01.Type != "DNS_01" || dns01.Token != "dns-tok" || dns01.KeyAuthorization != "dns-tok.kid" {
		t.Errorf("dns01 relay: %+v", dns01)
	}
	if dns01.DNSRecord == nil ||
		dns01.DNSRecord.Name != "_acme-challenge.agent.example.com" ||
		dns01.DNSRecord.Value != "digest" {
		t.Errorf("dns01 record: %+v", dns01.DNSRecord)
	}
	http01 := out[1]
	if http01.Type != "HTTP_01" || http01.HTTPPath != "/.well-known/acme-challenge/http-tok" {
		t.Errorf("http01 relay: %+v", http01)
	}
	if http01.DNSRecord != nil {
		t.Error("http01 must not carry a dnsRecord")
	}

	// No order → no challenges block.
	if got := buildRegistrationChallenges(&domain.AgentRegistration{}); got != nil {
		t.Errorf("zero order should omit challenges, got %+v", got)
	}
}

// TestBuildRegistrationPendingBlock_PendingCerts pins the derived
// registration-flow status: PENDING_VALIDATION lifecycle + ISSUING
// order reports PENDING_CERTS with WAIT guidance, no challenges (the
// provider already accepted the answer).
func TestBuildRegistrationPendingBlock_PendingCerts(t *testing.T) {
	reg := orderedReg(t, domain.OrderStateIssuing)
	block := buildRegistrationPendingBlock(reg, mustReq(t, "GET", "/v2/ans/agents/agent-1"), nil)
	if block == nil {
		t.Fatal("pending block missing")
	}
	if block.Status != "PENDING_CERTS" {
		t.Fatalf("status: got %q want PENDING_CERTS", block.Status)
	}
	if len(block.Challenges) != 0 {
		t.Error("ISSUING block must not relay challenges")
	}
	if len(block.NextSteps) != 1 || block.NextSteps[0].Action != "WAIT" {
		t.Errorf("nextSteps: %+v", block.NextSteps)
	}

	// Every block carries the spec-required agentId.
	if block.AgentID != "agent-1" {
		t.Errorf("PENDING_CERTS block missing agentId: %q", block.AgentID)
	}

	// PENDING order keeps the lifecycle status + challenges.
	pendingBlock := buildRegistrationPendingBlock(orderedReg(t, domain.OrderStatePending),
		mustReq(t, "GET", "/v2/ans/agents/agent-1"), nil)
	if pendingBlock.Status != string(domain.StatusPendingValidation) {
		t.Fatalf("status: got %q", pendingBlock.Status)
	}
	if len(pendingBlock.Challenges) != 2 {
		t.Errorf("PENDING block must relay challenges, got %d", len(pendingBlock.Challenges))
	}
	if pendingBlock.AgentID != "agent-1" {
		t.Errorf("PENDING block missing agentId: %q", pendingBlock.AgentID)
	}
}

// TestBuildRegistrationPendingBlock_FailedOrder pins the terminal-
// failure guidance (V2 + V1): no dead challenges, and a CANCEL step
// pointing at /revoke rather than a verify-acme loop that can only
// return CERT_ORDER_FAILED.
func TestBuildRegistrationPendingBlock_FailedOrder(t *testing.T) {
	reg := orderedReg(t, domain.OrderStateFailed)
	v2 := buildRegistrationPendingBlock(reg, mustReq(t, "GET", "/v2/ans/agents/agent-1"), nil)
	if v2 == nil || v2.Status != "PENDING_CERTS" {
		t.Fatalf("v2 failed-order block: %+v", v2)
	}
	if len(v2.Challenges) != 0 {
		t.Error("failed-order block must not relay dead challenges")
	}
	if len(v2.NextSteps) != 1 || v2.NextSteps[0].Action != "CANCEL" {
		t.Errorf("v2 nextSteps: %+v", v2.NextSteps)
	}
	if v2.AgentID != "agent-1" {
		t.Errorf("v2 failed-order block missing agentId: %q", v2.AgentID)
	}

	v1 := buildV1RegistrationPending(reg, mustReq(t, "GET", "/v1/agents/agent-1"), nil)
	if v1 == nil || len(v1.Challenges) != 0 {
		t.Fatalf("v1 failed-order block must omit challenges: %+v", v1)
	}
	if len(v1.NextSteps) != 1 || v1.NextSteps[0].Action != "CANCEL" {
		t.Errorf("v1 nextSteps: %+v", v1.NextSteps)
	}

	// V1 ISSUING block: WAIT, no re-relayed challenge.
	v1issuing := buildV1RegistrationPending(orderedReg(t, domain.OrderStateIssuing),
		mustReq(t, "GET", "/v1/agents/agent-1"), nil)
	if v1issuing == nil || len(v1issuing.Challenges) != 0 ||
		len(v1issuing.NextSteps) != 1 || v1issuing.NextSteps[0].Action != "WAIT" {
		t.Errorf("v1 issuing block: %+v", v1issuing)
	}
}

// TestPhaseTrio_IssuingOrder pins the order-derived step reporting.
func TestPhaseTrio_IssuingOrder(t *testing.T) {
	reg := orderedReg(t, domain.OrderStateIssuing)
	if got := phaseFor(reg); got != "CERTIFICATE_ISSUANCE" {
		t.Errorf("phase: %q", got)
	}
	completed := completedStepsFor(reg)
	if len(completed) != 1 || completed[0] != "DOMAIN_VALIDATION" {
		t.Errorf("completedSteps: %v", completed)
	}
	pending := pendingStepsFor(reg)
	if len(pending) != 1 || pending[0] != "CERTIFICATE_ISSUANCE" {
		t.Errorf("pendingSteps: %v", pending)
	}
}

// TestBuildRenewalChallenges_Shapes pins the renewal challenges block
// the operator publishes from — including the HTTP-01 URL + expected
// response that were previously never surfaced.
func TestBuildRenewalChallenges_Shapes(t *testing.T) {
	v := domain.RenewalValidation{
		Challenges: []domain.Challenge{
			{Type: domain.ChallengeTypeDNS01, Token: "d-tok"},
			{Type: domain.ChallengeTypeHTTP01, Token: "h-tok", KeyAuthorization: "h-tok.kid"},
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	out := buildRenewalChallenges("agent.example.com", v)
	if out == nil || out.DNS01 == nil || out.HTTP01 == nil {
		t.Fatalf("challenges block incomplete: %+v", out)
	}
	// Shape must match the spec's ChallengeInfo — the renewal
	// responses $ref the same schema the registration lane uses.
	if out.DNS01.Type != "DNS_01" || out.DNS01.Token != "d-tok" ||
		out.DNS01.DNSRecord == nil ||
		out.DNS01.DNSRecord.Name != "_acme-challenge.agent.example.com" ||
		out.DNS01.DNSRecord.Type != "TXT" || out.DNS01.DNSRecord.Value != "d-tok" {
		t.Errorf("dns01: %+v", out.DNS01)
	}
	if out.HTTP01.Type != "HTTP_01" || out.HTTP01.Token != "h-tok" ||
		out.HTTP01.KeyAuthorization != "h-tok.kid" ||
		out.HTTP01.HTTPPath != "/.well-known/acme-challenge/h-tok" {
		t.Errorf("http01: %+v", out.HTTP01)
	}
	if out.HTTP01.DNSRecord != nil {
		t.Error("http01 must not carry a dnsRecord")
	}

	// Empty challenge set → nil block (omitted on the wire).
	if got := buildRenewalChallenges("x", domain.RenewalValidation{}); got != nil {
		t.Errorf("empty set should yield nil, got %+v", got)
	}
}

// TestTlsaDTOFrom covers both arms of the nil-propagating mapper.
func TestTlsaDTOFrom(t *testing.T) {
	if got := tlsaDTOFrom(nil); got != nil {
		t.Errorf("nil in, nil out: got %+v", got)
	}
	rec := domain.TLSARecordForCert("agent.example.com", "ff00")
	dto := tlsaDTOFrom(&rec)
	if dto == nil || dto.Name != "_443._tcp.agent.example.com" ||
		dto.Type != "TLSA" || dto.Value != "3 0 1 ff00" {
		t.Errorf("tlsa dto: %+v", dto)
	}
}
