package handler_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestDetail_PendingDNSBlockShape exercises the PENDING_DNS arm of
// buildRegistrationPendingBlock — production DNS records (DISCOVERY,
// BADGE, CERTIFICATE_BINDING) must materialize on the detail
// response once verify-acme has signed the certs and moved the agent
// out of PENDING_VALIDATION. Pre-coverage we only exercised the
// PENDING_VALIDATION arm (no records, only ACME challenge).
func TestDetail_PendingDNSBlockShape(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	// verify-acme moves the agent to PENDING_DNS and triggers cert
	// issuance; production DNS records become computable from that
	// point.
	if rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme",
		nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID, nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		AgentStatus         string `json:"agentStatus"`
		RegistrationPending struct {
			Status     string `json:"status"`
			DNSRecords []struct {
				Name    string `json:"name"`
				Type    string `json:"type"`
				Purpose string `json:"purpose"`
			} `json:"dnsRecords"`
			NextSteps []struct {
				Action string `json:"action"`
			} `json:"nextSteps"`
		} `json:"registrationPending"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AgentStatus != "PENDING_DNS" {
		t.Errorf("agentStatus: got %q want PENDING_DNS", resp.AgentStatus)
	}
	if resp.RegistrationPending.Status != "PENDING_DNS" {
		t.Errorf("pending.status: got %q", resp.RegistrationPending.Status)
	}
	// Expected production records: at least DISCOVERY (_ans), BADGE
	// (_ans-badge), and CERTIFICATE_BINDING (_443._tcp TLSA).
	purposes := map[string]bool{}
	for _, r := range resp.RegistrationPending.DNSRecords {
		purposes[r.Purpose] = true
	}
	for _, want := range []string{"DISCOVERY", "BADGE", "CERTIFICATE_BINDING"} {
		if !purposes[want] {
			t.Errorf("dnsRecords missing %s; got %+v", want, purposes)
		}
	}
	// nextSteps at PENDING_DNS should drive the operator to call verify-dns.
	if len(resp.RegistrationPending.NextSteps) == 0 ||
		resp.RegistrationPending.NextSteps[0].Action != "VERIFY_DNS" {
		t.Errorf("nextSteps[0]: got %+v want VERIFY_DNS", resp.RegistrationPending.NextSteps)
	}
}

// TestDetail_TerminalStateOmitsPendingBlock covers the default arm
// of buildRegistrationPendingBlock: ACTIVE / REVOKED / DEPRECATED
// agents have no `registrationPending` block at all.
func TestDetail_TerminalStateOmitsPendingBlock(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID, nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}
	// The wire shape uses `registrationPending,omitempty` so the
	// field is absent on ACTIVE agents. Spot-check by parsing into a
	// generic map and asserting the key is missing.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["registrationPending"]; present {
		t.Errorf("ACTIVE agent should omit registrationPending block; got body=%s", rec.Body)
	}
	// Also confirm the agent is genuinely ACTIVE.
	if got, _ := raw["agentStatus"].(string); !strings.EqualFold(got, "ACTIVE") {
		t.Errorf("agentStatus: got %q want ACTIVE", got)
	}
}
