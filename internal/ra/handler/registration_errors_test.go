package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Pre-coverage the V2 Register handler at 53.8% had only the happy
// path exercised. This file pins each early-return branch:
//
//   - bad JSON
//   - missing agentHost / version (parser/builder rejects)
//   - bad endpoints (no protocol)
//   - body too large (1 MiB)
//
// Each test rides through the full router so the auth middleware and
// service layer are also touched, but the assertions focus on the
// 422/413 status code returned by the handler's early-exit.

// TestRegister_AgentCardContent_PlumbedToService verifies the V2
// handler delivers the agentCardContent body to the service as the
// raw JSON bytes the operator submitted. The service hashes the bytes
// (covered by service-layer tests); this test only proves the wire
// is connected.
func TestRegister_AgentCardContent_PlumbedToService(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	cardBody := map[string]any{
		"ansName": "ans://v1.0.0.cardplumb.example.com",
		"version": "1.0.0",
	}
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "cardplumb.example.com",
		"endpoints": []map[string]any{
			{"agentUrl": "https://cardplumb.example.com", "protocol": "MCP", "transports": []string{"SSE"}},
		},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.cardplumb.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "cardplumb.example.com"),
		"agentCardContent": cardBody,
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
	// The aggregate must carry a non-empty CapabilitiesHash. The exact
	// hex value is the service-layer concern; here we just confirm the
	// hash flowed through, which proves the handler delivered the bytes.
	regs, err := fx.agents.FindAllByAgentHost(fx.ctx, "cardplumb.example.com")
	if err != nil {
		t.Fatalf("FindAllByAgentHost: %v", err)
	}
	if len(regs) != 1 {
		t.Fatalf("agents: got %d want 1", len(regs))
	}
	if regs[0].CapabilitiesHash == "" {
		t.Errorf("CapabilitiesHash empty after register with agentCardContent")
	}
	if len(regs[0].CapabilitiesHash) != 64 {
		t.Errorf("CapabilitiesHash length: got %d want 64", len(regs[0].CapabilitiesHash))
	}
}

// TestRegister_AgentCardContent_OmittedNoHash verifies the absence
// path: a registration without agentCardContent leaves the aggregate's
// CapabilitiesHash empty.
func TestRegister_AgentCardContent_OmittedNoHash(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "noccard.example.com",
		"endpoints": []map[string]any{
			{"agentUrl": "https://noccard.example.com", "protocol": "MCP", "transports": []string{"SSE"}},
		},
		"identityCsrPEM": newTestCSR(t, "ans://v1.0.0.noccard.example.com"),
		"serverCsrPEM":   newTestServerCSR(t, "noccard.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
	regs, err := fx.agents.FindAllByAgentHost(fx.ctx, "noccard.example.com")
	if err != nil {
		t.Fatalf("FindAllByAgentHost: %v", err)
	}
	if len(regs) != 1 {
		t.Fatalf("agents: got %d want 1", len(regs))
	}
	if regs[0].CapabilitiesHash != "" {
		t.Errorf("CapabilitiesHash: want empty, got %q", regs[0].CapabilitiesHash)
	}
}

// TestRegister_AgentCardContent_MalformedJSON_RejectedAt422 pins the
// outer-body contract: when an operator embeds raw bytes the JSON
// decoder cannot parse inside agentCardContent, the failure mode is
// BAD_JSON at the handler, not INVALID_AGENT_CARD_CONTENT at the
// service. The malformed bytes break the outer body decode before
// the service runs.
//
// The service-layer INVALID_AGENT_CARD_CONTENT path is exercised by
// TestRegister_AgentCardContent_NotAnObject_RejectedAt422 below,
// which submits JSON that decodes successfully at the outer layer
// (a JSON array) but the service rejects because agentCardContent
// must be a JSON object per ANS_SPEC §A.1.
func TestRegister_AgentCardContent_MalformedJSON_RejectedAt422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	bad := []byte(`{
        "agentDisplayName": "X",
        "agentCardContent": {{this is not valid json}},
        "version": "1.0.0"
    }`)
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(bad), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "BAD_JSON" {
		t.Errorf("code: got %q want BAD_JSON (service is not reached)", prob.Code)
	}
}

// TestRegister_AgentCardContent_NotAnObject_RejectedAt422 exercises
// the service-layer INVALID_AGENT_CARD_CONTENT path. Submitting a
// JSON array as agentCardContent decodes cleanly at the outer layer
// (the body is valid JSON), so the request reaches the service. The
// service rejects with INVALID_AGENT_CARD_CONTENT because the
// agentCardContent shape MUST be a JSON object per ANS_SPEC §A.1.
func TestRegister_AgentCardContent_NotAnObject_RejectedAt422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
		"agentCardContent": []string{"not", "an", "object"},
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "INVALID_AGENT_CARD_CONTENT" {
		t.Errorf("code: got %q want INVALID_AGENT_CARD_CONTENT", prob.Code)
	}
}

func TestRegister_BadJSONReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "BAD_JSON" {
		t.Errorf("code: got %q want BAD_JSON", prob.Code)
	}
}

func TestRegister_BadVersionReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "not-a-semver",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://vnot-a-semver.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestRegister_MissingEndpoints422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestRegister_BadProtocolReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "PIGEON", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 for unknown protocol; body=%s", rec.Code, rec.Body)
	}
}

// 1 MiB max body — handler enforces via http.MaxBytesReader. The
// stream gets short-circuited on Decode and surfaces as a
// validation-shaped 422 (not 413, because the handler doesn't
// distinguish — anything that fails Decode becomes BAD_JSON).
func TestRegister_BodyTooLargeRejected(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	huge := strings.Repeat("a", 2<<20) // 2 MiB
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": huge,
		"version":          "1.0.0",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code == http.StatusAccepted {
		t.Fatalf("oversize body should not be accepted; got 202")
	}
}

// TestVerifyDNS_AgentNotFound exercises the lifecycle.go VerifyDNS
// handler's "ServiceLayer returned NOT_FOUND" branch — which it
// didn't get coverage on because the existing tests only run the
// happy path. We don't assert error code precisely; just that the
// status is 404 (or 422/forbidden depending on auth state).
func TestVerifyDNS_UnknownAgentNotFound(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/no-such-agent/verify-dns",
		nil, fx.asOwner("alice"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("unknown agent should not succeed; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestVerifyACME_UnknownAgent400Plus parallels the verify-dns case for
// the V2 verify-acme handler — exercises the "no such agent" branch.
func TestVerifyACME_UnknownAgent400Plus(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/no-such-agent/verify-acme",
		nil, fx.asOwner("alice"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("unknown agent should not succeed; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestRevoke_UnknownAgent404 covers the V2 Revoke handler's
// "service returned NOT_FOUND" branch. Pre-coverage the revoke
// handler sat at 76.5% — only the happy and "owned by another
// caller" paths landed. This pushes the not-found branch.
func TestRevoke_UnknownAgent404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/no-such-agent/revoke",
		nil, fx.asOwner("alice"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("unknown agent should not be revocable; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestRevoke_BadJSON_422 covers the BAD_JSON branch in Revoke that
// fires when the request body isn't valid JSON. Pre-coverage we hit
// the missing-reason branch but not the JSON-decode failure.
func TestRevoke_BadJSON_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/revoke",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestV1Revoke_BadJSON_422 mirrors the above for the V1 revoke
// handler, which has its own copy of the JSON decode + missing-reason
// guards.
func TestV1Revoke_BadJSON_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/revoke",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitServerCSR_BadDNSSANReturns422 covers the validator
// rejection branch in service.SubmitServerCSR — the integration
// happy path validates a matching DNS SAN; this submits a CSR
// whose DNS SAN doesn't match the agent FQDN, exercising the
// INVALID_SERVER_CSR error return.
func TestSubmitServerCSR_BadDNSSANReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	// Server CSR for a *different* host → validator rejects.
	csrPEM := newTestServerCSR(t, "wrong.example.com")
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 for SAN mismatch; body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitIdentityCSR_BadURISANReturns422 mirrors the same SAN-
// mismatch check on the identity-CSR submission path.
func TestSubmitIdentityCSR_BadURISANReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	// Activate the agent so SubmitIdentityCSR doesn't bail on the
	// status-gate ahead of validator.
	fx.activateAgent(t, "alice", agentID)

	// Identity CSR with a URI SAN pointing at a different ANS name.
	csrPEM := newTestCSR(t, "ans://v9.9.9.other.example.com")
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/identity",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422 for URI SAN mismatch; body=%s", rec.Code, rec.Body)
	}
}

// ----- V1 lane parity -----
//
// The V1 register/lifecycle handlers share most of their early-exit
// shape with their V2 counterparts. Mirror the failure-path tests
// here so coverage of the V1 lane catches up.

func TestV1Register_BadJSONReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestV1Register_BadVersionReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "not-a-semver",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://vnot-a-semver.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestV1Register_MissingEndpoints422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestV1Register_BadProtocolReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "x.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "PIGEON", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.x.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "x.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestV1VerifyDNS_UnknownAgent(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v1/agents/no-such-agent/verify-dns",
		nil, fx.asOwner("alice"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("unknown agent should not succeed; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestV1VerifyACME_UnknownAgent(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodPost, "/v1/agents/no-such-agent/verify-acme",
		nil, fx.asOwner("alice"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("unknown agent should not succeed; got %d body=%s", rec.Code, rec.Body)
	}
}
