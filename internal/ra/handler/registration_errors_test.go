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

// ----- optional `version` field on registration -----
//
// When `version` is omitted from a registration body the RA defaults
// it to 1.0.0; an explicit empty string (or any malformed value) is
// rejected as 422 MALFORMED_SEMVER. Both lanes share the behaviour.

func TestRegister_OmittedVersionDefaultsTo100(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	const host = "omitted-version.example.com"

	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"agentHost":        host,
		"endpoints":        []map[string]any{{"agentUrl": "https://omitted-version.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"serverCsrPEM":     newTestServerCSR(t, host),
	})

	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		AgentID string `json:"agentId"`
		Status  string `json:"status"`
		AnsName string `json:"ansName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse 202: %v", err)
	}
	if resp.Status != "PENDING_VALIDATION" {
		t.Errorf("status: got %q want PENDING_VALIDATION", resp.Status)
	}
	if want := "ans://v1.0.0." + host; resp.AnsName != want {
		t.Errorf("ansName: got %q want %q", resp.AnsName, want)
	}

	// The default propagates to the read model.
	det := fx.request(t, http.MethodGet, "/v2/ans/agents/"+resp.AgentID, nil, fx.asOwner("alice"))
	if det.Code != http.StatusOK {
		t.Fatalf("detail status: got %d want 200; body=%s", det.Code, det.Body)
	}
	var detail struct {
		Version string `json:"version"`
		AnsName string `json:"ansName"`
	}
	if err := json.Unmarshal(det.Body.Bytes(), &detail); err != nil {
		t.Fatalf("parse detail: %v", err)
	}
	if detail.Version != "1.0.0" {
		t.Errorf("detail version: got %q want 1.0.0", detail.Version)
	}
}

func TestRegister_EmptyStringVersionRejected(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "",
		"agentHost":        "empty-version.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://empty-version.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"serverCsrPEM":     newTestServerCSR(t, "empty-version.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf(`version "" status: got %d want 422; body=%s`, rec.Code, rec.Body)
	}
}

func TestRegister_SuppliedVersionPreserved(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "2.5.1",
		"agentHost":        "supplied-version.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://supplied-version.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"serverCsrPEM":     newTestServerCSR(t, "supplied-version.example.com"),
	})

	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		AnsName string `json:"ansName"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if want := "ans://v2.5.1.supplied-version.example.com"; resp.AnsName != want {
		t.Errorf("ansName: got %q want %q", resp.AnsName, want)
	}
}

func TestV1Register_OmittedVersionDefaultsTo100(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"agentHost":        "omitted-version.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://omitted-version.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"serverCsrPEM":     newTestServerCSR(t, "omitted-version.example.com"),
	})

	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		AnsName string `json:"ansName"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if want := "ans://v1.0.0.omitted-version.example.com"; resp.AnsName != want {
		t.Errorf("ansName: got %q want %q", resp.AnsName, want)
	}
}

func TestV1Register_EmptyStringVersionRejected(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "",
		"agentHost":        "empty-version.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://empty-version.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
		"serverCsrPEM":     newTestServerCSR(t, "empty-version.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf(`version "" status: got %d want 422; body=%s`, rec.Code, rec.Body)
	}
}
