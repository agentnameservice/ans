package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/dns"
	"github.com/godaddy/ans/internal/adapter/eventbus"
	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/handler"
	ramiddleware "github.com/godaddy/ans/internal/ra/middleware"
	"github.com/godaddy/ans/internal/ra/service"
)

// End-to-end integration tests for Stage 2: list / detail / identity-
// certs / verify-acme / verify-dns / revoke. Uses the real ports +
// real SQLite (in-memory) so the assertions exercise the full
// handler → service → store → back path.
//
// Ownership middleware is wired exactly as in cmd/ans-ra/main.go, so
// the tests also prove the middleware correctly guards each endpoint.

func TestList_EmptyForNewCaller(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Items         []any   `json:"items"`
		ReturnedCount int     `json:"returnedCount"`
		HasMore       bool    `json:"hasMore"`
		NextCursor    *string `json:"nextCursor"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 0 {
		t.Errorf("empty caller should see 0 items; got %d", len(resp.Items))
	}
	if resp.HasMore {
		t.Error("hasMore should be false")
	}
}

func TestList_ShowsOnlyCallerOwned(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)

	// Alice registers one agent; Bob registers two.
	aliceAgent := fx.registerAgent(t, "alice", "aliceagent.example.com", "1.0.0")
	bobAgent1 := fx.registerAgent(t, "bob", "bob1.example.com", "1.0.0")
	bobAgent2 := fx.registerAgent(t, "bob", "bob2.example.com", "2.0.0")

	// Bob should see both of his agents and none of Alice's.
	rec := fx.request(t, http.MethodGet, "/v2/ans/agents?status=ALL", nil, fx.asOwner("bob"))
	if rec.Code != http.StatusOK {
		t.Fatalf("bob list status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Items []struct {
			AgentID string `json:"agentId"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 2 {
		t.Fatalf("bob want 2, got %d (%+v)", len(resp.Items), resp.Items)
	}
	seen := map[string]bool{}
	for _, it := range resp.Items {
		seen[it.AgentID] = true
	}
	if !seen[bobAgent1] || !seen[bobAgent2] {
		t.Errorf("expected both of bob's agents; got %v", seen)
	}
	if seen[aliceAgent] {
		t.Error("bob should NOT see alice's agent")
	}
}

func TestList_DefaultFilterIsActive(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// Register (status = PENDING_VALIDATION). Default filter is ACTIVE
	// → should return empty list.
	fx.registerAgent(t, "alice", "a.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp struct {
		Items []any `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 0 {
		t.Errorf("default=ACTIVE should hide PENDING_VALIDATION agents; got %d items", len(resp.Items))
	}
}

func TestList_BadLimitReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	rec := fx.request(t, http.MethodGet, "/v2/ans/agents?limit=999", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", rec.Code)
	}
}

func TestDetail_OwnedReturns200(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID, nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		AgentID     string `json:"agentId"`
		AgentStatus string `json:"agentStatus"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AgentID != agentID {
		t.Errorf("agentId: got %q want %q", resp.AgentID, agentID)
	}
	if resp.AgentStatus != "PENDING_VALIDATION" {
		t.Errorf("status: got %q", resp.AgentStatus)
	}
}

func TestDetail_NotOwnedReturns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID, nil, fx.asOwner("bob"))
	// Spec: reads return 404 to hide existence.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestGetIdentityCerts_ReturnsIssuedCertArray(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	// Cert issuance moved to verify-acme — advance the lifecycle so
	// the identity CSR gets signed and stored.
	if rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/certificates/identity", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp []struct {
		CertificatePEM                string `json:"certificatePEM"`
		CertificateSubject            string `json:"certificateSubject"`
		CertificateIssuer             string `json:"certificateIssuer"`
		CertificateSerialNumber       string `json:"certificateSerialNumber"`
		CertificatePublicKeyAlgorithm string `json:"certificatePublicKeyAlgorithm"`
		CertificateSignatureAlgorithm string `json:"certificateSignatureAlgorithm"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp) != 1 {
		t.Fatalf("want 1 cert, got %d", len(resp))
	}
	if !strings.Contains(resp[0].CertificatePEM, "BEGIN CERTIFICATE") {
		t.Error("cert PEM not in response body")
	}
	// Parsed-metadata fields must all be populated — the issued
	// identity cert is a real X.509 we generate at registration time,
	// so there's no reason for any of these to come back empty.
	if resp[0].CertificateSubject == "" {
		t.Error("subject not populated")
	}
	if resp[0].CertificateIssuer == "" {
		t.Error("issuer not populated")
	}
	if resp[0].CertificateSerialNumber == "" {
		t.Error("serial number not populated")
	}
	if resp[0].CertificatePublicKeyAlgorithm == "" {
		t.Error("public-key algorithm not populated")
	}
	if resp[0].CertificateSignatureAlgorithm == "" {
		t.Error("signature algorithm not populated")
	}
}

func TestGetServerCerts_ReturnsIssuedArray(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// Default register path uses serverCsrPEM → the server CA signs
	// at verify-acme → we expect the issued leaf to surface on GET
	// once the lifecycle has advanced.
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	if rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/certificates/server", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp []struct {
		CertificatePEM string `json:"certificatePEM"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v body=%s", err, rec.Body)
	}
	if len(resp) != 1 {
		t.Fatalf("want exactly one server cert (issued via CSR path), got %d", len(resp))
	}
	if !strings.HasPrefix(resp[0].CertificatePEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certificatePEM not PEM-encoded: %.40s", resp[0].CertificatePEM)
	}
}

func TestGetServerCerts_NotOwnedReturns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID+"/certificates/server", nil, fx.asOwner("bob"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

// activateAgent drives a fresh registration through verify-acme +
// verify-dns so subsequent CSR-submission tests can run against an
// ACTIVE agent. Uses the test router's own routes so the lifecycle
// state machine is exercised end-to-end.
func (f *handlerFixture) activateAgent(t *testing.T, ownerID, agentID string) {
	t.Helper()
	rec := f.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, f.asOwner(ownerID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: got %d body=%s", rec.Code, rec.Body)
	}
	rec = f.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-dns", nil, f.asOwner(ownerID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("verify-dns: got %d body=%s", rec.Code, rec.Body)
	}
}

func TestSubmitIdentityCSR_AcceptsRotation(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	// Rotation CSR — same ANS name so the validator's CN-match rule is satisfied.
	csrPEM := newTestCSR(t, "ans://v1.0.0.agent.example.com")
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/identity",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		CsrID   string `json:"csrId"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CsrID == "" {
		t.Error("csrId not populated")
	}
	if resp.Message == "" {
		t.Error("message not populated")
	}
}

func TestSubmitIdentityCSR_RejectedOnNonActiveAgent(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// Newly-registered agent is PENDING_VALIDATION — identity CSR
	// submission should be rejected per reference's status gate.
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	csrPEM := newTestCSR(t, "ans://v1.0.0.agent.example.com")
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/identity",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 (AGENT_NOT_ACTIVE), got %d body=%s", rec.Code, rec.Body)
	}
}

// registerAgentNoIdentityCSR is the no-identity-CSR analogue of
// registerAgent: it POSTs a V2 registration that omits identityCsrPEM
// (server CSR still supplied) and returns the new agentId.
func (f *handlerFixture) registerAgentNoIdentityCSR(t *testing.T, ownerID, host, version string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "No identity CSR",
		"version":          version,
		"agentHost":        host,
		"endpoints": []map[string]any{
			{"agentUrl": "https://" + host + "/mcp", "protocol": "MCP", "transports": []string{"SSE"}},
		},
		// identityCsrPEM intentionally omitted.
		"serverCsrPEM": newTestServerCSR(t, host),
	})
	rec := f.request(t, http.MethodPost, "/v2/ans/agents", bytes.NewReader(body), f.asOwner(ownerID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register %s without identity CSR: status=%d body=%s", host, rec.Code, rec.Body)
	}
	var resp struct {
		AgentID string `json:"agentId"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse register response: %v", err)
	}
	if resp.AgentID == "" {
		t.Fatal("register returned empty agentId")
	}
	if resp.Status != "PENDING_VALIDATION" {
		t.Fatalf("status: got %q want PENDING_VALIDATION", resp.Status)
	}
	return resp.AgentID
}

// TestRegister_NoIdentityCSR_Accepted covers the V2 optional
// identity-CSR path at the HTTP layer: a registration omitting
// identityCsrPEM is accepted with 202 + PENDING_VALIDATION (asserted in
// the helper). The agent simply gets no identity certificate.
func TestRegister_NoIdentityCSR_Accepted(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	if id := fx.registerAgentNoIdentityCSR(t, "alice", "no-id-csr.example.com", "1.0.0"); id == "" {
		t.Fatal("expected a non-empty agentId")
	}
}

// TestSubmitIdentityCSR_NoIdentityCSR_Rejected covers the no-add-later
// guard at the HTTP layer: an ACTIVE agent that registered without an
// identity CSR cannot obtain one via POST .../certificates/identity. It
// must register a new version instead — the route returns 409 with code
// IDENTITY_CSR_NOT_PERMITTED.
func TestSubmitIdentityCSR_NoIdentityCSR_Rejected(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "no-add-later.example.com"
	agentID := fx.registerAgentNoIdentityCSR(t, "alice", host, "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	csrPEM := newTestCSR(t, "ans://v1.0.0."+host)
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/identity",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d body=%s", rec.Code, rec.Body)
	}
	var prob struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("parse problem details: %v", err)
	}
	if prob.Code != "IDENTITY_CSR_NOT_PERMITTED" {
		t.Fatalf("code: got %q want IDENTITY_CSR_NOT_PERMITTED", prob.Code)
	}
}

func TestSubmitServerCSR_AcceptsRegardlessOfStatus(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// Pending agent — server CSRs don't gate on status.
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	// Server CSR — DNS SAN must match agent FQDN.
	csrPEM := newTestServerCSR(t, "agent.example.com")
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestSubmitCSR_MissingBody_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	// Empty JSON body → no csrPEM field → 422.
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server",
		bytes.NewReader([]byte(`{}`)), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestGetCSRStatus_ReturnsPendingForFreshSubmission(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	csrPEM := newTestServerCSR(t, "agent.example.com")
	body, _ := json.Marshal(map[string]any{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("seed submit: got %d body=%s", rec.Code, rec.Body)
	}
	var submit struct {
		CsrID string `json:"csrId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &submit)

	rec = fx.request(t, http.MethodGet,
		"/v2/ans/agents/"+agentID+"/csrs/"+submit.CsrID+"/status",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rec.Code, rec.Body)
	}
	var status struct {
		CsrID       string `json:"csrId"`
		Type        string `json:"type"`
		Status      string `json:"status"`
		SubmittedAt string `json:"submittedAt"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if status.CsrID != submit.CsrID {
		t.Errorf("csrId roundtrip failed: got %q want %q", status.CsrID, submit.CsrID)
	}
	if status.Type != "SERVER" {
		t.Errorf("type: got %q want SERVER", status.Type)
	}
	if status.Status != "PENDING" {
		t.Errorf("status: got %q want PENDING", status.Status)
	}
	if status.SubmittedAt == "" {
		t.Error("submittedAt not populated")
	}
}

func TestGetCSRStatus_UnknownCSR_Returns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet,
		"/v2/ans/agents/"+agentID+"/csrs/00000000-0000-0000-0000-000000000000/status",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestSubmitRenewal_RejectedWhenAgentNotActive(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	// Fresh registration is PENDING_VALIDATION — renewal must 409.
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 (AGENT_NOT_ACTIVE), got %d body=%s", rec.Code, rec.Body)
	}
}

func TestSubmitRenewal_CSRPath_202(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		RenewalType string `json:"renewalType"`
		Status      string `json:"status"`
		CsrID       string `json:"csrId"`
		ExpiresAt   string `json:"expiresAt"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.RenewalType != "SERVER_CSR" {
		t.Errorf("renewalType: got %q want SERVER_CSR", resp.RenewalType)
	}
	if resp.Status != "PENDING_VALIDATION" {
		t.Errorf("status: got %q want PENDING_VALIDATION", resp.Status)
	}
	if resp.CsrID == "" {
		t.Error("csrId missing")
	}
	if resp.ExpiresAt == "" {
		t.Error("expiresAt missing")
	}
}

func TestSubmitRenewal_BothInputs_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	// Both serverCsrPEM and serverCertificatePEM set — 422.
	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM":         newTestServerCSR(t, "agent.example.com"),
		"serverCertificatePEM": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
	})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestSubmitRenewal_DuplicateReturns409(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	// First submission should succeed.
	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first submit: got %d", rec.Code)
	}
	// Second submission while the first is pending should 409.
	body2, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	rec = fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body2), fx.asOwner("alice"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestGetRenewal_ReturnsPendingStatus(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	if rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("seed submit: %d", rec.Code)
	}

	rec := fx.request(t, http.MethodGet,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "PENDING_VALIDATION" {
		t.Errorf("status: got %q", resp.Status)
	}
}

func TestVerifyRenewal_CSR_Returns200Completed(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	// Seed a CSR renewal.
	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	if rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("seed: %d", rec.Code)
	}

	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal/verify-acme",
		nil, fx.asOwner("alice"))
	// CSR path with a configured server CA issues synchronously at
	// verify-acme → 200 COMPLETED. Async issuance would return 202
	// ISSUING_CERTIFICATE; when the async path lands (background
	// job for slow CAs) this test will need a mode switch.
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-acme: got %d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "COMPLETED" {
		t.Errorf("status: got %q want COMPLETED", resp.Status)
	}
}

func TestCancelRenewal_DeletesPendingAnd404sAfter(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	if rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("seed: %d", rec.Code)
	}

	rec := fx.request(t, http.MethodDelete,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cancel: got %d body=%s", rec.Code, rec.Body)
	}
	// Subsequent GET returns 404 — the row's gone.
	rec = fx.request(t, http.MethodGet,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after cancel: got %d body=%s", rec.Code, rec.Body)
	}
}

func TestVerifyACME_TransitionsToPendingDNS(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Status string `json:"status"`
		Phase  string `json:"phase"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "PENDING_DNS" {
		t.Errorf("status: got %q want PENDING_DNS", resp.Status)
	}
	if resp.Phase != "DNS_PROVISIONING" {
		t.Errorf("phase: got %q want DNS_PROVISIONING", resp.Phase)
	}
}

func TestVerifyDNS_ActivatesWhenRecordsMatch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	// Advance to PENDING_DNS.
	_ = fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))

	// DNSVerifier is noop → treats all records as matching.
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("verify-dns status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "ACTIVE" {
		t.Fatalf("status: got %q want ACTIVE", resp.Status)
	}

	// Exactly one sealed event: a single terminal AGENT_REGISTERED
	// sealed INLINE at the PENDING_DNS → ACTIVE transition
	// (seal-before-success). Activation does not report ACTIVE until
	// the event is durable in the TL, so it never rides the outbox.
	// The V1 reference and production TL both use this single-terminal
	// model — no AGENT_REGISTRATION / DOMAIN_VALIDATION intermediate
	// events exist on either lane.
	sealed := fx.sealer.sealedTypes()
	if len(sealed) != 1 {
		t.Fatalf("sealed events: got %v, want 1 (single AGENT_REGISTERED terminal)", sealed)
	}
	if sealed[0] != "AGENT_REGISTERED" {
		t.Errorf("eventType: got %q, want AGENT_REGISTERED", sealed[0])
	}

	// Activation seals inline, so nothing is claimable by the outbox
	// worker — the only row it writes is the pre-delivered feed row
	// (sent + logId at insert), which Claim never returns.
	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("claimable outbox rows: got %d, want 0 (activation seals inline)", len(rows))
	}
}

// TestVerifyDNS_SealFailure_Returns503 pins the seal-before-success
// contract at the HTTP boundary. When the inline TL seal fails (TL
// unreachable), verify-dns must surface 503 SERVICE_UNAVAILABLE and the
// agent must stay PENDING_DNS — never reporting ACTIVE for an agent that
// was never written to the log.
func TestVerifyDNS_SealFailure_Returns503(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	_ = fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))

	// Arm the sealer to fail as the tlclient would when the TL is down.
	fx.sealer.failErr = domain.NewUnavailableError("TL_UNAVAILABLE", "tl down")

	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("verify-dns on seal failure: got %d, want 503; body=%s", rec.Code, rec.Body)
	}

	// Fail-closed: the agent must still read as PENDING_DNS, and nothing
	// leaked onto the outbox.
	det := fx.request(t, http.MethodGet, "/v2/ans/agents/"+agentID, nil, fx.asOwner("alice"))
	var detResp struct {
		AgentStatus string `json:"agentStatus"`
	}
	_ = json.Unmarshal(det.Body.Bytes(), &detResp)
	if detResp.AgentStatus != "PENDING_DNS" {
		t.Fatalf("agent must stay PENDING_DNS after a failed seal; got %q", detResp.AgentStatus)
	}
	if rows, _ := fx.outbox.Claim(context.Background(), 100); len(rows) != 0 {
		t.Errorf("activation must not enqueue to the outbox; got %d rows", len(rows))
	}
}

func TestRevoke_TransitionsToRevokedAndEmitsEvent(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	// Walk state to ACTIVE first (revoke requires ACTIVE or DEPRECATED).
	_ = fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	_ = fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))

	body := `{"reason":"KEY_COMPROMISE","comments":"test revoke"}`
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/revoke",
		bytes.NewReader([]byte(body)), fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "REVOKED" {
		t.Errorf("status: got %q want REVOKED", resp.Status)
	}
	if resp.Reason != "KEY_COMPROMISE" {
		t.Errorf("reason: got %q", resp.Reason)
	}

	// After the register → verify-acme → verify-dns → revoke walk, the
	// two terminal events land on different rails. AGENT_REGISTERED is
	// sealed INLINE at the ACTIVE transition (seal-before-success), so
	// it lives in the sealer, not the outbox. AGENT_REVOKED still rides
	// the outbox: revoke is an idempotent terminal transition whose
	// async delivery is safe — the agent is already REVOKED locally and
	// stays visible until the log catches up. Intermediate events don't
	// exist on either lane.
	sawRegistered := false
	for _, et := range fx.sealer.sealedTypes() {
		if et == "AGENT_REGISTERED" {
			sawRegistered = true
		}
	}
	if !sawRegistered {
		t.Error("sealer missing AGENT_REGISTERED event")
	}

	rows, _ := fx.outbox.Claim(context.Background(), 100)
	sawRevoked := false
	for _, row := range rows {
		if row.EventType == "AGENT_REGISTERED" {
			t.Error("AGENT_REGISTERED must be sealed inline, not enqueued to the outbox")
		}
		if row.EventType == "AGENT_REVOKED" {
			sawRevoked = true
		}
	}
	if !sawRevoked {
		t.Error("outbox missing AGENT_REVOKED event")
	}
}

func TestRevoke_BadReason_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	// Must be ACTIVE first so the "bad reason" path is hit, not the state-machine error.
	_ = fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	_ = fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))

	body := `{"reason":"MADE_UP","comments":"nope"}`
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/revoke",
		bytes.NewReader([]byte(body)), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422 for bad reason, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestRevoke_NotOwnedReturns403(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")

	body := `{"reason":"KEY_COMPROMISE"}`
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/revoke",
		bytes.NewReader([]byte(body)), fx.asOwner("bob"))
	// Write routes: explicit 403 so operators can distinguish auth
	// from existence.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d body=%s", rec.Code, rec.Body)
	}
}

// ----- fixture -----

type handlerFixture struct {
	router chi.Router
	outbox *sqlite.OutboxStore
	sealer *recordingAgentSealer        // captures AGENT_REGISTERED sealed at activation
	svc    *service.RegistrationService // exposed for direct-handler tests
}

// ----- FQDN exclusivity (one-host-one-owner) -----
//
// Once a registration goes live (ACTIVE/DEPRECATED) on an FQDN, that FQDN
// belongs to its owner alone: a different owner may neither register nor
// activate on it until no live registration remains. Checked at every
// progression step (register, verify-acme, verify-dns) as a fast-fail,
// and decided authoritatively by commitActivation's in-tx re-check —
// these tests pin the sequential contract; the mid-seal race interleavings
// are pinned by the service-level TestVerifyDNS_Rival* tests.

// registerRaw POSTs a registration and returns the recorder without
// asserting status — for the conflict paths where 409 is the expectation.
func (f *handlerFixture) registerRaw(t *testing.T, owner, host, version string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "Exclusivity",
		"version":          version,
		"agentHost":        host,
		"endpoints": []map[string]any{
			{"agentUrl": "https://" + host + "/mcp", "protocol": "MCP", "transports": []string{"SSE"}},
		},
		"identityCsrPEM": newTestCSR(t, "ans://v"+version+"."+host),
		"serverCsrPEM":   newTestServerCSR(t, host),
	})
	return f.request(t, http.MethodPost, "/v2/ans/agents", bytes.NewReader(body), f.asOwner(owner))
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p.Code
}

func TestFQDNExclusivity_DifferentOwnerRegisterRejected(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "excl.example.com"
	a := fx.registerAgent(t, "alice", host, "1.0.0")
	fx.activateAgent(t, "alice", a)

	rec := fx.registerRaw(t, "bob", host, "2.0.0")
	if rec.Code != http.StatusConflict {
		t.Fatalf("bob register on alice's active host: status=%d body=%s, want 409", rec.Code, rec.Body)
	}
	if c := problemCode(t, rec); c != "AGENT_HOST_TAKEN" {
		t.Errorf("code = %q, want AGENT_HOST_TAKEN", c)
	}
}

func TestFQDNExclusivity_SameOwnerMayAddVersion(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "excl-same.example.com"
	a := fx.registerAgent(t, "alice", host, "1.0.0")
	fx.activateAgent(t, "alice", a)

	// The same owner may register another version while the first is
	// ACTIVE (version coexistence, ANS-1 §7.1).
	if rec := fx.registerRaw(t, "alice", host, "2.0.0"); rec.Code != http.StatusAccepted {
		t.Fatalf("same owner adding a version: status=%d body=%s, want 202", rec.Code, rec.Body)
	}
}

// TestFQDNExclusivity_LoserCanceledOnWinnerActivation is the scenario from
// the requirement: A (who does not control the host) and B (who does) both
// submit pending registrations — both allowed — and when B's registration
// goes ACTIVE, A's pending registration is cancelled.
func TestFQDNExclusivity_LoserCanceledOnWinnerActivation(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "excl-cancel.example.com"

	// Both pending → both allowed (the host is not yet live).
	loser := fx.registerAgent(t, "alice", host, "1.0.0")
	winner := fx.registerAgent(t, "bob", host, "2.0.0")

	// B finishes registration → goes ACTIVE, taking the host.
	fx.activateAgent(t, "bob", winner)

	// A's pending registration was cancelled by B's activation.
	rec := fx.request(t, http.MethodGet, "/v2/ans/agents/"+loser, nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("alice detail status=%d body=%s", rec.Code, rec.Body)
	}
	var detail struct {
		AgentStatus string `json:"agentStatus"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &detail)
	if detail.AgentStatus != "REVOKED" {
		t.Errorf("loser status = %q, want REVOKED (cancelled when winner activated)", detail.AgentStatus)
	}
}

// TestFQDNExclusivity_LoserRejectedAtEveryLevel confirms that once the host
// is taken, the losing registration is rejected at verify-acme AND
// verify-dns (not only at the final activation).
func TestFQDNExclusivity_LoserRejectedAtEveryLevel(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "excl-levels.example.com"
	loser := fx.registerAgent(t, "alice", host, "1.0.0")
	winner := fx.registerAgent(t, "bob", host, "2.0.0")
	fx.activateAgent(t, "bob", winner)

	for _, step := range []string{"verify-acme", "verify-dns"} {
		rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+loser+"/"+step, nil, fx.asOwner("alice"))
		if rec.Code != http.StatusConflict {
			t.Fatalf("loser %s: status=%d body=%s, want 409", step, rec.Code, rec.Body)
		}
		if c := problemCode(t, rec); c != "AGENT_HOST_TAKEN" {
			t.Errorf("loser %s code = %q, want AGENT_HOST_TAKEN", step, c)
		}
	}
}

func TestFQDNExclusivity_FreedAfterRevoke(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	host := "excl-freed.example.com"
	a := fx.registerAgent(t, "alice", host, "1.0.0")
	fx.activateAgent(t, "alice", a)

	// Alice revokes → no live registration remains on the host.
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+a+"/revoke",
		bytes.NewReader([]byte(`{"reason":"CESSATION_OF_OPERATION","comments":"done"}`)), fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("alice revoke: status=%d body=%s", rec.Code, rec.Body)
	}
	// Bob may now take the freed host — and activate on it. Activating
	// also exercises cancelConflictingPendings skipping alice's terminal
	// (REVOKED) registration.
	b := fx.registerAgent(t, "bob", host, "2.0.0")
	fx.activateAgent(t, "bob", b)
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	dir := t.TempDir()

	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	agents := sqlite.NewAgentStore(db)
	endpoints := sqlite.NewEndpointStore(db)
	certsStore := sqlite.NewCertificateStore(db)
	byoc := sqlite.NewByocCertificateStore(db)
	renewals := sqlite.NewRenewalStore(db)
	outbox := sqlite.NewOutboxStore(db)

	identityCA, err := cert.NewSelfCA(dir+"/ca", "Test CA", 365)
	if err != nil {
		t.Fatal(err)
	}
	// Wire a server CA in the fixture so the default register helper
	// exercises the serverCsrPEM → sign flow (matching the reference's
	// default expectation of an RA-signed server cert). BYOC tests
	// can bypass this via a dedicated helper.
	serverCA, err := cert.NewServerSelfCA(dir+"/server-ca", "Test Server CA", 365)
	if err != nil {
		t.Fatal(err)
	}
	validator := cert.NewX509Validator(cert.WithSkipChainVerify())
	bus := eventbus.NewInMemoryBus(zerolog.Nop())

	km, err := keymanager.NewFileKeyManager(dir + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(context.Background(), "ra-signer", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}

	discoveryReg, err := service.NewDefaultProfileRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	sealer := &recordingAgentSealer{}
	svc := service.NewRegistrationService(
		agents, endpoints, certsStore, byoc, renewals, validator, identityCA, bus, outbox, db, discoveryReg,
	).WithSigner(service.EventSigner{
		KeyManager: km,
		KeyID:      "ra-signer",
		RaID:       "ra-test",
	}).WithDNSVerifier(dns.NewNoopVerifier()).
		WithServerCertificateIssuer(serverCA).
		WithAgentSealer(sealer)

	r := chi.NewRouter()
	regH := handler.NewRegistrationHandler(svc, zerolog.Nop())
	lifeH := handler.NewLifecycleHandler(svc, zerolog.Nop())
	readOwn := ramiddleware.ReadOwnership(agents)
	writeOwn := ramiddleware.WriteOwnership(agents)

	r.Post("/v2/ans/agents", regH.Register)
	r.Get("/v2/ans/agents", lifeH.List)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}", lifeH.Detail)
	catH := handler.NewCatalogHandler(svc, zerolog.Nop())
	r.With(readOwn).Get("/v2/ans/agents/{agentId}/catalog-entry", catH.CatalogEntry)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}/ai-catalog", catH.HostCatalog)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}/certificates/identity", lifeH.GetIdentityCerts)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}/certificates/server", lifeH.GetServerCerts)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}/csrs/{csrId}/status", lifeH.GetCSRStatus)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/verify-acme", lifeH.VerifyACME)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/verify-dns", lifeH.VerifyDNS)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/revoke", lifeH.Revoke)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/certificates/identity", lifeH.SubmitIdentityCSR)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/certificates/server", lifeH.SubmitServerCSR)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}/certificates/server/renewal", lifeH.GetServerCertRenewal)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/certificates/server/renewal", lifeH.SubmitServerCertRenewal)
	r.With(writeOwn).Delete("/v2/ans/agents/{agentId}/certificates/server/renewal", lifeH.CancelServerCertRenewal)
	r.With(writeOwn).Post("/v2/ans/agents/{agentId}/certificates/server/renewal/verify-acme", lifeH.VerifyRenewalACME)

	// V1 RA routes — mount on the same router so V1 handler tests can
	// reuse the fixture. Shares services with V2; only the DTOs +
	// URL prefixes differ.
	v1regH := handler.NewV1RegistrationHandler(svc, zerolog.Nop())
	r.Post("/v1/agents/register", v1regH.Register)
	r.With(readOwn).Get("/v1/agents/{agentId}", v1regH.Detail)

	v1lifeH := handler.NewV1LifecycleHandler(svc, zerolog.Nop())
	r.With(writeOwn).Post("/v1/agents/{agentId}/verify-acme", v1lifeH.VerifyACME)
	r.With(writeOwn).Post("/v1/agents/{agentId}/verify-dns", v1lifeH.VerifyDNS)
	r.With(writeOwn).Post("/v1/agents/{agentId}/revoke", v1lifeH.Revoke)

	v1certH := handler.NewV1CertificatesHandler(svc, zerolog.Nop())
	r.With(readOwn).Get("/v1/agents/{agentId}/certificates/identity", v1certH.GetIdentityCerts)
	r.With(readOwn).Get("/v1/agents/{agentId}/certificates/server", v1certH.GetServerCerts)
	r.With(readOwn).Get("/v1/agents/{agentId}/csrs/{csrId}/status", v1certH.GetCSRStatus)
	r.With(writeOwn).Post("/v1/agents/{agentId}/certificates/identity", v1certH.SubmitIdentityCSR)
	r.With(writeOwn).Post("/v1/agents/{agentId}/certificates/server", v1certH.SubmitServerCSR)

	v1renH := handler.NewV1RenewalHandler(svc, zerolog.Nop())
	r.With(writeOwn).Post("/v1/agents/{agentId}/certificates/server/renewal", v1renH.SubmitServerCertRenewal)
	r.With(readOwn).Get("/v1/agents/{agentId}/certificates/server/renewal", v1renH.GetServerCertRenewal)
	r.With(writeOwn).Delete("/v1/agents/{agentId}/certificates/server/renewal", v1renH.CancelServerCertRenewal)
	r.With(writeOwn).Post("/v1/agents/{agentId}/certificates/server/renewal/verify-acme", v1renH.VerifyRenewalACME)

	return &handlerFixture{router: r, outbox: outbox, sealer: sealer, svc: svc}
}

// asOwner wraps a request with a synthetic Identity matching the
// given subject. Mimics the auth-provider middleware, which in tests
// we don't run end-to-end.
func (f *handlerFixture) asOwner(subject string) func(*http.Request) {
	return func(r *http.Request) {
		ctx := auth.WithIdentity(r.Context(), &port.Identity{Subject: subject})
		*r = *r.WithContext(ctx)
	}
}

func (f *handlerFixture) request(t *testing.T, method, path string, body *bytes.Reader, tweak func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, body)
	}
	req.Header.Set("Content-Type", "application/json")
	if tweak != nil {
		tweak(req)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// registerAgent issues a POST /v2/ans/agents for the given owner and
// returns the new agentId. Uses the CSR path for the server cert
// (matching the reference's default registration expectation): an
// identity CSR with matching URI SAN + a server CSR with matching
// DNS SAN. The fixture's server CA signs the server CSR.
func (f *handlerFixture) registerAgent(t *testing.T, ownerID, host, version string) string {
	t.Helper()
	identityCSR := newTestCSR(t, "ans://v"+version+"."+host)
	serverCSR := newTestServerCSR(t, host)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "Test",
		"version":          version,
		"agentHost":        host,
		"endpoints": []map[string]any{
			{
				"agentUrl":   "https://" + host + "/mcp",
				"protocol":   "MCP",
				"transports": []string{"SSE"},
			},
		},
		"identityCsrPEM": identityCSR,
		"serverCsrPEM":   serverCSR,
	})
	rec := f.request(t, http.MethodPost, "/v2/ans/agents", bytes.NewReader(body), f.asOwner(ownerID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register %s: status=%d body=%s", host, rec.Code, rec.Body)
	}
	var resp struct {
		AgentID string `json:"agentId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AgentID == "" {
		t.Fatal("register returned empty agentId")
	}
	// Avoid stale domain state between tests by probing the store
	// directly when diagnosing failures — but the return is enough.
	_ = domain.StatusPendingValidation
	return resp.AgentID
}
