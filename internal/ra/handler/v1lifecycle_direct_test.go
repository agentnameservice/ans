package handler_test

// Direct-handler tests for the V1 lifecycle endpoints. The router-
// level tests can't reach the service-error branches because the
// WriteOwnership middleware short-circuits unknown agentIDs at 404
// before the handler runs. To pin those branches we build a chi
// route context with the agentID directly and call the handler
// method without middleware.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	authpkg "github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/handler"
)

// directReq builds an *http.Request with a chi route context whose
// "agentId" is set to the given value, suitable for invoking V1/V2
// lifecycle handlers directly without the router stack.
func directReq(method, path, agentID string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", agentID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestV1LifecycleHandler_VerifyACME_ServiceErrorBranch covers the
// `if err := svc.VerifyACME(...); err != nil` branch in the V1
// VerifyACME handler — the service errors when called for an
// unknown agentID. Pre-coverage only the happy path landed because
// the writeOwn middleware blocked the unknown-agent case before the
// handler ran.
func TestV1LifecycleHandler_VerifyACME_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1LifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.VerifyACME(rec, directReq(http.MethodPost, "/v1/agents/no-such/verify-acme", "no-such"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1LifecycleHandler_VerifyDNS_ServiceErrorBranch — same shape
// for VerifyDNS.
func TestV1LifecycleHandler_VerifyDNS_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1LifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.VerifyDNS(rec, directReq(http.MethodPost, "/v1/agents/no-such/verify-dns", "no-such"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1RegistrationHandler_Detail_ServiceErrorBranch hits the
// V1 Detail handler's err-branch via direct invocation (router
// path goes through readOwn middleware).
func TestV1RegistrationHandler_Detail_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1RegistrationHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.Detail(rec, directReq(http.MethodGet, "/v1/agents/no-such", "no-such"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1RegistrationHandler_Detail_EmptyAgentID covers the V1
// registration Detail handler's "agentID == ”" guard.
func TestV1RegistrationHandler_Detail_EmptyAgentID(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1RegistrationHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.Detail(rec, directReq(http.MethodGet, "/v1/agents/", ""))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

// TestV1RenewalHandler_GetServerCertRenewal_ServiceErrorBranch
// covers the V1 GetServerCertRenewal err-branch.
func TestV1RenewalHandler_GetServerCertRenewal_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1RenewalHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.GetServerCertRenewal(rec, directReq(http.MethodGet,
		"/v1/agents/no-such/certificates/server/renewal", "no-such"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1RenewalHandler_CancelServerCertRenewal_ServiceErrorBranch
// covers the V1 CancelServerCertRenewal err-branch.
func TestV1RenewalHandler_CancelServerCertRenewal_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1RenewalHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.CancelServerCertRenewal(rec, directReq(http.MethodDelete,
		"/v1/agents/no-such/certificates/server/renewal", "no-such"))
	if rec.Code == http.StatusNoContent {
		t.Fatalf("expected error status, not 204; body=%s", rec.Body)
	}
}

// ----- V2 lifecycle direct tests -----
//
// Same pattern for V2 handlers — bypass writeOwn middleware to hit
// the service-error branches that the integration tests can't
// reach because the middleware blocks unknown agentIDs at 404.

func TestLifecycleHandler_Detail_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.Detail(rec, directReq(http.MethodGet, "/v2/ans/agents/no-such", "no-such"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestLifecycleHandler_VerifyACME_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.VerifyACME(rec, directReq(http.MethodPost, "/v2/ans/agents/no-such/verify-acme", "no-such"))
	if rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestLifecycleHandler_VerifyDNS_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.VerifyDNS(rec, directReq(http.MethodPost, "/v2/ans/agents/no-such/verify-dns", "no-such"))
	if rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestLifecycleHandler_CancelServerCertRenewal_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.CancelServerCertRenewal(rec, directReq(http.MethodDelete,
		"/v2/ans/agents/no-such/certificates/server/renewal", "no-such"))
	if rec.Code == http.StatusNoContent {
		t.Fatalf("expected error status, not 204; body=%s", rec.Body)
	}
}

func TestLifecycleHandler_VerifyRenewalACME_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.VerifyRenewalACME(rec, directReq(http.MethodPost,
		"/v2/ans/agents/no-such/certificates/server/renewal/verify-acme", "no-such"))
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestLifecycleHandler_GetServerCertRenewal_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.GetServerCertRenewal(rec, directReq(http.MethodGet,
		"/v2/ans/agents/no-such/certificates/server/renewal", "no-such"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitRenewal_BYOCPath covers the BYOC arm of
// SubmitServerCertRenewal — pre-coverage we only saw the CSR arm
// (TestSubmitRenewal_CSRPath_202). Use the testbed's own
// self-signed-server-cert builder so the validator's chain check
// (skipChainVerify) accepts it.
func TestSubmitRenewal_BYOCPath(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	leafPEM, chainPEM := selfSignedLeafAndChain(t, "agent.example.com")
	body, _ := json.Marshal(map[string]any{
		"serverCertificatePEM":      leafPEM,
		"serverCertificateChainPEM": chainPEM,
	})
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		RenewalType string `json:"renewalType"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.RenewalType == "" {
		t.Error("renewalType empty")
	}
}

// TestV1SubmitRenewal_BYOCPath mirrors the V2 BYOC test for the
// V1 handler.
func TestV1SubmitRenewal_BYOCPath(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")

	leafPEM, chainPEM := selfSignedLeafAndChain(t, "agent.example.com")
	body, _ := json.Marshal(map[string]any{
		"serverCertificatePEM":      leafPEM,
		"serverCertificateChainPEM": chainPEM,
	})
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202; body=%s", rec.Code, rec.Body)
	}
}

// TestList_NoIdentityReturns403 covers the no-identity guard at
// the top of LifecycleHandler.List. The router test always carries
// auth, so this branch needs a direct call without an auth context.
func TestList_NoIdentityReturns403(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	// httptest.NewRequest gives a bare context — no identity.
	h.List(rec, httptest.NewRequest(http.MethodGet, "/v2/ans/agents", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d want 403 (NO_IDENTITY)", rec.Code)
	}
}

// TestRegister_NoIdentityReturns403 — V2 Register.
func TestRegister_NoIdentityReturns403(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewRegistrationHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"version":   "1.0.0",
		"agentHost": "x.example.com",
		"endpoints": []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
	})
	h.Register(rec, httptest.NewRequest(http.MethodPost, "/v2/ans/agents", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d want 403 (NO_IDENTITY)", rec.Code)
	}
}

// TestV1Register_NoIdentityReturns403 — V1 Register.
func TestV1Register_NoIdentityReturns403(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1RegistrationHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{
		"version":   "1.0.0",
		"agentHost": "x.example.com",
		"endpoints": []map[string]any{{"agentUrl": "https://x.example.com", "protocol": "MCP", "transports": []string{"SSE"}}},
	})
	h.Register(rec, httptest.NewRequest(http.MethodPost, "/v1/agents/register", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: got %d want 403 (NO_IDENTITY)", rec.Code)
	}
}

// TestRegister_BadAnsNameViaHostReturns422 — agentHost with a
// character that NewAnsName rejects (e.g. underscore in the host
// label) drives the ansName-construction error branch in both
// V2 and V1 Register handlers.
func TestRegister_BadAnsNameReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "bad_host_with_underscore.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x", "protocol": "MCP", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.bad_host_with_underscore.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "bad_host_with_underscore.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v2/ans/agents",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestV1Register_BadAnsNameReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	body, _ := json.Marshal(map[string]any{
		"agentDisplayName": "X",
		"version":          "1.0.0",
		"agentHost":        "bad_host_with_underscore.example.com",
		"endpoints":        []map[string]any{{"agentUrl": "https://x", "protocol": "MCP", "transports": []string{"SSE"}}},
		"identityCsrPEM":   newTestCSR(t, "ans://v1.0.0.bad_host_with_underscore.example.com"),
		"serverCsrPEM":     newTestServerCSR(t, "bad_host_with_underscore.example.com"),
	})
	rec := fx.request(t, http.MethodPost, "/v1/agents/register",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitServerCertRenewal_BadJSON covers the BAD_JSON branch in
// V2 SubmitServerCertRenewal — pre-coverage only the happy + bad-input
// (both inputs supplied) paths landed.
func TestSubmitServerCertRenewal_BadJSON(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitServerCertRenewal_BadJSON mirrors for V1.
func TestV1SubmitServerCertRenewal_BadJSON(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitIdentityCSR_BadJSON covers the BAD_JSON branch in the V2
// SubmitIdentityCSR handler.
func TestSubmitIdentityCSR_BadJSON(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/identity",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitServerCSR_BadJSON covers the V2 SubmitServerCSR
// BAD_JSON branch.
func TestSubmitServerCSR_BadJSON(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitIdentityCSR_BadJSON / TestV1SubmitServerCSR_BadJSON
// mirror for V1.
func TestV1SubmitIdentityCSR_BadJSON(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/identity",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

func TestV1SubmitServerCSR_BadJSON(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server",
		bytes.NewReader([]byte("{not json")), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// fakeDNSVerifier always returns a single MISSING + a single
// MISMATCH record. Used to drive the DNS-mismatch arm of
// VerifyDNS in both V1 and V2 lanes.
type fakeDNSVerifier struct{}

func (fakeDNSVerifier) VerifyRecords(_ context.Context, _ string, recs []domain.ExpectedDNSRecord) (*port.VerificationResult, error) {
	out := &port.VerificationResult{Results: make([]port.RecordVerification, 0, len(recs))}
	for i, rec := range recs {
		v := port.RecordVerification{Record: rec}
		if i == 0 {
			// first record reported as found mismatch
			v.Found = false
			v.Actual = "wrong-value"
		}
		out.Results = append(out.Results, v)
	}
	out.AllRequired = false
	return out, nil
}

// TestVerifyDNS_MismatchReturns422 covers the V2 VerifyDNS
// "len(res.DNSMismatches) > 0" arm — emit a 422 dnsVerificationError
// rather than 202. Pre-coverage only the all-matching path landed
// (the fixture wires NoopVerifier).
func TestVerifyDNS_MismatchReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	if rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-acme",
		nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
	}

	// Swap to a verifier that reports mismatches. Safe because
	// fx is per-test.
	fx.svc.WithDNSVerifier(fakeDNSVerifier{})

	rec := fx.request(t, http.MethodPost, "/v2/ans/agents/"+agentID+"/verify-dns",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestV1Revoke_ServiceErrorBranch covers the service-error arm
// of V1 Revoke. The router-level test for not-owned hits middleware
// 403 before the handler runs; this direct call lets the service
// itself surface the error.
func TestV1Revoke_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1LifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"reason": "KEY_COMPROMISE"})
	req := httptest.NewRequest(http.MethodPost, "/v1/agents/no-such/revoke", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.Revoke(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestRevoke_ServiceErrorBranch covers the V2 Revoke service-error
// arm.
func TestRevoke_ServiceErrorBranch(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"reason": "KEY_COMPROMISE"})
	req := httptest.NewRequest(http.MethodPost, "/v2/ans/agents/no-such/revoke", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.Revoke(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitIdentityCSR_ServiceError direct-handler coverage
// for the service-error arm of V2 SubmitIdentityCSR. The router
// path goes through writeOwn middleware which 404s for unknown
// agentIDs.
func TestSubmitIdentityCSR_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"csrPEM": newTestCSR(t, "ans://v1.0.0.x.example.com")})
	req := httptest.NewRequest(http.MethodPost,
		"/v2/ans/agents/no-such/certificates/identity", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.SubmitIdentityCSR(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitServerCSR_ServiceError mirrors for V2 SubmitServerCSR.
func TestSubmitServerCSR_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"csrPEM": newTestServerCSR(t, "x.example.com")})
	req := httptest.NewRequest(http.MethodPost,
		"/v2/ans/agents/no-such/certificates/server", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.SubmitServerCSR(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestSubmitServerCertRenewal_ServiceError covers V2
// SubmitServerCertRenewal's service-error arm.
func TestSubmitServerCertRenewal_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"serverCsrPEM": newTestServerCSR(t, "x.example.com")})
	req := httptest.NewRequest(http.MethodPost,
		"/v2/ans/agents/no-such/certificates/server/renewal", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.SubmitServerCertRenewal(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitIdentityCSR_ServiceError mirrors for V1.
func TestV1SubmitIdentityCSR_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1CertificatesHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"csrPEM": newTestCSR(t, "ans://v1.0.0.x.example.com")})
	req := httptest.NewRequest(http.MethodPost,
		"/v1/agents/no-such/certificates/identity", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.SubmitIdentityCSR(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestV1SubmitServerCSR_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1CertificatesHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"csrPEM": newTestServerCSR(t, "x.example.com")})
	req := httptest.NewRequest(http.MethodPost,
		"/v1/agents/no-such/certificates/server", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.SubmitServerCSR(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitServerCertRenewal_ServiceError covers the V1 SubmitServerCertRenewal
// service-error arm.
func TestV1SubmitServerCertRenewal_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1RenewalHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"serverCsrPEM": newTestServerCSR(t, "x.example.com")})
	req := httptest.NewRequest(http.MethodPost,
		"/v1/agents/no-such/certificates/server/renewal", bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "no-such")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.SubmitServerCertRenewal(rec, req)
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// cancelledCtxReq returns a request whose Context is already
// cancelled, so any DB query inside the handler errors with
// context.Canceled — driving the service-error branch in the
// cert-list handlers.
func cancelledCtxReq(method, path, agentID string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", agentID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	cctx, cancel := context.WithCancel(ctx)
	cancel() // pre-cancel
	return req.WithContext(cctx)
}

// TestV1GetIdentityCerts_ServiceError covers the err-arm in
// V1 GetIdentityCerts via a pre-cancelled request context.
func TestV1GetIdentityCerts_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1CertificatesHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.GetIdentityCerts(rec, cancelledCtxReq(http.MethodGet,
		"/v1/agents/x/certificates/identity", "x"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestV1GetServerCerts_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewV1CertificatesHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.GetServerCerts(rec, cancelledCtxReq(http.MethodGet,
		"/v1/agents/x/certificates/server", "x"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// V2 mirrors.
func TestGetIdentityCerts_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.GetIdentityCerts(rec, cancelledCtxReq(http.MethodGet,
		"/v2/ans/agents/x/certificates/identity", "x"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

func TestGetServerCerts_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	h.GetServerCerts(rec, cancelledCtxReq(http.MethodGet,
		"/v2/ans/agents/x/certificates/server", "x"))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestList_ServiceError covers LifecycleHandler.List's service-
// error arm via a cancelled request context.
func TestList_ServiceError(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	h := handler.NewLifecycleHandler(fx.svc, zerolog.Nop())
	rec := httptest.NewRecorder()
	// Need a real Identity in context first; then layer cancel.
	id := &port.Identity{Subject: "alice"}
	req := httptest.NewRequest(http.MethodGet, "/v2/ans/agents", nil)
	ctx := authpkg.WithIdentity(req.Context(), id)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	h.List(rec, req.WithContext(cctx))
	if rec.Code == http.StatusOK {
		t.Fatalf("expected error status; got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1VerifyDNS_MismatchReturns422 mirrors for V1 lane.
func TestV1VerifyDNS_MismatchReturns422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	if rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme",
		nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("v1 verify-acme: %d %s", rec.Code, rec.Body)
	}
	fx.svc.WithDNSVerifier(fakeDNSVerifier{})
	rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// TestVerifyRenewalACME_BYOCSync covers the BYOC + verify-acme
// sync arm: submit a BYOC renewal, then verify-acme returns 200
// (Sync=true). The CSR arm is already exercised by other tests.
func TestVerifyRenewalACME_BYOCSync(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.registerAgent(t, "alice", "agent.example.com", "1.0.0")
	fx.activateAgent(t, "alice", agentID)

	leafPEM, chainPEM := selfSignedLeafAndChain(t, "agent.example.com")
	submitBody, _ := json.Marshal(map[string]any{
		"serverCertificatePEM":      leafPEM,
		"serverCertificateChainPEM": chainPEM,
	})
	if rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(submitBody), fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodPost,
		"/v2/ans/agents/"+agentID+"/certificates/server/renewal/verify-acme",
		nil, fx.asOwner("alice"))
	// BYOC verify-acme is synchronous in this build → 200.
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-acme BYOC: want 200, got %d body=%s", rec.Code, rec.Body)
	}
}
