package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// V1 server-cert renewal tests. Focus: V1-specific wire (URL
// prefix, next-step endpoints point at /v1/…) + BYOC-only rejection
// of serverCsrPEM. Service semantics are already tested via the V2
// renewal tests.

// v1ActivateAgent is the V1 analogue of handlerFixture.activateAgent:
// registers the agent via the V1 path then walks through the V1
// verify-acme + verify-dns transitions so the agent is ACTIVE and
// renewal POSTs are accepted.
func (f *handlerFixture) v1ActivateAgent(t *testing.T, ownerID, host, version string) string {
	t.Helper()
	agentID, _ := f.v1RegisterAgent(t, ownerID, host, version)
	if rec := f.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, f.asOwner(ownerID)); rec.Code != http.StatusAccepted {
		t.Fatalf("v1 verify-acme: %d %s", rec.Code, rec.Body)
	}
	if rec := f.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns", nil, f.asOwner(ownerID)); rec.Code != http.StatusAccepted {
		t.Fatalf("v1 verify-dns: %d %s", rec.Code, rec.Body)
	}
	return agentID
}

// TestV1SubmitRenewal_CSRPath_202 confirms V1 renewal accepts
// serverCsrPEM (the RA's configured server CA signs). Reference
// parity: the reference RA supports both CSR and BYOC renewal paths.
func TestV1SubmitRenewal_CSRPath_202(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")

	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		RenewalType string `json:"renewalType"`
		Status      string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.RenewalType != "SERVER_CSR" {
		t.Errorf("renewalType: got %q want SERVER_CSR", resp.RenewalType)
	}
	if resp.Status != "PENDING_VALIDATION" {
		t.Errorf("status: got %q want PENDING_VALIDATION", resp.Status)
	}
}

// TestV1GetRenewal_NotFound_404 verifies that a GET renewal on an
// agent with no open renewal returns 404 (matches reference).
func TestV1GetRenewal_NotFound_404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1CancelRenewal_NotFound_404 verifies DELETE on a non-existent
// renewal returns 404.
func TestV1CancelRenewal_NotFound_404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodDelete,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitRenewal_RejectedWhenNotActive confirms V1 inherits the
// V2 precondition: renewal requires ACTIVE status.
func TestV1SubmitRenewal_RejectedWhenNotActive(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	// NOT calling v1ActivateAgent — agent stays PENDING_VALIDATION.

	body, _ := json.Marshal(map[string]any{
		"serverCertificatePEM": "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----",
	})
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 (AGENT_NOT_ACTIVE), got %d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "AGENT_NOT_ACTIVE") {
		t.Errorf("expected AGENT_NOT_ACTIVE code, got %s", rec.Body)
	}
}

// TestV1VerifyRenewalACME_NotFound_404 verifies the verify-acme
// endpoint returns 404 when there's no renewal to verify.
func TestV1VerifyRenewalACME_NotFound_404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal/verify-acme",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1VerifyRenewalACME_HappyPath covers the success branch of
// VerifyRenewalACME (separate from the 404 case). With the local
// self-CA wired in, the renewal completes synchronously after
// verify — the response is 200 with status COMPLETED. Pre-coverage
// only the 404 path landed.
func TestV1VerifyRenewalACME_HappyPath(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID := fx.v1ActivateAgent(t, "alice", "agent.example.com", "1.0.0")

	// Submit a CSR-based renewal.
	body, _ := json.Marshal(map[string]any{
		"serverCsrPEM": newTestServerCSR(t, "agent.example.com"),
	})
	if rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal",
		bytes.NewReader(body), fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server/renewal/verify-acme",
		nil, fx.asOwner("alice"))
	// The local self-CA signs synchronously, so the response is 200
	// with status COMPLETED — exercise the Sync=true branch.
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-acme: want 200, got %d body=%s", rec.Code, rec.Body)
	}
}
