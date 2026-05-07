package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// V1 certificate-operation tests. Every handler pairs with a V2
// sibling that's already covered by lifecycle_test.go; these tests
// focus on the V1-specific wire (URL prefix + reference-shape
// parity) rather than re-testing the service semantics.

// TestV1GetIdentityCerts_ReturnsIssuedCertArray drives the V1 GET
// identity-certs path and confirms it returns the initial cert
// issued at verify-acme (certs no longer issue at register time —
// domain control must be proven first).
func TestV1GetIdentityCerts_ReturnsIssuedCertArray(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	// Drive through verify-acme so the identity CSR gets signed.
	if rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodGet,
		"/v1/agents/"+agentID+"/certificates/identity", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var certs []struct {
		CsrID          string `json:"csrId"`
		CertificatePEM string `json:"certificatePEM"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &certs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("expected at least one identity cert")
	}
	if certs[0].CsrID == "" {
		t.Error("csrId missing")
	}
	if !strings.HasPrefix(certs[0].CertificatePEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certificatePEM not PEM-encoded: %.40s", certs[0].CertificatePEM)
	}
}

// TestV1GetServerCerts_ReturnsIssuedArray drives the V1 GET server-
// certs path. The default V1 register uses the serverCsrPEM path,
// so the RA's server CA issues a cert at verify-acme — the handler
// surfaces it here.
func TestV1GetServerCerts_ReturnsIssuedArray(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	if rec := fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice")); rec.Code != http.StatusAccepted {
		t.Fatalf("verify-acme: %d %s", rec.Code, rec.Body)
	}

	rec := fx.request(t, http.MethodGet,
		"/v1/agents/"+agentID+"/certificates/server", nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var certs []struct {
		CertificatePEM string `json:"certificatePEM"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &certs); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("want exactly one server cert, got %d", len(certs))
	}
	if !strings.HasPrefix(certs[0].CertificatePEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("certificatePEM not PEM-encoded: %.40s", certs[0].CertificatePEM)
	}
}

// TestV1GetIdentityCerts_NotOwned_404 inherits the V2 hide-existence
// behavior on reads.
func TestV1GetIdentityCerts_NotOwned_404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet,
		"/v1/agents/"+agentID+"/certificates/identity", nil, fx.asOwner("bob"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitIdentityCSR_AcceptsRotation walks a V1 agent to ACTIVE,
// then submits a new identity CSR and expects 202 with a csrId.
func TestV1SubmitIdentityCSR_AcceptsRotation(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")
	// Walk to ACTIVE (identity CSR rotation is only allowed on ACTIVE).
	_ = fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-acme", nil, fx.asOwner("alice"))
	_ = fx.request(t, http.MethodPost, "/v1/agents/"+agentID+"/verify-dns", nil, fx.asOwner("alice"))

	csrPEM := newTestCSR(t, "ans://v1.0.0.agent.example.com")
	body, _ := json.Marshal(map[string]string{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/identity",
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
		t.Error("csrId missing on 202")
	}
}

// TestV1SubmitServerCSR_AcceptsRegardlessOfStatus: the reference
// allows server-CSR submission at any registration status. A
// just-registered agent is still-pending; the POST still returns
// 202 accepted.
func TestV1SubmitServerCSR_AcceptsRegardlessOfStatus(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	// Server CSRs carry DNS SAN (TLS server-auth shape), not URI SAN.
	csrPEM := newTestServerCSR(t, "agent.example.com")
	body, _ := json.Marshal(map[string]string{"csrPEM": csrPEM})
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

// TestV1SubmitCSR_MissingBody_422 on the V1 path. Matches V2 error
// code.
func TestV1SubmitCSR_MissingBody_422(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	body, _ := json.Marshal(map[string]string{}) // no csrPEM
	rec := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/identity",
		bytes.NewReader(body), fx.asOwner("alice"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "MISSING_CSR_PEM") {
		t.Errorf("expected MISSING_CSR_PEM code, got %s", rec.Body)
	}
}

// TestV1GetCSRStatus_ReturnsPendingForFreshSubmission does the full
// submit-then-query loop on the V1 URL family.
func TestV1GetCSRStatus_ReturnsPendingForFreshSubmission(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	// Server CSR for the /certificates/server path — DNS SAN shape.
	csrPEM := newTestServerCSR(t, "agent.example.com")
	body, _ := json.Marshal(map[string]string{"csrPEM": csrPEM})
	sub := fx.request(t, http.MethodPost,
		"/v1/agents/"+agentID+"/certificates/server",
		bytes.NewReader(body), fx.asOwner("alice"))
	if sub.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", sub.Code, sub.Body)
	}
	var sr struct {
		CsrID string `json:"csrId"`
	}
	_ = json.Unmarshal(sub.Body.Bytes(), &sr)

	rec := fx.request(t, http.MethodGet,
		"/v1/agents/"+agentID+"/csrs/"+sr.CsrID+"/status",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		CsrID  string `json:"csrId"`
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CsrID != sr.CsrID {
		t.Errorf("csrId: got %q want %q", resp.CsrID, sr.CsrID)
	}
	if resp.Status != "PENDING" {
		t.Errorf("status: got %q want PENDING", resp.Status)
	}
}

// TestV1GetCSRStatus_UnknownCSR_Returns404 matches reference
// behavior: unknown csrId → 404, not 500.
func TestV1GetCSRStatus_UnknownCSR_Returns404(t *testing.T) {
	t.Parallel()
	fx := newHandlerFixture(t)
	agentID, _ := fx.v1RegisterAgent(t, "alice", "agent.example.com", "1.0.0")

	rec := fx.request(t, http.MethodGet,
		"/v1/agents/"+agentID+"/csrs/does-not-exist/status",
		nil, fx.asOwner("alice"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d body=%s", rec.Code, rec.Body)
	}
}
