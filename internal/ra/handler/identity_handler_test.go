package handler_test

// HTTP-level tests for the /v2/ans/identities surface: status codes,
// DTO shapes, auth extraction, and the agent-detail identities[]
// composition. The proof-gate logic itself is covered in depth by the
// service tests; these pin the wire contract.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/didresolver"
	"github.com/godaddy/ans/internal/adapter/eventbus"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/handler"
	ramiddleware "github.com/godaddy/ans/internal/ra/middleware"
	"github.com/godaddy/ans/internal/ra/service"
)

// identityHTTPFixture wires the identity routes (plus the agent
// register + detail routes the link tests need) over real SQLite and
// the noop resolver. No signer — covering the unsigned outbox branch;
// the signed path is pinned by the service tests.
type identityHTTPFixture struct {
	router chi.Router
}

func newIdentityHTTPFixture(t *testing.T) *identityHTTPFixture {
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
	serverCA, err := cert.NewServerSelfCA(dir+"/server-ca", "Test Server CA", 365)
	if err != nil {
		t.Fatal(err)
	}
	regSvc := service.NewRegistrationService(
		agents, endpoints, certsStore, byoc, renewals,
		cert.NewX509Validator(cert.WithSkipChainVerify()),
		identityCA, eventbus.NewInMemoryBus(zerolog.Nop()), outbox, db,
	).WithServerCertificateAuthority(serverCA)

	idSvc := service.NewIdentityService(
		sqlite.NewIdentityStore(db),
		sqlite.NewIdentityLinkStore(db),
		agents,
		didresolver.NewNoopResolver(),
		outbox,
		db,
	).WithChallengeTTL(30 * time.Minute)

	r := chi.NewRouter()
	regH := handler.NewRegistrationHandler(regSvc)
	lifeH := handler.NewLifecycleHandler(regSvc).WithIdentityViews(idSvc)
	readOwn := ramiddleware.ReadOwnership(agents)
	r.Post("/v2/ans/agents", regH.Register)
	r.With(readOwn).Get("/v2/ans/agents/{agentId}", lifeH.Detail)

	idH := handler.NewIdentityHandler(idSvc)
	r.Post("/v2/ans/identities", idH.Register)
	r.Get("/v2/ans/identities", idH.List)
	r.Get("/v2/ans/identities/{identityId}", idH.Detail)
	r.Put("/v2/ans/identities/{identityId}", idH.Rotate)
	r.Post("/v2/ans/identities/{identityId}/verify-control", idH.VerifyControl)
	r.Post("/v2/ans/identities/{identityId}/revoke", idH.Revoke)
	r.Post("/v2/ans/identities/{identityId}/links", idH.Link)
	r.Delete("/v2/ans/identities/{identityId}/links/{agentId}", idH.Unlink)

	return &identityHTTPFixture{router: r}
}

// do sends a request as the given owner ("" = unauthenticated) and
// returns the recorder.
func (f *identityHTTPFixture) do(t *testing.T, owner, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if owner != "" {
		req = req.WithContext(auth.WithIdentity(req.Context(), &port.Identity{Subject: owner}))
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// doRaw sends a raw (possibly malformed) body.
func (f *identityHTTPFixture) doRaw(t *testing.T, owner, method, path, raw string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(raw)))
	req.Header.Set("Content-Type", "application/json")
	if owner != "" {
		req = req.WithContext(auth.WithIdentity(req.Context(), &port.Identity{Subject: owner}))
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

type challengeBody struct {
	IdentityID string `json:"identityId"`
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Status     string `json:"status"`
	Nonce      string `json:"nonce"`
	ExpiresAt  string `json:"expiresAt"`
	Challenges []struct {
		Kid          string `json:"kid"`
		SigningInput string `json:"signingInput"`
	} `json:"challenges"`
}

// signIdentityProof mints a compact JWS over the served signingInput
// with the kid + embedded jwk headers — the registrant-side signing.
func signIdentityProof(t *testing.T, priv *ecdsa.PrivateKey, kid, signingInput string) string {
	t.Helper()
	jwk, err := anscrypto.PublicKeyToJWK(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	headerJSON, err := json.Marshal(map[string]any{"alg": "ES256", "kid": kid, "jwk": jwk})
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	toSign := encodedHeader + "." + signingInput
	digest := sha256.Sum256([]byte(toSign))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	p1363, err := anscrypto.DERToP1363(der, 32)
	if err != nil {
		t.Fatal(err)
	}
	return toSign + "." + base64.RawURLEncoding.EncodeToString(p1363)
}

// registerAndVerify drives an identity to VERIFIED over HTTP and
// returns its id and DID.
func (f *identityHTTPFixture) registerAndVerify(t *testing.T, owner, didValue string) string {
	t.Helper()
	rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities", map[string]string{"value": didValue})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var ch challengeBody
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := signIdentityProof(t, priv, didValue+"#key-1", ch.Challenges[0].SigningInput)
	rec = f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+ch.IdentityID+"/verify-control",
		map[string]any{"signedProofs": []string{proof}})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-control: %d %s", rec.Code, rec.Body)
	}
	return ch.IdentityID
}

func TestIdentityHandler_RegisterShape(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)

	rec := f.do(t, "owner-1", http.MethodPost, "/v2/ans/identities",
		map[string]string{"value": "did:web:identity.acme-corp.com"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var ch challengeBody
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.IdentityID == "" || ch.Kind != "did:web" || ch.Status != "PENDING_CONTROL" ||
		ch.Nonce == "" || ch.ExpiresAt == "" || len(ch.Challenges) != 1 ||
		ch.Challenges[0].SigningInput == "" {
		t.Fatalf("202 shape wrong: %+v", ch)
	}
}

func TestIdentityHandler_AuthAndValidation(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)

	// Unauthenticated → 403-shaped problem from callerSubject.
	if rec := f.do(t, "", http.MethodPost, "/v2/ans/identities",
		map[string]string{"value": "did:web:a.com"}); rec.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated register: %d", rec.Code)
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/v2/ans/identities"},
		{http.MethodGet, "/v2/ans/identities/x"},
		{http.MethodPut, "/v2/ans/identities/x"},
		{http.MethodPost, "/v2/ans/identities/x/verify-control"},
		{http.MethodPost, "/v2/ans/identities/x/revoke"},
		{http.MethodPost, "/v2/ans/identities/x/links"},
		{http.MethodDelete, "/v2/ans/identities/x/links/y"},
	} {
		if rec := f.do(t, "", route.method, route.path, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated %s %s: %d", route.method, route.path, rec.Code)
		}
	}

	// Malformed bodies → 422.
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v2/ans/identities"},
		{http.MethodPut, "/v2/ans/identities/x"},
		{http.MethodPost, "/v2/ans/identities/x/verify-control"},
		{http.MethodPost, "/v2/ans/identities/x/links"},
	} {
		if rec := f.doRaw(t, "owner-1", route.method, route.path, "{not json"); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("bad json %s %s: %d", route.method, route.path, rec.Code)
		}
	}
	// Empty value → 422 on register and rotate.
	if rec := f.do(t, "owner-1", http.MethodPost, "/v2/ans/identities", map[string]string{}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty value register: %d", rec.Code)
	}
	if rec := f.do(t, "owner-1", http.MethodPut, "/v2/ans/identities/x", map[string]string{}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty value rotate: %d", rec.Code)
	}
}

func TestIdentityHandler_FullLifecycleOverHTTP(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)
	owner := "owner-1"

	identityID := f.registerAndVerify(t, owner, "did:web:identity.acme-corp.com")

	// List.
	rec := f.do(t, owner, http.MethodGet, "/v2/ans/identities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var list struct {
		Identities []struct {
			IdentityID string `json:"identityId"`
			Status     string `json:"status"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Identities) != 1 || list.Identities[0].Status != "VERIFIED" {
		t.Fatalf("list shape: %+v", list)
	}

	// Register the agent to link.
	agentID := registerAgentForIdentity(t, f, owner, "linked.example.com")

	// Link → 200 {linked:1}.
	rec = f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+identityID+"/links",
		map[string]any{"agentIds": []string{agentID}})
	if rec.Code != http.StatusOK {
		t.Fatalf("link: %d %s", rec.Code, rec.Body)
	}
	var linked struct {
		Linked int `json:"linked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &linked); err != nil || linked.Linked != 1 {
		t.Fatalf("link response: %s (%v)", rec.Body, err)
	}

	// Identity detail carries the live link.
	rec = f.do(t, owner, http.MethodGet, "/v2/ans/identities/"+identityID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d", rec.Code)
	}
	var detail struct {
		Status       string `json:"status"`
		VerifiedAt   string `json:"verifiedAt"`
		LinkedAgents []struct {
			AgentID string `json:"agentId"`
		} `json:"linkedAgents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Status != "VERIFIED" || detail.VerifiedAt == "" ||
		len(detail.LinkedAgents) != 1 || detail.LinkedAgents[0].AgentID != agentID {
		t.Fatalf("detail shape: %+v", detail)
	}

	// Agent detail carries the computed identities[] (the RA-side
	// §5.4 join through WithIdentityViews).
	rec = f.do(t, owner, http.MethodGet, "/v2/ans/agents/"+agentID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent detail: %d", rec.Code)
	}
	var agentDetail struct {
		Identities []struct {
			IdentityID     string `json:"identityId"`
			IdentityStatus string `json:"identityStatus"`
			LinkedAt       string `json:"linkedAt"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &agentDetail); err != nil {
		t.Fatal(err)
	}
	if len(agentDetail.Identities) != 1 || agentDetail.Identities[0].IdentityID != identityID ||
		agentDetail.Identities[0].IdentityStatus != "VERIFIED" || agentDetail.Identities[0].LinkedAt == "" {
		t.Fatalf("agent identities[]: %+v", agentDetail)
	}

	// Rotate → 202 with fresh challenges over the staged value.
	rec = f.do(t, owner, http.MethodPut, "/v2/ans/identities/"+identityID,
		map[string]string{"value": "did:web:identity.acme-corp.com"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}

	// Unlink → 204.
	rec = f.do(t, owner, http.MethodDelete, "/v2/ans/identities/"+identityID+"/links/"+agentID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unlink: %d %s", rec.Code, rec.Body)
	}
	// Unlinking again → 404.
	rec = f.do(t, owner, http.MethodDelete, "/v2/ans/identities/"+identityID+"/links/"+agentID, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("double unlink: %d", rec.Code)
	}

	// Revoke → 200, REVOKED echoed.
	rec = f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+identityID+"/revoke", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil || detail.Status != "REVOKED" {
		t.Fatalf("revoke response: %s (%v)", rec.Body, err)
	}

	// Cross-owner: read hides (404), write rejects (403).
	other := f.registerAndVerify(t, "owner-2", "did:web:other.example.com")
	if rec := f.do(t, owner, http.MethodGet, "/v2/ans/identities/"+other, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-owner detail: %d", rec.Code)
	}
	if rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+other+"/revoke", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-owner revoke: %d", rec.Code)
	}
}

// registerAgentForIdentity registers an agent over HTTP for link
// tests, reusing the package CSR helpers.
func registerAgentForIdentity(t *testing.T, f *identityHTTPFixture, owner, host string) string {
	t.Helper()
	body := map[string]any{
		"agentDisplayName": "Test",
		"version":          "1.0.0",
		"agentHost":        host,
		"endpoints": []map[string]any{{
			"agentUrl":   "https://" + host + "/mcp",
			"protocol":   "MCP",
			"transports": []string{"SSE"},
		}},
		"identityCsrPEM": newTestCSR(t, "ans://v1.0.0."+host),
		"serverCsrPEM":   newTestServerCSR(t, host),
	}
	rec := f.do(t, owner, http.MethodPost, "/v2/ans/agents", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("agent register: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		AgentID string `json:"agentId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.AgentID == "" {
		t.Fatalf("agent register response: %s (%v)", rec.Body, err)
	}
	return resp.AgentID
}
