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
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/didresolver"
	"github.com/godaddy/ans/internal/adapter/eventbus"
	"github.com/godaddy/ans/internal/adapter/leiverifier"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/handler"
	ramiddleware "github.com/godaddy/ans/internal/ra/middleware"
	"github.com/godaddy/ans/internal/ra/service"
)

// identityHTTPFixture wires the identity routes (plus the agent
// register + detail routes the link tests need) over real SQLite and
// the noop resolver. No signer — the seal goes through an always-ok
// stub sealer with an unsigned payload; the signed seal path is
// pinned by the service tests.
type identityHTTPFixture struct {
	router chi.Router
	agents *sqlite.AgentStore
}

// okSealer acknowledges every seal — the HTTP tests pin the wire
// contract, not the seal discipline (service tests own that).
type okSealer struct{}

func (okSealer) SealIdentityEvent(context.Context, []byte, string) error { return nil }

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
	).WithServerCertificateIssuer(serverCA)

	idSvc := service.NewIdentityService(
		sqlite.NewIdentityStore(db),
		sqlite.NewIdentityLinkStore(db),
		agents,
		didresolver.NewNoopResolver(),
		okSealer{},
		leiverifier.NewNoop(),
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

	return &identityHTTPFixture{router: r, agents: agents}
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

// assertSingletonVerifiedList pins GET /v2/ans/identities returning a
// single VERIFIED identity in the AgentListResponse-shaped envelope —
// `items` array plus returnedCount/limit/hasMore (review #6). Lives
// here so its branches stay out of the big lifecycle test's
// cyclomatic budget.
func assertSingletonVerifiedList(t *testing.T, f *identityHTTPFixture, owner string) {
	t.Helper()
	rec := f.do(t, owner, http.MethodGet, "/v2/ans/identities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var list struct {
		Items []struct {
			IdentityID string `json:"identityId"`
			Status     string `json:"status"`
		} `json:"items"`
		ReturnedCount int  `json:"returnedCount"`
		Limit         int  `json:"limit"`
		HasMore       bool `json:"hasMore"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Status != "VERIFIED" {
		t.Fatalf("list shape: %+v", list)
	}
	if list.ReturnedCount != 1 || list.Limit != 20 || list.HasMore {
		t.Fatalf("list envelope (items/returnedCount/limit/hasMore): %+v", list)
	}
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

// TestIdentityHandler_BodyCap pins the 1 MiB MaxBytesReader on the
// three JSON-decoding identity routes: an over-cap body fails the
// decode → 422, never reaching the parser (DoS guard).
func TestIdentityHandler_BodyCap(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)

	// Valid JSON envelope padded past 1 MiB inside the cesr field.
	oversized := `{"value":"did:web:a.com","vleiPresentation":{"cesr":"` +
		strings.Repeat("A", 1<<20) + `"}}`
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v2/ans/identities"},
		{http.MethodPut, "/v2/ans/identities/x"},
		{http.MethodPost, "/v2/ans/identities/x/verify-control"},
	} {
		if rec := f.doRaw(t, "owner-1", route.method, route.path, oversized); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("oversized body %s %s: %d", route.method, route.path, rec.Code)
		}
	}
}

// TestIdentityHandler_LEIRoundTrip drives the lei lane end-to-end over
// HTTP against the noop verifier and the real SQLite store: register
// with vleiPresentation.cesr → 202 carrying the advisory
// presentationStatus and the subject-AID challenge, then verify-control
// with cesrSignature → 200, and detail reflects the sealed VERIFIED
// state. This exercises the request DTO (vleiPresentation,
// cesrSignature) and response DTO (presentationStatus) wiring plus the
// subject_aid store round-trip the service-only tests cannot reach.
func TestIdentityHandler_LEIRoundTrip(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)
	owner := "owner-lei"

	// The noop verifier reads the leaf credential's subject AID (a.i)
	// and LEI (a.LEI) straight from the full-chain CESR export.
	const lei = "5493001KJTIIGC8Y1R17"
	const cesr = `{"v":"ACDC10JSON00011c_","d":"ECredSAID123","a":{"i":"EHolderAID123","LEI":"5493001KJTIIGC8Y1R17"}}`

	rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities",
		map[string]any{"value": lei, "vleiPresentation": map[string]string{"cesr": cesr}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var ch struct {
		IdentityID         string `json:"identityId"`
		Kind               string `json:"kind"`
		Status             string `json:"status"`
		PresentationStatus string `json:"presentationStatus"`
		Challenges         []struct {
			Kid          string `json:"kid"`
			SigningInput string `json:"signingInput"`
		} `json:"challenges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Kind != "lei" || ch.Status != "PENDING_CONTROL" || ch.PresentationStatus != "AUTHORIZED" {
		t.Fatalf("202 lei shape: %+v", ch)
	}
	if len(ch.Challenges) != 1 || ch.Challenges[0].Kid != "EHolderAID123" || ch.Challenges[0].SigningInput == "" {
		t.Fatalf("challenge over the pinned subject AID: %+v", ch.Challenges)
	}

	// verify-control with a well-formed qb64 CESR signature → 200.
	rec = f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+ch.IdentityID+"/verify-control",
		map[string]any{"cesrSignature": "0BwellFormedQb64Signature"})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-control: %d %s", rec.Code, rec.Body)
	}

	// Detail confirms the lei seal landed and the store round-tripped the
	// VERIFIED state with the lei proof method.
	rec = f.do(t, owner, http.MethodGet, "/v2/ans/identities/"+ch.IdentityID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body)
	}
	var detail struct {
		Status      string `json:"status"`
		Kind        string `json:"kind"`
		Value       string `json:"value"`
		ProofMethod string `json:"proofMethod"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Status != "VERIFIED" || detail.Kind != "lei" || detail.Value != lei || detail.ProofMethod != "lei-vlei-acdc" {
		t.Fatalf("verified detail: %+v", detail)
	}
}

func TestIdentityHandler_FullLifecycleOverHTTP(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)
	owner := "owner-1"

	identityID := f.registerAndVerify(t, owner, "did:web:identity.acme-corp.com")

	// List — the AgentListResponse-shaped envelope (items + counts).
	assertSingletonVerifiedList(t, f, owner)

	// Register the agent to link.
	agentID := registerAgentForIdentity(t, f, owner, "linked.example.com")

	// Link → 200 {linked:1}.
	rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+identityID+"/links",
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

	// Drive the agent to ACTIVE directly through the store — the link
	// liveness gate (§4.3) rejects pre-activation agents, and these
	// tests pin the identity wire contract, not the ACME lifecycle.
	reg, err := f.agents.FindByAgentID(context.Background(), resp.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	reg.Status = domain.StatusActive
	if err := f.agents.Save(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return resp.AgentID
}

// TestIdentityHandler_ListPagination pins the v2 limit + opaque-
// cursor envelope on GET /v2/ans/identities.
func TestIdentityHandler_ListPagination(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)
	owner := "owner-pages"
	f.registerAndVerify(t, owner, "did:web:page-a.example.com")
	f.registerAndVerify(t, owner, "did:web:page-b.example.com")
	f.registerAndVerify(t, owner, "did:web:page-c.example.com")

	// Invalid limit → 422 INVALID_LIMIT.
	rec := f.do(t, owner, http.MethodGet, "/v2/ans/identities?limit=0", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("limit=0: %d %s", rec.Code, rec.Body)
	}

	type page struct {
		Items []struct {
			IdentityID string `json:"identityId"`
		} `json:"items"`
		NextCursor *string `json:"nextCursor"`
	}
	var p1 page
	rec = f.do(t, owner, http.MethodGet, "/v2/ans/identities?limit=2", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page 1: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if len(p1.Items) != 2 || p1.NextCursor == nil {
		t.Fatalf("page 1 shape: %+v", p1)
	}

	var p2 page
	rec = f.do(t, owner, http.MethodGet, "/v2/ans/identities?limit=2&cursor="+*p1.NextCursor, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p2); err != nil {
		t.Fatal(err)
	}
	if len(p2.Items) != 1 || p2.NextCursor != nil {
		t.Fatalf("page 2 shape: %+v", p2)
	}
	// No overlap between pages.
	seen := map[string]bool{}
	for _, e := range append(p1.Items, p2.Items...) {
		if seen[e.IdentityID] {
			t.Fatalf("duplicate across pages: %s", e.IdentityID)
		}
		seen[e.IdentityID] = true
	}
}

// TestIdentityHandler_ServiceErrorsPropagate exercises the
// service-error pass-through arms across the mutating identity
// handlers: a well-formed request against an identity the caller
// does not own / that does not exist surfaces the service's domain
// error (404/403), not a 200. Complements the malformed-body and
// auth tests, which never reach the service call.
func TestIdentityHandler_ServiceErrorsPropagate(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)
	owner := "owner-svc-err"
	missing := "01HXMISSINGIDENTITY0000000"

	// Valid bodies, unknown identity → not-found from the owner gate.
	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/v2/ans/identities/" + missing, nil},
		{http.MethodPut, "/v2/ans/identities/" + missing, map[string]string{"value": "did:web:x.example.com"}},
		{http.MethodPost, "/v2/ans/identities/" + missing + "/verify-control", map[string]any{"signedProofs": []string{"a.b.c"}}},
		{http.MethodPost, "/v2/ans/identities/" + missing + "/revoke", nil},
		{http.MethodPost, "/v2/ans/identities/" + missing + "/links", map[string]any{"agentIds": []string{"some-agent"}}},
		{http.MethodDelete, "/v2/ans/identities/" + missing + "/links/some-agent", nil},
	}
	for _, tc := range cases {
		rec := f.do(t, owner, tc.method, tc.path, tc.body)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s: got %d, want 404/403 (service error must propagate)", tc.method, tc.path, rec.Code)
		}
	}
}

// TestIdentityHandler_EmptyCollectionsRejected pins the
// missing-required-field validation arms that a syntactically valid
// but empty body reaches: verify-control with no proofs and links
// with no agentIds are 4xx, not 200.
func TestIdentityHandler_EmptyCollectionsRejected(t *testing.T) {
	t.Parallel()
	f := newIdentityHTTPFixture(t)
	owner := "owner-empty"
	id := f.registerAndVerify(t, owner, "did:web:empty-coll.example.com")
	agentID := registerAgentForIdentity(t, f, owner, "empty-coll-agent.example.com")

	// Empty signedProofs on a verified identity → rejected (no proof
	// to verify), not a 200.
	if rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+id+"/verify-control",
		map[string]any{"signedProofs": []string{}}); rec.Code < 400 {
		t.Fatalf("empty signedProofs: got %d, want 4xx", rec.Code)
	}
	// Empty agentIds on a link call → INVALID_LINK_REQUEST.
	if rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+id+"/links",
		map[string]any{"agentIds": []string{}}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty agentIds: got %d, want 422", rec.Code)
	}
	// A valid single-agent link still works (sanity — the fixture's
	// okSealer acknowledges).
	if rec := f.do(t, owner, http.MethodPost, "/v2/ans/identities/"+id+"/links",
		map[string]any{"agentIds": []string{agentID}}); rec.Code != http.StatusOK {
		t.Fatalf("valid link after empty-batch reject: %d %s", rec.Code, rec.Body)
	}
}
