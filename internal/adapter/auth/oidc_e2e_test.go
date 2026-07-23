package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/agentnameservice/ans/internal/adapter/auth"
)

// oidcMock spins up an httptest server that serves the two OIDC
// endpoints `NewOIDCProvider` discovers at startup:
//   - /.well-known/openid-configuration
//   - /jwks
//
// The server signs JWTs with a fresh ECDSA P-256 key per test so we
// can drive Authenticate / Middleware end-to-end without a real
// identity provider. The pattern mirrors what go-oidc's own internal
// tests do.
type oidcMock struct {
	srv      *httptest.Server
	signKey  *ecdsa.PrivateKey
	keyID    string
	issuer   string
	audience string
}

func newOIDCMock(t *testing.T) *oidcMock {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &oidcMock{
		signKey:  priv,
		keyID:    "test-key-1",
		audience: "ans-test",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                m.issuer,
			"jwks_uri":                              m.issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       priv.Public(),
			KeyID:     m.keyID,
			Algorithm: "ES256",
			Use:       "sig",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	m.srv = httptest.NewServer(mux)
	m.issuer = m.srv.URL
	t.Cleanup(m.srv.Close)
	return m
}

// signToken mints a JWT carrying the given claims, signed by the
// mock's ECDSA key. Returns the compact-form token a client would
// supply in `Authorization: Bearer ...`.
func (m *oidcMock) signToken(t *testing.T, extra map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: m.signKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.Claims{
		Issuer:   m.issuer,
		Subject:  "alice",
		Audience: jwt.Audience{m.audience},
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(now),
	}
	tok, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestOIDC_Authenticate_HappyPath verifies a signed token round-trips
// through the discovery → JWKS → verify → claim-mapping flow and
// returns the populated Identity.
func TestOIDC_Authenticate_HappyPath(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "")
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	tok := m.signToken(t, map[string]any{
		"scope":  "ans.agent-registration:write ans.agent:read",
		"groups": []string{"ans-admin"},
	})
	req := httptest.NewRequest(http.MethodGet, "/v2/ans/agents", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	id, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Subject != "alice" {
		t.Errorf("subject: got %q want %q", id.Subject, "alice")
	}
	if len(id.Scopes) != 2 || id.Scopes[0] != "ans.agent-registration:write" {
		t.Errorf("scopes: got %v", id.Scopes)
	}
	if id.IsAdmin {
		t.Error("IsAdmin should be false without WithAdminGroups")
	}
}

// TestOIDC_Authenticate_AdminGroupSetsFlag confirms WithAdminGroups
// flips IsAdmin when the token's groups claim overlaps.
func TestOIDC_Authenticate_AdminGroupSetsFlag(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "",
		auth.WithAdminGroups("ans-admin"))
	if err != nil {
		t.Fatal(err)
	}
	tok := m.signToken(t, map[string]any{"groups": []string{"ans-admin"}})
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	id, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !id.IsAdmin {
		t.Error("IsAdmin should be true when token's groups include an admin group")
	}
}

// TestOIDC_Authenticate_AudienceMismatch rejects a token whose `aud`
// doesn't match the provider's expected audience. This is what keeps
// a token issued for service-A from being replayed against service-B.
func TestOIDC_Authenticate_AudienceMismatch(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "")
	if err != nil {
		t.Fatal(err)
	}
	// Sign a token for a different audience.
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: m.signKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	now := time.Now()
	tok, _ := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   m.issuer,
		Subject:  "bob",
		Audience: jwt.Audience{"some-other-service"},
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(now),
	}).Serialize()

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(context.Background(), req); err == nil {
		t.Error("expected audience-mismatch error")
	}
}

// TestOIDC_Authenticate_NoBearer surfaces missing/malformed
// Authorization headers as the same auth error the static provider
// uses.
func TestOIDC_Authenticate_NoBearer(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if _, err := p.Authenticate(context.Background(), req); err == nil {
		t.Error("expected error on missing Authorization header")
	}
}

// TestOIDC_Middleware_AnonymousPathBypass exercises the
// `WithOIDCAnonymousPath` option — the request hits the wrapped
// handler without the verifier ever running.
func TestOIDC_Middleware_AnonymousPathBypass(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "",
		auth.WithOIDCAnonymousPath("/v2/admin/health"))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/health", nil) // no Authorization
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200 on anonymous path", rec.Code)
	}
	if !called {
		t.Error("wrapped handler should have been called")
	}
}

// TestOIDC_Middleware_AuthFailureWritesAuthError covers the
// auth-error branch of the middleware: a missing Bearer token results
// in a 401 (mapped via writeAuthError) and the wrapped handler is
// never invoked.
func TestOIDC_Middleware_AuthFailureWritesAuthError(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := p.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/v2/ans/agents", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
	if called {
		t.Error("wrapped handler should NOT run when auth fails")
	}
}

// TestOIDC_Middleware_HappyPath drives the full middleware chain with
// a valid token: the verifier runs, the Identity is attached to the
// request context, the handler sees it.
func TestOIDC_Middleware_HappyPath(t *testing.T) {
	t.Parallel()
	m := newOIDCMock(t)
	p, err := auth.NewOIDCProvider(context.Background(), m.issuer, m.audience, "")
	if err != nil {
		t.Fatal(err)
	}
	tok := m.signToken(t, nil)

	var sawSubject string
	h := p.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if id, ok := auth.IdentityFromContext(r.Context()); ok {
			sawSubject = id.Subject
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/v2/ans/agents", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if sawSubject != "alice" {
		t.Errorf("identity not propagated to handler: got %q want alice", sawSubject)
	}
}
