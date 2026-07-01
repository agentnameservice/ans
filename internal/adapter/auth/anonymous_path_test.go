package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestStaticProvider_AnonymousPathMatching pins the exact-vs-subtree
// semantics that gate the events feed's auth exemption. The bug this
// guards: a subtree exemption on /v1/agents/events also skips auth for
// /v1/agents/events/revoke, which chi backtracks onto the authenticated
// /v1/agents/{agentId}/revoke route.
func TestStaticProvider_AnonymousPathMatching(t *testing.T) {
	t.Parallel()
	p := NewStaticProvider("k",
		WithAnonymousPath("/docs"),                  // subtree, no trailing slash
		WithAnonymousPath("/v1/agents/"),            // subtree, TRAILING SLASH (TL form)
		WithAnonymousPath("/tile/"),                 // subtree, TRAILING SLASH (TL form)
		WithAnonymousExactPath("/v1/agents/events"), // exact leaf
	)

	cases := []struct {
		path          string
		wantAnonymous bool
		why           string
	}{
		{"/v1/agents/events", true, "exact match is anonymous"},
		{"/docs", true, "subtree root is anonymous"},
		{"/docs/openapi.yaml", true, "subtree descendant is anonymous"},
		{"/docsfoo", false, "same-prefix sibling of a subtree is NOT anonymous"},
		// Trailing-slash-registered prefixes must behave identically to
		// the non-slash form — this is the regression the matcher missed.
		{"/v1/agents/", true, "trailing-slash prefix matches the registered path itself"},
		{"/v1/agents", true, "trailing-slash prefix matches its un-slashed root"},
		{"/v1/agents/abc/receipt", true, "trailing-slash prefix matches a deep descendant"},
		{"/v1/agentsfoo", false, "trailing-slash prefix does NOT match a same-prefix sibling"},
		{"/tile/", true, "trailing-slash /tile/ matches itself"},
		{"/tile/0/000", true, "trailing-slash /tile/ matches a descendant"},
		{"/tilefoo", false, "trailing-slash /tile/ does NOT match /tilefoo"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := p.isAnonymousPath(tc.path); got != tc.wantAnonymous {
				t.Errorf("isAnonymousPath(%q) = %v, want %v — %s",
					tc.path, got, tc.wantAnonymous, tc.why)
			}
		})
	}
}

// TestOIDCProvider_AnonymousPathMatching mirrors the static-provider
// test: both adapters must apply identical matching so a route's
// anonymity does not depend on which auth backend is wired.
func TestOIDCProvider_AnonymousPathMatching(t *testing.T) {
	t.Parallel()
	// Apply the option funcs (rather than setting fields directly) so
	// WithOIDCAnonymousExactPath is exercised.
	p := &OIDCProvider{}
	WithOIDCAnonymousPath("/docs")(p)
	WithOIDCAnonymousPath("/v1/agents/")(p) // trailing-slash (TL form)
	WithOIDCAnonymousPath("/tile/")(p)      // trailing-slash (TL form)
	WithOIDCAnonymousExactPath("/v2/events")(p)
	cases := []struct {
		path          string
		wantAnonymous bool
	}{
		{"/v2/events", true},
		{"/v2/eventsfoo", false},
		{"/docs", true},
		{"/docs/openapi.yaml", true},
		{"/docsfoo", false},
		{"/v1/agents/", true},
		{"/v1/agents", true},
		{"/v1/agents/abc/receipt", true},
		{"/v1/agentsfoo", false},
		{"/tile/0/000", true},
		{"/tilefoo", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := p.isAnonymousPath(tc.path); got != tc.wantAnonymous {
				t.Errorf("isAnonymousPath(%q) = %v, want %v", tc.path, got, tc.wantAnonymous)
			}
		})
	}
}

// TestEventsExemption_DoesNotBypassAuthOnWildcardSibling is the
// end-to-end regression for BLOCKER H1: wire the static provider's
// middleware in front of a chi router shaped like the real RA, and
// assert that an unauthenticated POST to /v1/agents/events/revoke is
// rejected with 401 by the auth layer — NOT silently allowed through
// (which would then rely on ownership middleware to fail closed) and
// NOT a 403 from ownership.
func TestEventsExemption_DoesNotBypassAuthOnWildcardSibling(t *testing.T) {
	t.Parallel()
	p := NewStaticProvider("secret-key",
		WithAnonymousExactPath("/v1/agents/events"),
	)

	r := chi.NewRouter()
	r.Use(p.Middleware())
	r.Get("/v1/agents/events", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("feed"))
	})
	// Authenticated wildcard sibling — must require credentials. The
	// handler asserts it is never reached without auth.
	r.Post("/v1/agents/{agentId}/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name       string
		method     string
		path       string
		withAuth   bool
		wantStatus int
	}{
		{"feed anonymous ok", http.MethodGet, "/v1/agents/events", false, http.StatusOK},
		{"backtracked revoke without creds is 401", http.MethodPost, "/v1/agents/events/revoke", false, http.StatusUnauthorized},
		{"sibling without creds is 401", http.MethodPost, "/v1/agents/123/revoke", false, http.StatusUnauthorized},
		{"same-prefix sibling without creds is 401", http.MethodGet, "/v1/agents/eventsfoo", false, http.StatusUnauthorized},
		{"revoke with creds passes auth", http.MethodPost, "/v1/agents/events/revoke", true, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.withAuth {
				req.Header.Set("Authorization", "Bearer secret-key")
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("%s %s (auth=%v): status %d, want %d",
					tc.method, tc.path, tc.withAuth, rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestTrailingSlashSubtree_StaticAllowsAnonymousDescendant is the
// full-stack regression for the TL trailing-slash 401: a provider with
// the TL's `WithAnonymousPath("/v1/agents/")` in front of a
// receipt-style GET route must let an UNCREDENTIALED request through
// (200), the way ans-verify reads receipts. Before the TrimRight fix
// the middleware 401ed it (HasPrefix vs "/v1/agents//").
func TestTrailingSlashSubtree_StaticAllowsAnonymousDescendant(t *testing.T) {
	t.Parallel()
	p := NewStaticProvider("secret-key", WithAnonymousPath("/v1/agents/"))

	r := chi.NewRouter()
	r.Use(p.Middleware())
	r.Get("/v1/agents/{id}/receipt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receipt"))
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/agents/abc/receipt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous receipt read under trailing-slash exemption: status %d, want 200", rec.Code)
	}
}

// TestTrailingSlashSubtree_OIDCAllowsAnonymousDescendant is the OIDC
// twin: the same trailing-slash exemption must short-circuit auth before
// token verification, so an uncredentialed receipt read is 200 even
// though the provider has no verifier wired (it never reaches it).
func TestTrailingSlashSubtree_OIDCAllowsAnonymousDescendant(t *testing.T) {
	t.Parallel()
	p := &OIDCProvider{}
	WithOIDCAnonymousPath("/v1/agents/")(p)

	r := chi.NewRouter()
	r.Use(p.Middleware())
	r.Get("/v1/agents/{id}/receipt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("receipt"))
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/agents/abc/receipt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous receipt read under trailing-slash exemption (OIDC): status %d, want 200", rec.Code)
	}
}
