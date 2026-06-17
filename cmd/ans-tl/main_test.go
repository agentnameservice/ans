package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/godaddy/ans/internal/config"
)

// TestBuildAuth_PublicReadAnonymousPaths pins the TL's anonymous-path
// wiring through the REAL provider construction (buildAuth), not a
// bare router. Regression guard for the verified-identity read
// surface: under the shipped public-read default, a third-party
// verifier must reach /v1/identities/* with no credential — the
// feature's offline-evidence hop — while producer ingest under
// /v1/internal/* still requires the bearer key. Handler tests mount a
// bare chi.Router with no auth, so only a test at this layer catches
// a missing WithAnonymousPath entry.
func TestBuildAuth_PublicReadAnonymousPaths(t *testing.T) {
	t.Parallel()
	cfg := &config.TLConfig{}
	cfg.Auth.Type = "static"
	cfg.Auth.PublicRead = true
	cfg.Auth.Static = &config.AuthStatic{APIKey: "test-key"}

	provider, err := buildAuth(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildAuth: %v", err)
	}
	// A handler that 200s — so an anonymous pass-through yields 200,
	// and only the middleware's own 401 distinguishes a gated path.
	h := provider.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		path    string
		anon    bool // true = reachable with no Authorization header
		comment string
	}{
		{"/v1/agents/01HX/badge", true, "agent badge — reference parity"},
		{"/v1/identities/01HX", true, "identity badge — the verifier's who-hop"},
		{"/v1/identities/01HX/audit", true, "identity audit"},
		{"/v1/identities/01HX/receipt", true, "identity receipt"},
		{"/v1/identities/01HX/agents", true, "reverse join"},
		{"/v1/log/checkpoint", true, "log read"},
		{"/checkpoint", true, "raw checkpoint"},
		{"/root-keys", true, "verification keys"},
		{"/tile/0/0", true, "tlog tiles"},
		{"/v1/internal/identities/event", false, "identity ingest — bearer required"},
		{"/v1/internal/agents/event", false, "agent ingest — bearer required"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil) // no Authorization header
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		anon := rec.Code != http.StatusUnauthorized
		if anon != tc.anon {
			t.Errorf("%s (%s): anonymous=%v (status %d), want anonymous=%v",
				tc.path, tc.comment, anon, rec.Code, tc.anon)
		}
	}
}
