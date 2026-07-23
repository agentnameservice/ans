package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentnameservice/ans/internal/adapter/auth"
)

// StaticProvider must accept both:
//   - `Authorization: Bearer <apiKey>` — ans-native Bearer format
//   - `Authorization: sso-key <apiKey>:<apiSecret>` — reference SDK
//     format (matches the reference RA's auth helper)
//
// plus the edge cases the reference regex covers (bare `key:secret`
// without the sso-key prefix). These tests pin all of that so SDK
// compatibility doesn't regress.

// TestAuthenticate_BearerFormat is the ans-native path used by the
// demo scripts and by simple curl-based tooling.
func TestAuthenticate_BearerFormat(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer my-api-key")
	id, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id == nil || id.Subject != "static-user" {
		t.Fatalf("expected static-user identity, got %+v", id)
	}
}

// TestAuthenticate_SSOKeyFormat_Prefix is the canonical reference
// format: `Authorization: sso-key KEY:SECRET`. This is what the ANS
// SDKs send by default.
func TestAuthenticate_SSOKeyFormat_Prefix(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key my-api-key:my-secret")
	id, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id == nil {
		t.Fatal("expected identity")
	}
}

// TestAuthenticate_SSOKeyFormat_CaseInsensitive matches the reference
// regex's `re.IGNORECASE` flag. Clients that send SSO-KEY, Sso-Key,
// etc. all resolve to the same authenticator.
func TestAuthenticate_SSOKeyFormat_CaseInsensitive(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	for _, prefix := range []string{"sso-key ", "SSO-KEY ", "Sso-Key ", "sSo-KeY "} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", prefix+"my-api-key:my-secret")
		if _, err := p.Authenticate(context.Background(), req); err != nil {
			t.Errorf("prefix %q: Authenticate: %v", prefix, err)
		}
	}
}

// TestAuthenticate_SSOKeyFormat_NoPrefix — the reference regex makes
// the `sso-key ` prefix optional. A bare `key:secret` in the header
// is a valid SSO-key submission. Some SDK versions send the bare
// form; we must accept it.
func TestAuthenticate_SSOKeyFormat_NoPrefix(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "my-api-key:my-secret")
	if _, err := p.Authenticate(context.Background(), req); err != nil {
		t.Fatalf("bare key:secret must authenticate: %v", err)
	}
}

// TestAuthenticate_SSOKeyFormat_SecretWithColons covers the case
// where the secret itself contains colons. The reference regex
// splits on the FIRST colon only — the secret ([^:]+):(.+) pattern
// lets the secret contain anything. A mis-split here would produce
// a confusing 401.
func TestAuthenticate_SSOKeyFormat_SecretWithColons(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("a:b:c:d"))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key my-api-key:a:b:c:d")
	if _, err := p.Authenticate(context.Background(), req); err != nil {
		t.Fatalf("secret with colons must authenticate: %v", err)
	}
}

// TestAuthenticate_WrongSecret rejects a correct key with the wrong
// secret. We return ErrInvalidCredentials, not ErrMissingCredentials
// — the header was well-formed, just unauthorized.
func TestAuthenticate_WrongSecret(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key my-api-key:wrong")
	_, err := p.Authenticate(context.Background(), req)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// TestAuthenticate_WrongKey rejects a bad key/secret pair with
// ErrInvalidCredentials.
func TestAuthenticate_WrongKey(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key wrong-key:my-secret")
	_, err := p.Authenticate(context.Background(), req)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// TestAuthenticate_SSOKeyWithoutConfiguredSecret — when the server
// has no apiSecret configured, an sso-key submission falls through
// to the Bearer check and fails (since `apikey:secret` is not a
// valid Bearer token). The server should return a recognizable
// credentials error, not a silent pass.
//
// This also ensures we don't accidentally accept sso-key headers
// against an apiKey-only config (which would be a downgrade).
func TestAuthenticate_SSOKeyWithoutConfiguredSecret(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key") // no WithAPISecret
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key my-api-key:any-secret")
	if _, err := p.Authenticate(context.Background(), req); err == nil {
		t.Fatal("sso-key submission must NOT authenticate when no secret is configured")
	}
}

// TestAuthenticate_MissingHeader returns ErrMissingCredentials.
func TestAuthenticate_MissingHeader(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	_, err := p.Authenticate(context.Background(), req)
	if !errors.Is(err, auth.ErrMissingCredentials) {
		t.Fatalf("expected ErrMissingCredentials, got %v", err)
	}
}

// TestAuthenticate_MalformedHeader — unrecognized Authorization
// schemes fall through to ErrMissingCredentials (matches the V2
// behavior — a malformed header is indistinguishable from "no
// credentials supplied").
func TestAuthenticate_MalformedHeader(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	cases := []string{
		"NotBearer my-api-key",
		"Bearer", // prefix only, no token
		"Bearer ",
		":secret-only", // malformed sso-key (empty key)
		"key:",         // malformed sso-key (empty secret)
	}
	for _, h := range cases {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", h)
		if _, err := p.Authenticate(context.Background(), req); err == nil {
			t.Errorf("header %q must not authenticate", h)
		}
	}
}

// TestMiddleware_Integration confirms the middleware wires the
// accepted identity into the request context so handlers downstream
// can pull it out via IdentityFromContext.
func TestMiddleware_Integration(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key", auth.WithAPISecret("my-secret"))
	var sawSubject string
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.IdentityFromContext(r.Context())
		if ok && id != nil {
			sawSubject = id.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Good sso-key request → handler sees identity.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key my-api-key:my-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if sawSubject != "static-user" {
		t.Errorf("handler saw subject %q, want static-user", sawSubject)
	}

	// Bad sso-key → middleware returns 401 before the handler runs.
	sawSubject = ""
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "sso-key my-api-key:wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	if sawSubject != "" {
		t.Error("handler must not run on auth failure")
	}
}

// TestMiddleware_AnonymousPath bypasses auth for configured prefixes.
func TestMiddleware_AnonymousPath(t *testing.T) {
	t.Parallel()
	p := auth.NewStaticProvider("my-api-key",
		auth.WithAPISecret("my-secret"),
		auth.WithAnonymousPath("/v2/admin/health"),
	)
	var ran bool
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/health", nil)
	// No Authorization header — anonymous path should pass through.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous path status: got %d, want 200", rec.Code)
	}
	if !ran {
		t.Error("handler must run on anonymous path")
	}
}
