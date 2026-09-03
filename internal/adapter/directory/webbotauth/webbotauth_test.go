package webbotauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/port"
)

const testJWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

func TestNoopResolver_SynthesizesFromHints(t *testing.T) {
	n := NewNoopResolver()

	// No hints (advisory register-time fetch) → empty set.
	keys, err := n.Resolve(context.Background(), "https://signer.example.com/.well-known/http-message-signatures-directory", nil)
	if err != nil || len(keys) != 0 {
		t.Fatalf("no-hint resolve: %d keys, %v", len(keys), err)
	}

	hints := []port.KeyHint{
		{Kid: "kid-1", PublicKeyJWK: json.RawMessage(testJWK)},
		{Kid: "kid-2"}, // no key — skipped
	}
	keys, err = n.Resolve(context.Background(), "https://signer.example.com", hints)
	if err != nil {
		t.Fatalf("resolve with hints: %v", err)
	}
	if len(keys) != 1 || string(keys[0].JWK) != testJWK {
		t.Fatalf("synthesized keys wrong: %+v", keys)
	}
}

func TestParseDirectory(t *testing.T) {
	body := []byte(`{"keys":[
		{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","nbf":1000,"exp":2000},
		{"kty":"OKP","crv":"Ed25519","x":"AAA"}
	]}`)
	keys, err := parseDirectory(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if keys[0].NotBefore != time.Unix(1000, 0).UTC() || keys[0].NotAfter != time.Unix(2000, 0).UTC() {
		t.Fatalf("window not parsed: %+v", keys[0])
	}
	if !keys[1].NotBefore.IsZero() || !keys[1].NotAfter.IsZero() {
		t.Fatalf("second key should be unbounded: %+v", keys[1])
	}
	// Empty keys array → empty set, no error.
	empty, err := parseDirectory([]byte(`{"keys":[]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty directory: %d, %v", len(empty), err)
	}
	// Malformed JSON → retryable failure.
	if _, err := parseDirectory([]byte(`{not json`)); err == nil {
		t.Fatal("malformed JWKS should error")
	}
}

// newTLSDirectory starts a loopback TLS server serving the given handler
// and returns an HTTP resolver that trusts it and may reach loopback.
func newTLSDirectory(t *testing.T, h http.HandlerFunc) (*httptest.Server, *HTTP) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r := NewHTTPResolver(
		WithRootCAs(pool),
		WithAllowPrivateNetworks(),
		WithTimeout(2*time.Second),
	)
	return srv, r
}

func TestHTTPResolver_HappyPath(t *testing.T) {
	srv, r := newTLSDirectory(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", directoryContentType)
		_, _ = w.Write([]byte(`{"keys":[` + testJWK + `]}`))
	})
	defer srv.Close()

	keys, err := r.Resolve(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(keys) != 1 || string(keys[0].JWK) != testJWK {
		t.Fatalf("keys: %+v", keys)
	}
}

func TestHTTPResolver_ContentTypeParametersAccepted(t *testing.T) {
	srv, r := newTLSDirectory(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", directoryContentType+"; charset=utf-8")
		_, _ = w.Write([]byte(`{"keys":[` + testJWK + `]}`))
	})
	defer srv.Close()
	if _, err := r.Resolve(context.Background(), srv.URL, nil); err != nil {
		t.Fatalf("content-type with parameters should be accepted: %v", err)
	}
}

func TestHTTPResolver_Rejections(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"wrong content type": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		},
		"non-200": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"bad json": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", directoryContentType)
			_, _ = w.Write([]byte(`{not json`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv, r := newTLSDirectory(t, h)
			defer srv.Close()
			_, err := r.Resolve(context.Background(), srv.URL, nil)
			if err == nil || !strings.Contains(err.Error(), "WBA_DIRECTORY_UNAVAILABLE") {
				t.Fatalf("want WBA_DIRECTORY_UNAVAILABLE, got %v", err)
			}
		})
	}
}

func TestHTTPResolver_BodyTooLarge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", directoryContentType)
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	r := NewHTTPResolver(WithRootCAs(pool), WithAllowPrivateNetworks(), WithMaxBodyBytes(1024))
	if _, err := r.Resolve(context.Background(), srv.URL, nil); err == nil ||
		!strings.Contains(err.Error(), "WBA_DIRECTORY_UNAVAILABLE") {
		t.Fatalf("want size-cap failure, got %v", err)
	}
}

// TestHTTPResolver_FetchFailureCoarse drives the real Resolve path
// against an unresolvable host: the failure is retryable and the wire
// error never leaks an address (no SSRF oracle). V15.
func TestHTTPResolver_FetchFailureCoarse(t *testing.T) {
	r := NewHTTPResolver(WithTimeout(2 * time.Second))
	_, err := r.Resolve(context.Background(), "https://no-such-host-ans-test.invalid/.well-known/http-message-signatures-directory", nil)
	if err == nil || !strings.Contains(err.Error(), "WBA_DIRECTORY_UNAVAILABLE") {
		t.Fatalf("want WBA_DIRECTORY_UNAVAILABLE, got %v", err)
	}
}

func TestHTTPResolver_MalformedURL(t *testing.T) {
	r := NewHTTPResolver()
	if _, err := r.Resolve(context.Background(), "http://not-https.example.com", nil); err == nil {
		t.Fatal("non-https directory URL should fail")
	}
}

func TestHTTPResolver_RedirectPolicy(t *testing.T) {
	r := NewHTTPResolver()
	mkReq := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}

	// Registrable-domain-anchored host.
	client := r.newClient("signer.example.com")
	if err := client.CheckRedirect(mkReq("https://cdn.example.com/dir"), nil); err != nil {
		t.Errorf("same registrable domain rejected: %v", err)
	}
	if err := client.CheckRedirect(mkReq("https://evil.other.com/dir"), nil); err == nil {
		t.Error("cross-domain redirect should be rejected")
	}
	if err := client.CheckRedirect(mkReq("http://cdn.example.com/dir"), nil); err == nil {
		t.Error("scheme downgrade should be rejected")
	}
	via := make([]*http.Request, maxRedirects)
	if err := client.CheckRedirect(mkReq("https://cdn.example.com/dir"), via); err == nil ||
		!strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("redirect cap: %v", err)
	}

	// IP-literal origin (no registrable domain) → exact-host anchor.
	ipClient := r.newClient("127.0.0.1")
	if err := ipClient.CheckRedirect(mkReq("https://127.0.0.1/dir"), nil); err != nil {
		t.Errorf("same-host redirect rejected: %v", err)
	}
	if err := ipClient.CheckRedirect(mkReq("https://10.0.0.1/dir"), nil); err == nil {
		t.Error("different-host redirect should be rejected for IP origin")
	}
}
