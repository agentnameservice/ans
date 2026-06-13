package challenge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testVerifier returns a verifier pointed at the given httptest
// server, exercising the WithURLBuilder + WithHTTPClient options the
// way production tests must (the default URL builder targets the real
// FQDN on port 80, which a unit test can't bind).
func testVerifier(srv *httptest.Server) *HTTPVerifier {
	return NewHTTPVerifier(
		WithHTTPClient(&http.Client{Timeout: 2 * time.Second}),
		WithURLBuilder(func(_, path string) string { return srv.URL + path }),
	)
}

func TestVerifyHTTPChallenge_Match(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/acme-challenge/tok" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("tok.keyauth"))
	}))
	t.Cleanup(srv.Close)

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/.well-known/acme-challenge/tok", "tok.keyauth")
	if err != nil || !ok {
		t.Fatalf("want match, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_TrailingNewlineTolerated(t *testing.T) {
	// RFC 8555 §8.3 lets validators accept a trailing newline — shells
	// and editors love appending one to challenge files.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tok.keyauth\r\n"))
	}))
	t.Cleanup(srv.Close)

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/p", "tok.keyauth")
	if err != nil || !ok {
		t.Fatalf("want match with trailing newline, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_Mismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("something-else"))
	}))
	t.Cleanup(srv.Close)

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/p", "tok.keyauth")
	if err != nil || ok {
		t.Fatalf("want mismatch, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("404 must report not-published, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_UnreachableHost(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // immediately dead — connection refused

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("unreachable host must report not-published, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_InputValidation(t *testing.T) {
	v := NewHTTPVerifier()
	for _, tc := range []struct{ fqdn, path, expected string }{
		{"", "/p", "tok"},
		{"agent.example.com", "", "tok"},
		{"agent.example.com", "/p", ""},
	} {
		if _, err := v.VerifyHTTPChallenge(context.Background(), tc.fqdn, tc.path, tc.expected); err == nil {
			t.Errorf("want error for %+v", tc)
		}
	}
}

func TestVerifyHTTPChallenge_BadURL(t *testing.T) {
	v := NewHTTPVerifier(WithURLBuilder(func(_, _ string) string { return "http://[::1]:namedport/x" }))
	if _, err := v.VerifyHTTPChallenge(context.Background(), "a", "/p", "tok"); err == nil {
		t.Error("want request-build error for malformed URL")
	}
}

func TestVerifyHTTPChallenge_DefaultURLBuilder(t *testing.T) {
	// The default builder targets plain HTTP on the FQDN itself per
	// RFC 8555 §8.3. Point it at a guaranteed-closed local port via
	// the fqdn argument: connection refused == not published.
	v := NewHTTPVerifier(WithHTTPClient(&http.Client{Timeout: 500 * time.Millisecond}))
	ok, err := v.VerifyHTTPChallenge(context.Background(), "127.0.0.1:1", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("want not-published from default builder, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_TruncatedBody(t *testing.T) {
	// A response that dies mid-body (Content-Length promises more
	// than arrives) surfaces as a read error → not published.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, herr := hj.Hijack()
			if herr == nil {
				_ = conn.Close()
			}
		}
	}))
	t.Cleanup(srv.Close)

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("truncated body must report not-published, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyHTTPChallenge_OversizeBodyMismatch(t *testing.T) {
	// Bodies past the read cap cannot match a ~130-byte key
	// authorization; the limited read keeps memory bounded and the
	// comparison fails.
	big := make([]byte, maxChallengeBodyBytes*2)
	for i := range big {
		big[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(big)
	}))
	t.Cleanup(srv.Close)

	ok, err := testVerifier(srv).VerifyHTTPChallenge(context.Background(),
		"agent.example.com", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("oversize body must mismatch, got ok=%v err=%v", ok, err)
	}
}

// --- SSRF guard ---

// TestSSRFGuard_BlocksNonPublicDialTargets verifies the DEFAULT
// (production) verifier refuses to connect to non-public addresses.
// The httptest server binds 127.0.0.1, and we point the default URL
// builder at it via the host:port — the dialer Control hook must
// reject the loopback dial, so the fetch fails closed (not-published)
// rather than reaching an internal service.
func TestSSRFGuard_BlocksNonPublicDialTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tok")) // would "match" if the guard let us connect
	}))
	t.Cleanup(srv.Close)
	hostPort := strings.TrimPrefix(srv.URL, "http://")

	// Default verifier (guarded transport), but route the FQDN to the
	// loopback test server. A registrant pointing their FQDN at an
	// internal/loopback IP is exactly the SSRF case being closed.
	v := NewHTTPVerifier(WithURLBuilder(func(_, path string) string {
		return "http://" + hostPort + path
	}))
	ok, err := v.VerifyHTTPChallenge(context.Background(), "agent.example.com", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("loopback dial must be blocked (fail closed), got ok=%v err=%v", ok, err)
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,  // public
		"1.1.1.1":         true,  // public
		"2606:4700::1111": true,  // public v6
		"127.0.0.1":       false, // loopback
		"::1":             false, // loopback v6
		"169.254.169.254": false, // link-local (cloud metadata)
		"10.0.0.1":        false, // RFC 1918
		"192.168.1.1":     false, // RFC 1918
		"172.16.0.1":      false, // RFC 1918
		"fd00::1":         false, // unique-local
		"0.0.0.0":         false, // unspecified
		"224.0.0.1":       false, // multicast
		// Ranges Go's stdlib predicates miss (blockedCIDRs):
		"100.64.0.1":      false, // RFC 6598 CGNAT (cloud-internal)
		"100.127.255.255": false, // RFC 6598 CGNAT upper edge
		"192.0.0.1":       false, // RFC 6890 IETF protocol assignments
		"198.18.0.1":      false, // RFC 2544 benchmarking
		// 6to4 / NAT64 embedding internal IPv4 must fail closed:
		"2002:7f00:0001::": false, // 6to4 wrapping 127.0.0.1
		"2002:0a00:0001::": false, // 6to4 wrapping 10.0.0.1
		"2002:0808:0808::": false, // 6to4 even wrapping public 8.8.8.8 (whole prefix blocked)
		"64:ff9b::7f00:1":  false, // NAT64 wrapping 127.0.0.1
		"64:ff9b::a00:1":   false, // NAT64 wrapping 10.0.0.1
		// IPv4-mapped IPv6 normalizes to its inner v4 (must still reject
		// loopback/private):
		"::ffff:127.0.0.1": false, // mapped loopback
		"::ffff:10.0.0.1":  false, // mapped RFC 1918
	}
	for s, want := range cases {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if got := isPublicIP(ip); got != want {
			t.Errorf("isPublicIP(%s): got %v want %v", s, got, want)
		}
	}
}

// TestSSRFGuard_RefusesRedirects confirms the verifier does not follow
// a redirect (which could pivot a public host to an internal one).
func TestSSRFGuard_RefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Emit a 302 directly (not http.Redirect, which derefs the
		// request for relative-path resolution) so the client's
		// CheckRedirect hook is what stops the chain.
		w.Header().Set("Location", "http://example.com/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	// Use a guarded client's redirect policy but a permissive dialer so
	// the FIRST hop (to the test server) connects; the redirect itself
	// must be refused.
	v := NewHTTPVerifier(
		WithHTTPClient(&http.Client{CheckRedirect: refuseRedirects, Timeout: 2 * time.Second}),
		WithURLBuilder(func(_, path string) string { return srv.URL + path }),
	)
	ok, err := v.VerifyHTTPChallenge(context.Background(), "agent.example.com", "/p", "tok")
	if err != nil || ok {
		t.Fatalf("redirect must not be followed (fail closed), got ok=%v err=%v", ok, err)
	}
}
