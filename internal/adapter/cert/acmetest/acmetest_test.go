package acmetest

import (
	"net/http"
	"strings"
	"testing"
)

// The fake's own contract: protocol violations it observes are
// surfaced via Err so adapter tests fail loudly instead of silently
// passing against a broken conversation.
func TestServer_RecordsProtocolViolations(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	if s.Err() != nil {
		t.Fatal("fresh server must have no errors")
	}

	// Unexpected path → 404 + recorded violation.
	resp, err := http.Get(s.url("/nope"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status: %d", resp.StatusCode)
	}
	if s.Err() == nil || !strings.Contains(s.Err().Error(), "unexpected path") {
		t.Errorf("violation not recorded: %v", s.Err())
	}
}

func TestServer_RejectsMalformedJWS(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	// Not JSON at all.
	resp, err := http.Post(s.url("/order"), "application/jose+json", strings.NewReader("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if s.Err() == nil {
		t.Error("malformed JWS must be recorded")
	}

	// Valid JSON, payload not base64url.
	s2, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s2.Close)
	resp2, err := http.Post(s2.url("/order"), "application/jose+json",
		strings.NewReader(`{"protected":"x","payload":"!!!not-b64!!!","signature":"y"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if s2.Err() == nil {
		t.Error("bad payload encoding must be recorded")
	}
}
