package auth

import (
	"context"
	"testing"
)

// ----- NewOIDCProvider input validation -----
//
// The happy path requires a live OIDC discovery endpoint, so we scope
// these tests to the pure-function error paths and internal helpers.
// End-to-end token verification is exercised in integration tests
// (out of scope for unit coverage).

func TestNewOIDCProvider_RequiresIssuer(t *testing.T) {
	_, err := NewOIDCProvider(context.Background(), "", "aud", "")
	if err == nil {
		t.Error("expected error when issuer URL is empty")
	}
}

func TestNewOIDCProvider_RequiresAudience(t *testing.T) {
	_, err := NewOIDCProvider(context.Background(), "https://issuer.example.com", "", "")
	if err == nil {
		t.Error("expected error when audience is empty")
	}
}

func TestNewOIDCProvider_DiscoveryFailurePropagates(t *testing.T) {
	// Point at a non-routable address. Discovery attempts HTTP/HTTPS
	// lookups and fails — wrapped in the provider's error.
	_, err := NewOIDCProvider(context.Background(),
		"http://127.0.0.1:1", "aud", "client")
	if err == nil {
		t.Error("expected discovery failure on unreachable issuer")
	}
}

// ----- Option constructors -----

func TestOIDCOptions_Set(t *testing.T) {
	p := &OIDCProvider{}
	WithOIDCAnonymousPath("/public")(p)
	WithOIDCAnonymousPath("/health")(p)
	WithAdminGroups("ops", "sre")(p)
	if len(p.anonymousPaths) != 2 {
		t.Errorf("anonymousPaths: got %v", p.anonymousPaths)
	}
	if len(p.adminGroups) != 2 {
		t.Errorf("adminGroups: got %v", p.adminGroups)
	}
}

// ----- isAnonymousPath -----

func TestOIDC_IsAnonymousPath(t *testing.T) {
	p := &OIDCProvider{anonymousPaths: []string{"/docs", "/v2/admin/health"}}
	if !p.isAnonymousPath("/docs") {
		t.Error("want true for exact prefix")
	}
	if !p.isAnonymousPath("/v2/admin/health/ready") {
		t.Error("want true for matching prefix")
	}
	if p.isAnonymousPath("/private") {
		t.Error("want false for non-matching path")
	}
}

// ----- audienceMatches -----

func TestAudienceMatches(t *testing.T) {
	cases := []struct {
		name string
		aud  any
		want bool
	}{
		{"string match", "ans", true},
		{"string mismatch", "other", false},
		{"slice any match", []any{"other", "ans"}, true},
		{"slice any mismatch", []any{"x", "y"}, false},
		{"slice any non-string element", []any{42, "ans"}, true},
		{"slice string match", []string{"ans", "other"}, true},
		{"slice string mismatch", []string{"x"}, false},
		{"unsupported type", 42, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audienceMatches(tc.aud, "ans"); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// ----- parseScopeClaim -----

func TestParseScopeClaim(t *testing.T) {
	cases := map[string][]string{
		"":               nil,
		"read":           {"read"},
		"read write":     {"read", "write"},
		"  read  write ": {"read", "write"},
	}
	for in, want := range cases {
		got := parseScopeClaim(in)
		if len(got) != len(want) {
			t.Errorf("parseScopeClaim(%q): got %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("parseScopeClaim(%q)[%d]: got %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

// ----- anyGroupMatches -----

func TestAnyGroupMatches(t *testing.T) {
	if anyGroupMatches([]string{"user"}, nil) {
		t.Error("empty adminGroups should never match")
	}
	if !anyGroupMatches([]string{"user", "ops"}, []string{"sre", "ops"}) {
		t.Error("should match shared element")
	}
	if anyGroupMatches([]string{"user"}, []string{"ops"}) {
		t.Error("disjoint groups should not match")
	}
	if anyGroupMatches(nil, []string{"ops"}) {
		t.Error("empty token groups should not match")
	}
}
