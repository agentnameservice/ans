package fqdn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

func mustClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestResolver_ResolveWithKey_Canonical(t *testing.T) {
	fixed := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	r := New().WithClock(mustClock(fixed))
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"Q-..."}`)

	claim, err := r.ResolveWithKey("Agent.Example.COM.", jwk, "")
	if err != nil {
		t.Fatalf("ResolveWithKey: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeFQDN {
		t.Errorf("AnchorType = %q, want %q", claim.AnchorType, domain.AnchorTypeFQDN)
	}
	if claim.ResolvedID != "agent.example.com" {
		t.Errorf("ResolvedID = %q, want %q (canonical lowercase, no trailing dot)",
			claim.ResolvedID, "agent.example.com")
	}
	if !claim.IssuedAt.Equal(fixed) {
		t.Errorf("IssuedAt = %v, want %v", claim.IssuedAt, fixed)
	}
	if string(claim.PublicKeyJWK) != string(jwk) {
		t.Errorf("PublicKeyJWK was mutated")
	}
	if err := claim.Validate(); err != nil {
		t.Errorf("returned claim fails Validate: %v", err)
	}
}

func TestResolver_ResolveWithKey_MetadataURL(t *testing.T) {
	r := New()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"Q-..."}`)
	want := "https://agent.example.com/.well-known/ans/trust-card.json"
	claim, err := r.ResolveWithKey("agent.example.com", jwk, want)
	if err != nil {
		t.Fatalf("ResolveWithKey: %v", err)
	}
	if claim.MetadataURL != want {
		t.Errorf("MetadataURL = %q, want %q", claim.MetadataURL, want)
	}
}

func TestResolver_ResolveWithKey_BadFormat(t *testing.T) {
	r := New()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"Q-..."}`)

	cases := []struct {
		name     string
		input    string
		wantCode string
	}{
		{"empty", "", "FQDN_BAD_FORMAT"},
		{"whitespace only", "   ", "FQDN_BAD_FORMAT"},
		{"single label (no dot)", "localhost", "FQDN_BAD_FORMAT"},
		{"too long total", longFQDN(254), "FQDN_BAD_FORMAT"},
		{"contains whitespace", "agent .example.com", "FQDN_BAD_FORMAT"},
		{"empty label", "agent..example.com", "FQDN_LABEL_BAD"},
		{"label too long", "agent." + repeat("a", 64) + ".com", "FQDN_LABEL_BAD"},
		{"leading hyphen", "-bad.example.com", "FQDN_LABEL_BAD"},
		{"trailing hyphen", "bad-.example.com", "FQDN_LABEL_BAD"},
		{"underscore (ANS reserves _-prefixed)", "_ans.example.com", "FQDN_LABEL_BAD"},
		{"non-LDH char", "ag$ent.example.com", "FQDN_LABEL_BAD"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.ResolveWithKey(c.input, jwk, "")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var dErr *domain.Error
			ok := errors.As(err, &dErr)
			if !ok {
				t.Fatalf("error is not *domain.Error: %T", err)
			}
			if dErr.Code != c.wantCode {
				t.Errorf("code = %q, want %q (msg: %s)", dErr.Code, c.wantCode, dErr.Message)
			}
		})
	}
}

func TestResolver_ResolveWithKey_MissingKey(t *testing.T) {
	r := New()
	_, err := r.ResolveWithKey("agent.example.com", nil, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "MISSING_PUBLIC_KEY" {
		t.Errorf("expected MISSING_PUBLIC_KEY, got %v", err)
	}
}

func TestResolver_SupportedProfiles(t *testing.T) {
	got := New().SupportedProfiles()
	if len(got) != 1 || got[0] != ProfileID {
		t.Errorf("SupportedProfiles = %v, want [%q]", got, ProfileID)
	}
	if ProfileID != "0.A-fqdn" {
		t.Errorf("ProfileID = %q, want %q (matches docs/profiles/anchor-0a-fqdn.md)",
			ProfileID, "0.A-fqdn")
	}
}

func TestResolver_Resolve_NotImplemented(t *testing.T) {
	// Slice 1: full Resolve is deferred. The shape-only ResolveWithKey
	// is the migration entry point. Once Slice 4 lands, Resolve will
	// own DNS resolution + cert chain validation; this test pins the
	// not-implemented error so the migration boundary is explicit.
	r := New()
	_, err := r.Resolve(context.Background(), "agent.example.com")
	if err == nil {
		t.Fatal("expected not-implemented error, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "FQDN_RESOLVE_NOT_IMPLEMENTED" {
		t.Errorf("expected FQDN_RESOLVE_NOT_IMPLEMENTED, got %v", err)
	}
}

// longFQDN returns a string of exactly n characters that has the
// shape of a multi-label FQDN (interspersed dots) so canonicalize's
// label-loop runs and surfaces the size cap before label-loop errors.
func longFQDN(n int) string {
	out := make([]byte, 0, n)
	for i := range n {
		if i > 0 && i%32 == 0 {
			out = append(out, '.')
		} else {
			out = append(out, 'a')
		}
	}
	return string(out[:n])
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}
