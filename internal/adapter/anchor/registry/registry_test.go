package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/anchor/did"
	"github.com/godaddy/ans/internal/adapter/anchor/lei"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// Compile-time check that *Registry satisfies port.AnchorResolver.
var _ port.AnchorResolver = (*Registry)(nil)

const validLEI = "529900T8BM49AURSDO55"

// fakeFQDNResolver is a test double for the slice-3 FQDN resolver
// surface. The production package's Resolve currently returns a
// not-implemented stub; tests against the registry want a live
// success path so we double the surface here.
type fakeFQDNResolver struct {
	resolveErr error
	claim      *domain.IdentityClaim
}

func (f *fakeFQDNResolver) Resolve(_ context.Context, _ string) (*domain.IdentityClaim, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return f.claim, nil
}

func (f *fakeFQDNResolver) SupportedProfiles() []string {
	return []string{"0.A-fqdn"}
}

// fakeGLEIFClient lets the LEI sub-resolver succeed in tests
// without an HTTP transport. Mirrors the test double in
// internal/adapter/anchor/lei.
type fakeGLEIFClient struct {
	record *lei.GLEIFRecord
	err    error
}

func (f *fakeGLEIFClient) LookupRecord(_ context.Context, _ string) (*lei.GLEIFRecord, error) {
	return f.record, f.err
}

func TestRegistry_DispatchByLexicalForm(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantBranch string
	}{
		{"FQDN", "agent.example.com", "fqdn"},
		{"DID lowercased", "did:web:agent.example.com", "did"},
		{"DID uppercase prefix", "DID:web:agent.example.com", "did"},
		{"LEI 20-char alphanumeric", validLEI, "lei"},
		{"FQDN-shape with dot beats LEI shape (lexical match)", "1234567890ABCDEF.com", "fqdn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fqdnHits := false
			r := New().
				WithFQDN(&fakeFQDNResolver{
					claim: &domain.IdentityClaim{AnchorType: domain.AnchorTypeFQDN, ResolvedID: c.input},
				})

			r = r.WithDIDWeb(did.NewWeb()).WithLEI(lei.New())
			_ = fqdnHits

			claim, err := r.Resolve(context.Background(), c.input)
			switch c.wantBranch {
			case "fqdn":
				if err != nil {
					t.Errorf("FQDN dispatch should reach fake (no error), got %v", err)
				}
				if claim == nil || claim.AnchorType != domain.AnchorTypeFQDN {
					t.Errorf("FQDN dispatch returned %+v", claim)
				}
			case "did":
				// did.NewWeb has no client transport here, so the
				// fetch fails — but it must fail with a DID-shaped
				// error code, proving the dispatch chose the DID
				// branch.
				if err == nil {
					t.Errorf("expected DID resolver to error without configured client, got nil")
				}
				var dErr *domain.Error
				if errors.As(err, &dErr) {
					if !startsWith(dErr.Code, "DID_") {
						t.Errorf("DID branch returned non-DID code %q", dErr.Code)
					}
				}
			case "lei":
				// LEI resolver with no client returns
				// LEI_GLEIF_NOT_CONFIGURED proving the LEI
				// branch fired.
				if err == nil {
					t.Errorf("expected LEI resolver to surface stub error, got nil")
				}
				var dErr *domain.Error
				if errors.As(err, &dErr) {
					if !startsWith(dErr.Code, "LEI_") {
						t.Errorf("LEI branch returned non-LEI code %q", dErr.Code)
					}
				}
			}
		})
	}
}

func TestRegistry_EmptyInput(t *testing.T) {
	r := New().WithFQDN(&fakeFQDNResolver{})
	_, err := r.Resolve(context.Background(), "")
	if err == nil {
		t.Fatal("expected INVALID_ANCHOR_FORMAT, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "INVALID_ANCHOR_FORMAT" {
		t.Errorf("expected INVALID_ANCHOR_FORMAT, got %v", err)
	}
}

func TestRegistry_UnknownShape(t *testing.T) {
	r := New().WithFQDN(&fakeFQDNResolver{}).WithLEI(lei.New()).WithDIDWeb(did.NewWeb())
	cases := []string{
		"not a real input",       // contains spaces, no dot
		"only-one-label-no-dots", // no dot
		"shorter-than-twenty",    // hyphen, no dot
		"ABCDEFGHIJ123456789",    // 19 chars, looks LEI-ish but length wrong
		"#%$@!()",                // punctuation
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := r.Resolve(context.Background(), c)
			if err == nil {
				t.Fatal("expected INVALID_ANCHOR_FORMAT, got nil")
			}
			var dErr *domain.Error
			if !errors.As(err, &dErr) || dErr.Code != "INVALID_ANCHOR_FORMAT" {
				t.Errorf("input %q: expected INVALID_ANCHOR_FORMAT, got %v", c, err)
			}
		})
	}
}

func TestRegistry_DIDWithoutDIDResolverConfigured(t *testing.T) {
	r := New().WithFQDN(&fakeFQDNResolver{}) // no DID resolver
	_, err := r.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected PROFILE_NOT_CONFIGURED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "PROFILE_NOT_CONFIGURED" {
		t.Errorf("expected PROFILE_NOT_CONFIGURED, got %v", err)
	}
}

func TestRegistry_LEIWithoutLEIResolverConfigured(t *testing.T) {
	r := New().WithFQDN(&fakeFQDNResolver{}) // no LEI resolver
	_, err := r.Resolve(context.Background(), validLEI)
	if err == nil {
		t.Fatal("expected PROFILE_NOT_CONFIGURED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "PROFILE_NOT_CONFIGURED" {
		t.Errorf("expected PROFILE_NOT_CONFIGURED, got %v", err)
	}
}

func TestRegistry_FQDNWithoutFQDNResolverConfigured(t *testing.T) {
	r := New().WithLEI(lei.New()) // no FQDN resolver
	_, err := r.Resolve(context.Background(), "agent.example.com")
	if err == nil {
		t.Fatal("expected PROFILE_NOT_CONFIGURED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "PROFILE_NOT_CONFIGURED" {
		t.Errorf("expected PROFILE_NOT_CONFIGURED, got %v", err)
	}
}

func TestRegistry_SupportedProfilesUnion(t *testing.T) {
	r := New().
		WithFQDN(&fakeFQDNResolver{}).
		WithDIDWeb(did.NewWeb()).
		WithLEI(lei.New())
	got := r.SupportedProfiles()
	if len(got) != 3 {
		t.Errorf("SupportedProfiles len = %d, want 3 (got %v)", len(got), got)
	}
	wantContains := []string{"0.A-fqdn", "0.B-did:web", "0.C-lei"}
	for _, w := range wantContains {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SupportedProfiles missing %q (got %v)", w, got)
		}
	}
}

func TestRegistry_LEIBranchSucceedsWithFakeClient(t *testing.T) {
	fixed := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"LEI-K"}`)
	leiResolver := lei.New().
		WithClock(func() time.Time { return fixed }).
		WithClient(&fakeGLEIFClient{
			record: &lei.GLEIFRecord{
				LEI:            validLEI,
				EntityStatus:   "ACTIVE",
				AttestationJWK: jwk,
			},
		})
	r := New().WithLEI(leiResolver)
	claim, err := r.Resolve(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeLEI {
		t.Errorf("expected LEI claim, got %+v", claim)
	}
}

func TestLooksLikeLEI(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{validLEI, true},
		{"abcdefghijklmnopqrst", true},   // shape only; mod-97 is the LEI resolver's job
		{"529900T8BM49AURSDO5", false},   // 19 chars
		{"529900T8BM49AURSDO551", false}, // 21 chars
		{"529900T8BM49AURSDO5-", false},  // hyphen
		{"529900T8BM49AURSDO5 ", false},  // space
	}
	for _, c := range cases {
		if got := looksLikeLEI(c.input); got != c.want {
			t.Errorf("looksLikeLEI(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestLooksLikeFQDN(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"agent.example.com", true},
		{"a.b", true},
		{"single", false}, // no dot
		{"has.spaces .com", false},
		{"has_underscore.com", false},
		{"has@symbol.com", false},
	}
	for _, c := range cases {
		if got := looksLikeFQDN(c.input); got != c.want {
			t.Errorf("looksLikeFQDN(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

// startsWith is a tiny helper to keep imports minimal.
func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := range len(prefix) {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}
