package lei

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// validLEI is the well-known GLEIF documentation example LEI, which
// passes mod-97. Verified against
// https://www.gleif.org/en/about-lei/iso-17442-the-lei-code-structure
const validLEI = "529900T8BM49AURSDO55"

// invalidCheckLEI is validLEI with the last two check digits perturbed
// to fail mod-97.
const invalidCheckLEI = "529900T8BM49AURSDO99"

func TestCanonicalize_HappyPath(t *testing.T) {
	got, err := Canonicalize(validLEI)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got != validLEI {
		t.Errorf("got %q, want %q", got, validLEI)
	}
}

func TestCanonicalize_LowercaseUppercased(t *testing.T) {
	lower := "529900t8bm49aursdo55"
	got, err := Canonicalize(lower)
	if err != nil {
		t.Fatalf("Canonicalize lowercase: %v", err)
	}
	if got != validLEI {
		t.Errorf("uppercase form not enforced: got %q", got)
	}
}

func TestCanonicalize_TrimsWhitespace(t *testing.T) {
	got, err := Canonicalize("  " + validLEI + "  ")
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got != validLEI {
		t.Errorf("got %q", got)
	}
}

func TestCanonicalize_BadFormat(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantCode string
	}{
		{"empty", "", "LEI_BAD_FORMAT"},
		{"too short", "529900T8BM49", "LEI_BAD_FORMAT"},
		{"too long", validLEI + "X", "LEI_BAD_FORMAT"},
		{"contains hyphen", "529900-T8BM49AURSDO55", "LEI_BAD_FORMAT"},
		{"contains space inside", "529900 T8BM49AURSDO55", "LEI_BAD_FORMAT"},
		{"contains lowercase non-alpha", "529900t8bm49aursdo5!", "LEI_BAD_FORMAT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Canonicalize(c.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var dErr *domain.Error
			if !errors.As(err, &dErr) || dErr.Code != c.wantCode {
				t.Errorf("expected %q, got %v", c.wantCode, err)
			}
		})
	}
}

func TestCanonicalize_BadCheckDigits(t *testing.T) {
	_, err := Canonicalize(invalidCheckLEI)
	if err == nil {
		t.Fatal("expected LEI_BAD_CHECK_DIGITS, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "LEI_BAD_CHECK_DIGITS" {
		t.Errorf("expected LEI_BAD_CHECK_DIGITS, got %v", err)
	}
}

func TestResolver_Resolve_NoClient(t *testing.T) {
	r := New()
	_, err := r.Resolve(context.Background(), validLEI)
	if err == nil {
		t.Fatal("expected LEI_GLEIF_NOT_CONFIGURED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "LEI_GLEIF_NOT_CONFIGURED" {
		t.Errorf("expected LEI_GLEIF_NOT_CONFIGURED, got %v", err)
	}
}

func TestResolver_Resolve_BadFormatPropagates(t *testing.T) {
	r := New()
	_, err := r.Resolve(context.Background(), "")
	if err == nil {
		t.Fatal("expected LEI_BAD_FORMAT, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "LEI_BAD_FORMAT" {
		t.Errorf("expected LEI_BAD_FORMAT, got %v", err)
	}
}

// fakeGLEIFClient is a test double for the slice-3 + slice-3.1
// boundary; once a real GLEIF HTTP client lands it satisfies the
// same interface and these tests carry over unchanged.
type fakeGLEIFClient struct {
	record *GLEIFRecord
	err    error
}

func (f *fakeGLEIFClient) LookupRecord(_ context.Context, _ string) (*GLEIFRecord, error) {
	return f.record, f.err
}

func TestResolver_Resolve_ActiveEntity(t *testing.T) {
	fixed := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"LEI-KEY"}`)
	r := New().
		WithClock(func() time.Time { return fixed }).
		WithClient(&fakeGLEIFClient{
			record: &GLEIFRecord{
				LEI:            validLEI,
				EntityName:     "Acme Corp",
				EntityStatus:   "ACTIVE",
				Jurisdiction:   "US-DE",
				AttestationJWK: jwk,
				UpdatedAt:      fixed.Add(-30 * 24 * time.Hour),
			},
		})

	claim, err := r.Resolve(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeLEI {
		t.Errorf("AnchorType = %q", claim.AnchorType)
	}
	if claim.ResolvedID != validLEI {
		t.Errorf("ResolvedID = %q, want %q", claim.ResolvedID, validLEI)
	}
	if string(claim.PublicKeyJWK) != string(jwk) {
		t.Errorf("attestation JWK was mutated")
	}
	if !claim.IssuedAt.Equal(fixed) {
		t.Errorf("IssuedAt = %v", claim.IssuedAt)
	}
	if !claim.ExpiresAt.Equal(fixed.Add(freshnessBudget)) {
		t.Errorf("ExpiresAt = %v, want %v", claim.ExpiresAt, fixed.Add(freshnessBudget))
	}
	if err := claim.Validate(); err != nil {
		t.Errorf("returned claim fails Validate: %v", err)
	}
}

func TestResolver_Resolve_InactiveStatusRejected(t *testing.T) {
	cases := []string{"INACTIVE", "LAPSED", "RETIRED", "MERGED"}
	for _, status := range cases {
		t.Run(status, func(t *testing.T) {
			r := New().WithClient(&fakeGLEIFClient{
				record: &GLEIFRecord{
					LEI:            validLEI,
					EntityStatus:   status,
					AttestationJWK: []byte(`{"kty":"OKP"}`),
				},
			})
			_, err := r.Resolve(context.Background(), validLEI)
			if err == nil {
				t.Fatal("expected LEI_INACTIVE, got nil")
			}
			var dErr *domain.Error
			if !errors.As(err, &dErr) || dErr.Code != "LEI_INACTIVE" {
				t.Errorf("expected LEI_INACTIVE, got %v", err)
			}
		})
	}
}

func TestResolver_Resolve_LookupError(t *testing.T) {
	r := New().WithClient(&fakeGLEIFClient{err: errors.New("network down")})
	_, err := r.Resolve(context.Background(), validLEI)
	if err == nil {
		t.Fatal("expected LEI_RESOLUTION_FAILED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "LEI_RESOLUTION_FAILED" {
		t.Errorf("expected LEI_RESOLUTION_FAILED, got %v", err)
	}
}

func TestResolver_Resolve_NilRecord(t *testing.T) {
	r := New().WithClient(&fakeGLEIFClient{}) // both record and err nil
	_, err := r.Resolve(context.Background(), validLEI)
	if err == nil {
		t.Fatal("expected LEI_UNKNOWN, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "LEI_UNKNOWN" {
		t.Errorf("expected LEI_UNKNOWN, got %v", err)
	}
}

func TestResolver_Resolve_MissingAttestationKey(t *testing.T) {
	r := New().WithClient(&fakeGLEIFClient{
		record: &GLEIFRecord{
			LEI:          validLEI,
			EntityStatus: "ACTIVE",
			// AttestationJWK omitted
		},
	})
	_, err := r.Resolve(context.Background(), validLEI)
	if err == nil {
		t.Fatal("expected LEI_NO_ATTESTATION_KEY, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "LEI_NO_ATTESTATION_KEY" {
		t.Errorf("expected LEI_NO_ATTESTATION_KEY, got %v", err)
	}
}

func TestResolver_SupportedProfiles(t *testing.T) {
	got := New().SupportedProfiles()
	if len(got) != 1 || got[0] != ProfileID {
		t.Errorf("SupportedProfiles = %v, want [%q]", got, ProfileID)
	}
	if ProfileID != "0.C-lei" {
		t.Errorf("ProfileID = %q, want %q (matches docs/profiles/anchor-0c-lei.md)",
			ProfileID, "0.C-lei")
	}
}
