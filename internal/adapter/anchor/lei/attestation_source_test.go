package lei

import (
	"context"
	"testing"
)

func TestStaticAttestationSource_SetAndLookup(t *testing.T) {
	s := NewStaticAttestationSource()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`)
	s.Set(validLEI, jwk)

	got, err := s.Lookup(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if string(got) != string(jwk) {
		t.Errorf("Lookup: got %q, want %q", got, jwk)
	}
}

func TestStaticAttestationSource_LookupMissing(t *testing.T) {
	s := NewStaticAttestationSource()
	got, err := s.Lookup(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Lookup on empty: %v", err)
	}
	if got != nil {
		t.Errorf("Lookup on empty source should return nil, got %q", got)
	}
}

func TestStaticAttestationSource_SetCanonicalizes(t *testing.T) {
	s := NewStaticAttestationSource()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`)
	// Set with lowercase form; Lookup with canonical form should hit.
	s.Set("529900t8bm49aursdo55", jwk)

	got, err := s.Lookup(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if string(got) != string(jwk) {
		t.Errorf("canonicalization failed: got %q", got)
	}
}

func TestStaticAttestationSource_DefensiveCopyOnLookup(t *testing.T) {
	s := NewStaticAttestationSource()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`)
	s.Set(validLEI, jwk)

	got, _ := s.Lookup(context.Background(), validLEI)
	got[0] = 'X' // mutate the returned slice

	// Lookup again — should return unmutated bytes.
	again, _ := s.Lookup(context.Background(), validLEI)
	if string(again) != string(jwk) {
		t.Errorf("stored bytes mutated by caller: got %q", again)
	}
}

func TestStaticAttestationSource_DefensiveCopyOnSet(t *testing.T) {
	s := NewStaticAttestationSource()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`)
	s.Set(validLEI, jwk)

	// Mutate the original slice the caller passed to Set.
	jwk[0] = 'X'

	got, _ := s.Lookup(context.Background(), validLEI)
	if got[0] == 'X' {
		t.Error("Set should defensively copy; caller's mutation leaked into store")
	}
}

func TestStaticAttestationSource_OverwriteSet(t *testing.T) {
	s := NewStaticAttestationSource()
	first := []byte(`{"kty":"OKP","crv":"Ed25519","x":"first"}`)
	second := []byte(`{"kty":"OKP","crv":"Ed25519","x":"second"}`)
	s.Set(validLEI, first)
	s.Set(validLEI, second)

	got, _ := s.Lookup(context.Background(), validLEI)
	if string(got) != string(second) {
		t.Errorf("overwrite failed: got %q, want %q", got, second)
	}
}

// TestResolver_Resolve_AttestationFromSource exercises the new
// composition: GLEIF entity check + AttestationJWKSource for the
// JWK. The Level 1 record has no AttestationJWK; the source supplies
// it; the resolver returns a complete IdentityClaim.
func TestResolver_Resolve_AttestationFromSource(t *testing.T) {
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`)

	gleif := &fakeGLEIFClient{
		record: &GLEIFRecord{
			LEI:          validLEI,
			EntityName:   "Test Entity",
			EntityStatus: "ACTIVE",
			Jurisdiction: "US-DE",
			// AttestationJWK intentionally empty; comes from source.
		},
	}
	source := NewStaticAttestationSource()
	source.Set(validLEI, jwk)

	r := New().WithClient(gleif).WithAttestationSource(source)
	claim, err := r.Resolve(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(claim.PublicKeyJWK) != string(jwk) {
		t.Errorf("PublicKeyJWK: got %q, want %q", claim.PublicKeyJWK, jwk)
	}
	if claim.ResolvedID != validLEI {
		t.Errorf("ResolvedID: got %q, want %q", claim.ResolvedID, validLEI)
	}
}

// TestResolver_Resolve_AttestationFallsBackToRecord verifies that a
// vLEI-aware GLEIFClient that already populates AttestationJWK takes
// precedence; the source is the fallback path.
func TestResolver_Resolve_AttestationFallsBackToRecord(t *testing.T) {
	fromRecord := []byte(`{"kty":"OKP","crv":"Ed25519","x":"from-record"}`)
	fromSource := []byte(`{"kty":"OKP","crv":"Ed25519","x":"from-source"}`)

	gleif := &fakeGLEIFClient{
		record: &GLEIFRecord{
			LEI:            validLEI,
			EntityStatus:   "ACTIVE",
			AttestationJWK: fromRecord,
		},
	}
	source := NewStaticAttestationSource()
	source.Set(validLEI, fromSource)

	r := New().WithClient(gleif).WithAttestationSource(source)
	claim, err := r.Resolve(context.Background(), validLEI)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(claim.PublicKeyJWK) != string(fromRecord) {
		t.Errorf("expected record's AttestationJWK to win, got %q", claim.PublicKeyJWK)
	}
}

// TestResolver_Resolve_NoSourceNoKey verifies the existing
// LEI_NO_ATTESTATION_KEY error path: no source, no key on the
// record, error.
func TestResolver_Resolve_NoSourceNoKey(t *testing.T) {
	gleif := &fakeGLEIFClient{
		record: &GLEIFRecord{
			LEI:          validLEI,
			EntityStatus: "ACTIVE",
		},
	}
	r := New().WithClient(gleif)
	_, err := r.Resolve(context.Background(), validLEI)
	if err == nil {
		t.Fatal("expected LEI_NO_ATTESTATION_KEY error")
	}
}
