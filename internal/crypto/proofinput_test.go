package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sampleProofInput() IdentityProofInput {
	return IdentityProofInput{
		Identifier: "did:web:identity.acme-corp.com",
		IdentityID: "01HXKQ00000000000000000000",
		Nonce:      "bm9uY2U",
		Purpose:    IdentityProofPurpose,
		RaID:       "ans-ra-local",
		Scheme:     "did:web",
	}
}

func TestIdentityProofInputCanonical(t *testing.T) {
	in := sampleProofInput()
	canonical, err := in.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	// JCS: keys sorted lexicographically, no whitespace.
	s := string(canonical)
	order := []string{`"identifier"`, `"identityId"`, `"nonce"`, `"purpose"`, `"raId"`, `"scheme"`}
	last := -1
	for _, key := range order {
		idx := strings.Index(s, key)
		if idx < 0 || idx < last {
			t.Fatalf("canonical key order wrong: %s", s)
		}
		last = idx
	}
	if strings.Contains(s, " ") {
		t.Fatalf("canonical bytes contain whitespace: %s", s)
	}

	// Deterministic.
	again, err := in.Canonical()
	if err != nil || string(again) != s {
		t.Fatal("canonicalization must be deterministic")
	}
}

func TestIdentityProofInputSigningInput(t *testing.T) {
	in := sampleProofInput()
	encoded, err := in.SigningInput()
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("signing input is not base64url: %v", err)
	}
	var back IdentityProofInput
	if err := json.Unmarshal(decoded, &back); err != nil {
		t.Fatalf("decoded payload is not a proof input: %v", err)
	}
	if back != in {
		t.Fatalf("round trip mismatch: %+v", back)
	}
	if back.Purpose != "ans:identity-proof:v1" {
		t.Fatalf("purpose: %s", back.Purpose)
	}
}
