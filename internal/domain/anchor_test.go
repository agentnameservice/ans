package domain

import (
	"errors"
	"testing"
	"time"
)

func TestAnchorType_IsValid(t *testing.T) {
	cases := []struct {
		name string
		typ  AnchorType
		want bool
	}{
		{"fqdn", AnchorTypeFQDN, true},
		{"did", AnchorTypeDID, true},
		{"lei", AnchorTypeLEI, true},
		{"empty", AnchorType(""), false},
		{"unknown", AnchorType("spiffe"), false},
		{"uppercase rejected", AnchorType("FQDN"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.typ.IsValid(); got != c.want {
				t.Errorf("IsValid(%q) = %v, want %v", c.typ, got, c.want)
			}
		})
	}
}

func TestIdentityClaim_Validate(t *testing.T) {
	now := time.Now().UTC()
	jwk := []byte(`{"kty":"OKP","crv":"Ed25519","x":"Q-..."}`)

	cases := []struct {
		name      string
		claim     IdentityClaim
		wantCode  string
		wantValid bool
	}{
		{
			name: "valid fqdn claim",
			claim: IdentityClaim{
				AnchorType:   AnchorTypeFQDN,
				ResolvedID:   "agent.example.com",
				PublicKeyJWK: jwk,
				IssuedAt:     now,
			},
			wantValid: true,
		},
		{
			name: "valid did claim with metadataUrl",
			claim: IdentityClaim{
				AnchorType:   AnchorTypeDID,
				ResolvedID:   "did:web:agent.example.com",
				PublicKeyJWK: jwk,
				MetadataURL:  "https://agent.example.com/.well-known/did.json",
				IssuedAt:     now,
			},
			wantValid: true,
		},
		{
			name: "invalid anchor type",
			claim: IdentityClaim{
				AnchorType:   AnchorType("spiffe"),
				ResolvedID:   "spiffe://example.com/foo",
				PublicKeyJWK: jwk,
				IssuedAt:     now,
			},
			wantCode: "INVALID_ANCHOR_TYPE",
		},
		{
			name: "missing resolvedId",
			claim: IdentityClaim{
				AnchorType:   AnchorTypeFQDN,
				PublicKeyJWK: jwk,
				IssuedAt:     now,
			},
			wantCode: "MISSING_RESOLVED_ID",
		},
		{
			name: "missing public key",
			claim: IdentityClaim{
				AnchorType: AnchorTypeFQDN,
				ResolvedID: "agent.example.com",
				IssuedAt:   now,
			},
			wantCode: "MISSING_PUBLIC_KEY",
		},
		{
			name: "missing issuedAt",
			claim: IdentityClaim{
				AnchorType:   AnchorTypeFQDN,
				ResolvedID:   "agent.example.com",
				PublicKeyJWK: jwk,
			},
			wantCode: "MISSING_ISSUED_AT",
		},
		{
			name: "whitespace-only resolvedId",
			claim: IdentityClaim{
				AnchorType:   AnchorTypeFQDN,
				ResolvedID:   "   ",
				PublicKeyJWK: jwk,
				IssuedAt:     now,
			},
			wantCode: "MISSING_RESOLVED_ID",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.claim.Validate()
			if c.wantValid {
				if err != nil {
					t.Errorf("expected valid, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var code string
			var dErr *Error
			if errors.As(err, &dErr) {
				code = dErr.Code
			}
			if code != c.wantCode {
				t.Errorf("error code = %q, want %q (err: %v)", code, c.wantCode, err)
			}
		})
	}
}

func TestIdentityClaim_IsZero(t *testing.T) {
	if !(IdentityClaim{}).IsZero() {
		t.Error("zero-value IdentityClaim should be IsZero")
	}
	populated := IdentityClaim{
		AnchorType:   AnchorTypeFQDN,
		ResolvedID:   "x",
		PublicKeyJWK: []byte("y"),
	}
	if populated.IsZero() {
		t.Error("populated IdentityClaim should not be IsZero")
	}
}

func TestIdentityClaim_FQDN(t *testing.T) {
	cases := []struct {
		name  string
		claim IdentityClaim
		want  string
	}{
		{
			name: "fqdn anchor returns resolvedId",
			claim: IdentityClaim{
				AnchorType: AnchorTypeFQDN,
				ResolvedID: "agent.example.com",
			},
			want: "agent.example.com",
		},
		{
			name: "did anchor returns empty",
			claim: IdentityClaim{
				AnchorType: AnchorTypeDID,
				ResolvedID: "did:web:agent.example.com",
			},
			want: "",
		},
		{
			name:  "zero claim returns empty",
			claim: IdentityClaim{},
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.claim.FQDN(); got != c.want {
				t.Errorf("FQDN() = %q, want %q", got, c.want)
			}
		})
	}
}
