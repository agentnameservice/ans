package domain_test

import (
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/domain"
)

// validPayload returns an AttestationPayload that passes
// NewAttestationPayload as-is. Tests clone it and mutate one field
// at a time to exercise each rejection path.
func validPayload() domain.AttestationPayload {
	return domain.AttestationPayload{
		Issuer:                 "https://ra.example.com",
		Subject:                "agent.example.com",
		IssuedAt:               1700000000,
		ExpiresAt:              1700003600,
		IdentityCertSPKISHA256: bytesOf(0xAA, 32),
		ServerCertSPKISHA256:   bytesOf(0xBB, 32),
		DNS: domain.AttestationDNS{
			VerifiedAt:      1700000000,
			TLSARecords:     [][]byte{bytesOf(0xCC, 35)},
			DNSSECValidated: true,
		},
		TL: domain.AttestationTL{
			LogURL:   "https://tl.example.com",
			LeafHash: bytesOf(0xDD, 32),
			TreeSize: 42,
			Receipt:  bytesOf(0xEE, 100),
		},
	}
}

func TestNewAttestationPayload_HappyPath(t *testing.T) {
	t.Parallel()
	out, err := domain.NewAttestationPayload(validPayload())
	if err != nil {
		t.Fatalf("NewAttestationPayload: %v", err)
	}
	// DID auto-derived from subject.
	if out.DID != "did:web:agent.example.com" {
		t.Errorf("DID = %q, want did:web:agent.example.com", out.DID)
	}
	// Subject lowercased + trimmed.
	if out.Subject != "agent.example.com" {
		t.Errorf("Subject = %q, want agent.example.com", out.Subject)
	}
}

func TestNewAttestationPayload_SubjectNormalization(t *testing.T) {
	t.Parallel()
	p := validPayload()
	p.Subject = "  AGENT.Example.COM  "
	out, err := domain.NewAttestationPayload(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Subject != "agent.example.com" {
		t.Errorf("Subject = %q, want lowercased+trimmed", out.Subject)
	}
	if out.DID != "did:web:agent.example.com" {
		t.Errorf("DID = %q, want derived from normalized subject", out.DID)
	}
}

func TestNewAttestationPayload_ExplicitDIDPreserved(t *testing.T) {
	t.Parallel()
	p := validPayload()
	p.DID = "did:web:operator-chosen.example.com"
	out, err := domain.NewAttestationPayload(p)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.DID != "did:web:operator-chosen.example.com" {
		t.Errorf("DID = %q, want explicit value preserved", out.DID)
	}
}

func TestNewAttestationPayload_Validations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*domain.AttestationPayload)
		wantErr string // substring of the returned error code
	}{
		{"missing iss", func(p *domain.AttestationPayload) { p.Issuer = "" }, "MISSING_ISS"},
		{"invalid iss", func(p *domain.AttestationPayload) { p.Issuer = "://not a url" }, "INVALID_ISS"},
		{"missing sub", func(p *domain.AttestationPayload) { p.Subject = "" }, "MISSING_SUB"},
		{"sub all whitespace", func(p *domain.AttestationPayload) { p.Subject = "    " }, "MISSING_SUB"},
		{"sub not a hostname", func(p *domain.AttestationPayload) { p.Subject = "not a host" }, "INVALID_SUB"},
		{"did wrong method", func(p *domain.AttestationPayload) { p.DID = "did:key:abc" }, "INVALID_DID"},
		{"iat zero", func(p *domain.AttestationPayload) { p.IssuedAt = 0 }, "INVALID_IAT"},
		{"iat negative", func(p *domain.AttestationPayload) { p.IssuedAt = -1 }, "INVALID_IAT"},
		{"exp equal iat", func(p *domain.AttestationPayload) { p.ExpiresAt = p.IssuedAt }, "INVALID_EXP"},
		{"exp before iat", func(p *domain.AttestationPayload) { p.ExpiresAt = p.IssuedAt - 1 }, "INVALID_EXP"},
		{"identity spki short", func(p *domain.AttestationPayload) { p.IdentityCertSPKISHA256 = bytesOf(0xAA, 31) }, "INVALID_IDENTITY_SPKI"},
		{"identity spki long", func(p *domain.AttestationPayload) { p.IdentityCertSPKISHA256 = bytesOf(0xAA, 33) }, "INVALID_IDENTITY_SPKI"},
		{"server spki nil", func(p *domain.AttestationPayload) { p.ServerCertSPKISHA256 = nil }, "INVALID_SERVER_SPKI"},
		{"dns verified_at zero", func(p *domain.AttestationPayload) { p.DNS.VerifiedAt = 0 }, "INVALID_DNS_VERIFIED_AT"},
		{"tl log_url missing", func(p *domain.AttestationPayload) { p.TL.LogURL = "" }, "MISSING_TL_LOG_URL"},
		{"tl log_url malformed", func(p *domain.AttestationPayload) { p.TL.LogURL = "://nope" }, "INVALID_TL_LOG_URL"},
		{"tl leaf_hash wrong size", func(p *domain.AttestationPayload) { p.TL.LeafHash = bytesOf(0xDD, 16) }, "INVALID_TL_LEAF_HASH"},
		{"tl tree_size zero", func(p *domain.AttestationPayload) { p.TL.TreeSize = 0 }, "INVALID_TL_TREE_SIZE"},
		{"tl receipt missing", func(p *domain.AttestationPayload) { p.TL.Receipt = nil }, "MISSING_TL_RECEIPT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := validPayload()
			c.mutate(&p)
			_, err := domain.NewAttestationPayload(p)
			if err == nil {
				t.Fatalf("want validation error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want error code containing %q", err, c.wantErr)
			}
		})
	}
}

func TestNewAttestationPayload_EmptyTLSARecordsOK(t *testing.T) {
	t.Parallel()
	// BADGE_TXT_ONLY style emits no TLSA records — must not be a
	// validation failure.
	p := validPayload()
	p.DNS.TLSARecords = nil
	if _, err := domain.NewAttestationPayload(p); err != nil {
		t.Fatalf("empty TLSA should be valid: %v", err)
	}
	p.DNS.TLSARecords = [][]byte{}
	if _, err := domain.NewAttestationPayload(p); err != nil {
		t.Fatalf("empty TLSA slice should be valid: %v", err)
	}
}

func TestDIDForSubject(t *testing.T) {
	t.Parallel()
	if got := domain.DIDForSubject("morpheus.example.com"); got != "did:web:morpheus.example.com" {
		t.Errorf("DIDForSubject = %q, want did:web:morpheus.example.com", got)
	}
}

// --- helpers ---

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
