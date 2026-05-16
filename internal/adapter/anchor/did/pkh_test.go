package did

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// Anvil's first pre-funded account address (the canonical Ethereum
// testnet address used widely in foundry/hardhat documentation).
const anvilAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

func TestParseDIDPkh_Eip155(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantNS   string
		wantRef  string
		wantAddr string
	}{
		{
			name:     "Sepolia testnet",
			input:    "did:pkh:eip155:11155111:" + anvilAddress,
			wantNS:   "eip155",
			wantRef:  "11155111",
			wantAddr: anvilAddress,
		},
		{
			name:     "Ethereum mainnet",
			input:    "did:pkh:eip155:1:" + anvilAddress,
			wantNS:   "eip155",
			wantRef:  "1",
			wantAddr: anvilAddress,
		},
		{
			name:     "Local Anvil chain (chain id 31337)",
			input:    "did:pkh:eip155:31337:" + anvilAddress,
			wantNS:   "eip155",
			wantRef:  "31337",
			wantAddr: anvilAddress,
		},
		{
			name:     "uppercase namespace lowercased",
			input:    "did:pkh:EIP155:1:" + anvilAddress,
			wantNS:   "eip155",
			wantRef:  "1",
			wantAddr: anvilAddress,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDIDPkh(c.input)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got.Namespace != c.wantNS {
				t.Errorf("Namespace = %q, want %q", got.Namespace, c.wantNS)
			}
			if got.Reference != c.wantRef {
				t.Errorf("Reference = %q, want %q", got.Reference, c.wantRef)
			}
			if got.Address != c.wantAddr {
				t.Errorf("Address = %q, want %q", got.Address, c.wantAddr)
			}
		})
	}
}

func TestParseDIDPkh_BadShape(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantCode string
	}{
		{"wrong prefix", "did:web:agent.example.com", "DID_BAD_FORMAT"},
		{"missing prefix", "eip155:1:0x1234", "DID_BAD_FORMAT"},
		{"too few parts", "did:pkh:eip155:1", "DID_PKH_BAD_FORMAT"},
		{"empty namespace", "did:pkh::1:0x1234", "DID_PKH_BAD_FORMAT"},
		{"empty reference", "did:pkh:eip155::0x1234", "DID_PKH_BAD_FORMAT"},
		{"empty address", "did:pkh:eip155:1:", "DID_PKH_BAD_FORMAT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseDIDPkh(c.input)
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

func TestValidateEIP155Address(t *testing.T) {
	good := []string{
		anvilAddress,
		"0x" + strings.Repeat("a", 40),
		"0x" + strings.Repeat("F", 40),
		"0X" + strings.Repeat("0", 40), // uppercase 0X also accepted
	}
	for _, a := range good {
		if err := validateEIP155Address(a); err != nil {
			t.Errorf("validateEIP155Address(%q) rejected: %v", a, err)
		}
	}

	bad := []string{
		"",
		"not-an-address",
		"f39Fd6e51aad88F6F4ce6aB8827279cffFb92266", // missing 0x
		"0x" + strings.Repeat("a", 39),             // 39 chars
		"0x" + strings.Repeat("a", 41),             // 41 chars
		"0x" + strings.Repeat("g", 40),             // non-hex
	}
	for _, a := range bad {
		if err := validateEIP155Address(a); err == nil {
			t.Errorf("validateEIP155Address(%q) should reject", a)
		}
	}
}

func TestPkh_Resolve_NoChainConfigured(t *testing.T) {
	r := NewPkh()
	_, err := r.Resolve(context.Background(),
		"did:pkh:eip155:1:"+anvilAddress)
	if err == nil {
		t.Fatal("expected DID_PKH_CHAIN_NOT_CONFIGURED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_PKH_CHAIN_NOT_CONFIGURED" {
		t.Errorf("expected DID_PKH_CHAIN_NOT_CONFIGURED, got %v", err)
	}
}

func TestPkh_Resolve_BadAddressPropagates(t *testing.T) {
	r := NewPkh()
	_, err := r.Resolve(context.Background(),
		"did:pkh:eip155:1:not-hex")
	if err == nil {
		t.Fatal("expected DID_PKH_BAD_ADDRESS, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_PKH_BAD_ADDRESS" {
		t.Errorf("expected DID_PKH_BAD_ADDRESS, got %v", err)
	}
}

func TestPkh_Resolve_BadFormatPropagates(t *testing.T) {
	r := NewPkh()
	_, err := r.Resolve(context.Background(), "did:web:agent.example.com")
	if err == nil {
		t.Fatal("expected DID_BAD_FORMAT, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_BAD_FORMAT" {
		t.Errorf("expected DID_BAD_FORMAT, got %v", err)
	}
}

func TestPkh_Resolve_NonEip155NamespaceAcceptedLexically(t *testing.T) {
	// Solana-style account: did:pkh:solana:<chain-id>:<base58-address>.
	// The resolver does no per-namespace shape check beyond eip155
	// today; the chain resolver implementation owns that.
	r := NewPkh()
	_, err := r.Resolve(context.Background(),
		"did:pkh:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc6wjsmkddF:8FE27ioQh3T7o22QsYVT5Re8NhTiUuoBM5kbsW1ZqhB1")
	// Should fail with DID_PKH_CHAIN_NOT_CONFIGURED, not a parsing error,
	// because the namespace passes lexical validation.
	if err == nil {
		t.Fatal("expected DID_PKH_CHAIN_NOT_CONFIGURED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_PKH_CHAIN_NOT_CONFIGURED" {
		t.Errorf("non-eip155 namespace should pass lexical validation; got %v", err)
	}
}

// fakeChainResolver is a test double for the chain client. Mirrors
// the LEI resolver's fakeGLEIFClient pattern.
type fakeChainResolver struct {
	jwk []byte
	err error
}

func (f *fakeChainResolver) LookupKey(_ context.Context, _ CAIPAccount) ([]byte, error) {
	return f.jwk, f.err
}

func TestPkh_Resolve_HappyPath(t *testing.T) {
	fixed := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	jwk := []byte(`{"kty":"EC","crv":"secp256k1","x":"ANVIL-X","y":"ANVIL-Y"}`)
	r := NewPkh().
		WithClock(func() time.Time { return fixed }).
		WithChainResolver(&fakeChainResolver{jwk: jwk})

	claim, err := r.Resolve(context.Background(),
		"did:pkh:eip155:31337:"+anvilAddress)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if claim.AnchorType != domain.AnchorTypeDID {
		t.Errorf("AnchorType = %q", claim.AnchorType)
	}
	if claim.ResolvedID != "did:pkh:eip155:31337:"+anvilAddress {
		t.Errorf("ResolvedID = %q", claim.ResolvedID)
	}
	if string(claim.PublicKeyJWK) != string(jwk) {
		t.Errorf("PublicKeyJWK was mutated")
	}
	if !claim.IssuedAt.Equal(fixed) {
		t.Errorf("IssuedAt = %v", claim.IssuedAt)
	}
	if claim.ExpiresAt.Sub(claim.IssuedAt) != pkhFreshnessBudget {
		t.Errorf("ExpiresAt - IssuedAt = %v, want %v",
			claim.ExpiresAt.Sub(claim.IssuedAt), pkhFreshnessBudget)
	}
	if err := claim.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestPkh_Resolve_ChainLookupError(t *testing.T) {
	r := NewPkh().WithChainResolver(&fakeChainResolver{err: errors.New("rpc unavailable")})
	_, err := r.Resolve(context.Background(),
		"did:pkh:eip155:1:"+anvilAddress)
	if err == nil {
		t.Fatal("expected DID_PKH_CHAIN_LOOKUP_FAILED, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_PKH_CHAIN_LOOKUP_FAILED" {
		t.Errorf("expected DID_PKH_CHAIN_LOOKUP_FAILED, got %v", err)
	}
}

func TestPkh_Resolve_EmptyJWKReturned(t *testing.T) {
	r := NewPkh().WithChainResolver(&fakeChainResolver{jwk: nil})
	_, err := r.Resolve(context.Background(),
		"did:pkh:eip155:1:"+anvilAddress)
	if err == nil {
		t.Fatal("expected DID_PKH_NO_KEY, got nil")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_PKH_NO_KEY" {
		t.Errorf("expected DID_PKH_NO_KEY, got %v", err)
	}
}

func TestPkh_SupportedProfiles(t *testing.T) {
	got := NewPkh().SupportedProfiles()
	if len(got) != 1 || got[0] != PkhProfileID {
		t.Errorf("SupportedProfiles = %v", got)
	}
	if PkhProfileID != "0.B-did:pkh" {
		t.Errorf("PkhProfileID = %q", PkhProfileID)
	}
}

func TestCAIPAccount_String(t *testing.T) {
	a := CAIPAccount{Namespace: "eip155", Reference: "1", Address: anvilAddress}
	want := "eip155:1:" + anvilAddress
	if got := a.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
