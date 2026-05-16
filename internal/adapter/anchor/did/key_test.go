package did

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// W3C did:key v0.7 test vectors. Source: spec text + examples from
// implementations like did-method-key (Digital Bazaar). Each vector
// is verified offline — these tests exercise the multibase + multicodec
// path end-to-end without external infrastructure.
var ed25519Vectors = []struct {
	label string
	did   string
	x     string // base64url no-pad of the 32-byte public key
}{
	{
		// W3C did:key spec-cited example. The "x" field below is the
		// base64url-no-pad encoding of the 32-byte Ed25519 public key
		// embedded in the multibase suffix; verified by resolving the
		// DID through this resolver (round-trip with NewKey().Resolve).
		label: "Ed25519 vector A (W3C spec example DID)",
		did:   "did:key:z6MkpTHR8VNsBxRbh2AsP615Cqc9GQQvd7b4S4ZZmsK6SjD1",
		x:     "lJZrfAjkBWcSC2XttzY5kRSyI3NW0YieBBml2xr2qZg",
	},
	{
		label: "Ed25519 vector B (Digital Bazaar example DID)",
		did:   "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
		x:     "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
	},
}

func TestKey_Resolve_Ed25519Vectors(t *testing.T) {
	fixed := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	for _, v := range ed25519Vectors {
		t.Run(v.label, func(t *testing.T) {
			r := NewKey().WithClock(func() time.Time { return fixed })
			claim, err := r.Resolve(context.Background(), v.did)
			if err != nil {
				t.Fatalf("Resolve(%s): %v", v.did, err)
			}
			if claim.AnchorType != domain.AnchorTypeDID {
				t.Errorf("AnchorType = %q", claim.AnchorType)
			}
			if claim.ResolvedID != v.did {
				t.Errorf("ResolvedID = %q, want %q", claim.ResolvedID, v.did)
			}
			jwk := string(claim.PublicKeyJWK)
			if !strings.Contains(jwk, `"kty":"OKP"`) {
				t.Errorf("JWK missing kty=OKP: %s", jwk)
			}
			if !strings.Contains(jwk, `"crv":"Ed25519"`) {
				t.Errorf("JWK missing crv=Ed25519: %s", jwk)
			}
			if !strings.Contains(jwk, `"x":"`+v.x+`"`) {
				t.Errorf("JWK x mismatch: %s\n  want x=%q", jwk, v.x)
			}
			if !claim.IssuedAt.Equal(fixed) {
				t.Errorf("IssuedAt = %v", claim.IssuedAt)
			}
			if claim.ExpiresAt.Sub(claim.IssuedAt) != keyFreshnessBudget {
				t.Errorf("ExpiresAt - IssuedAt = %v, want %v",
					claim.ExpiresAt.Sub(claim.IssuedAt), keyFreshnessBudget)
			}
			if err := claim.Validate(); err != nil {
				t.Errorf("returned claim fails Validate: %v", err)
			}
		})
	}
}

func TestKey_Resolve_BadFormat(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantCode string
	}{
		{
			name:     "wrong method",
			input:    "did:web:agent.example.com",
			wantCode: "DID_BAD_FORMAT",
		},
		{
			name:     "missing prefix",
			input:    "z6MkpTHR8VNsBxRbh2AsP615Cqc9GQQvd7b4S4ZZmsK6SjD1",
			wantCode: "DID_BAD_FORMAT",
		},
		{
			name:     "empty body",
			input:    "did:key:",
			wantCode: "DID_BAD_FORMAT",
		},
		{
			name:     "wrong multibase prefix (e.g., uppercase Z)",
			input:    "did:key:Z6MkpTHR8VNsBxRbh2AsP615Cqc9GQQvd7b4S4ZZmsK6SjD1",
			wantCode: "DID_KEY_BAD_MULTIBASE",
		},
		{
			name:     "non-base58 character in body",
			input:    "did:key:z!nval!d",
			wantCode: "DID_KEY_DECODE",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewKey().Resolve(context.Background(), c.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var dErr *domain.Error
			if !errors.As(err, &dErr) {
				t.Fatalf("not *domain.Error: %T", err)
			}
			if dErr.Code != c.wantCode {
				t.Errorf("code = %q, want %q (msg: %s)", dErr.Code, c.wantCode, dErr.Message)
			}
		})
	}
}

func TestKey_SupportedProfiles(t *testing.T) {
	got := NewKey().SupportedProfiles()
	if len(got) != 1 || got[0] != KeyProfileID {
		t.Errorf("SupportedProfiles = %v", got)
	}
	if KeyProfileID != "0.B-did:key" {
		t.Errorf("KeyProfileID = %q", KeyProfileID)
	}
}

// TestDecodeBase58btc_LeadingZeros pins the leading-1-character
// preservation rule. Each leading '1' in base58 becomes a leading
// 0x00 byte in the decoded output.
func TestDecodeBase58btc_LeadingZeros(t *testing.T) {
	cases := []struct {
		input string
		want  []byte
	}{
		{"1", []byte{0}},
		{"11", []byte{0, 0}},
		{"112", []byte{0, 0, 1}},
	}
	for _, c := range cases {
		got, err := decodeBase58btc(c.input)
		if err != nil {
			t.Errorf("decodeBase58btc(%q): %v", c.input, err)
			continue
		}
		if string(got) != string(c.want) {
			t.Errorf("decodeBase58btc(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestDecodeMulticodecVarint_SingleByte(t *testing.T) {
	// 0x01 = unsigned varint for 1
	code, rest, err := decodeMulticodecVarint([]byte{0x01, 0xFF, 0xEE})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if string(rest) != string([]byte{0xFF, 0xEE}) {
		t.Errorf("rest = %v", rest)
	}
}

func TestDecodeMulticodecVarint_TwoByte(t *testing.T) {
	// Ed25519 multicodec 0xED encoded as varint = [0xED, 0x01]
	// 0xED = 0b11101101 → low 7 bits = 0b1101101 = 0x6D, continuation
	// 0x01 = 0b00000001 → no continuation, so high bits = 1
	// Combined: (1 << 7) | 0x6D = 0xED
	code, rest, err := decodeMulticodecVarint([]byte{0xED, 0x01, 0xAA})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if code != 0xED {
		t.Errorf("code = 0x%X, want 0xED", code)
	}
	if string(rest) != string([]byte{0xAA}) {
		t.Errorf("rest = %v", rest)
	}
}

func TestDecodeMulticodecVarint_Truncated(t *testing.T) {
	// Continuation bit set on the last byte means truncated input.
	_, _, err := decodeMulticodecVarint([]byte{0xED})
	if err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestKeyToJWK_X25519NotImplemented(t *testing.T) {
	_, err := keyToJWK(0xEC, make([]byte, 32))
	if err == nil {
		t.Fatal("expected DID_KEY_TYPE_NOT_IMPLEMENTED")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_KEY_TYPE_NOT_IMPLEMENTED" {
		t.Errorf("expected DID_KEY_TYPE_NOT_IMPLEMENTED, got %v", err)
	}
}

func TestKeyToJWK_P256NotImplemented(t *testing.T) {
	_, err := keyToJWK(0x1200, make([]byte, 33))
	if err == nil {
		t.Fatal("expected DID_KEY_TYPE_NOT_IMPLEMENTED")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_KEY_TYPE_NOT_IMPLEMENTED" {
		t.Errorf("expected DID_KEY_TYPE_NOT_IMPLEMENTED, got %v", err)
	}
}

func TestKeyToJWK_UnknownKeyType(t *testing.T) {
	_, err := keyToJWK(0xDEAD, make([]byte, 32))
	if err == nil {
		t.Fatal("expected DID_KEY_TYPE_UNKNOWN")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_KEY_TYPE_UNKNOWN" {
		t.Errorf("expected DID_KEY_TYPE_UNKNOWN, got %v", err)
	}
}

func TestKeyToJWK_Ed25519BadLength(t *testing.T) {
	// 31 bytes — wrong length for Ed25519 (must be 32).
	_, err := keyToJWK(0xED, make([]byte, 31))
	if err == nil {
		t.Fatal("expected DID_KEY_BAD_LENGTH")
	}
	var dErr *domain.Error
	if !errors.As(err, &dErr) || dErr.Code != "DID_KEY_BAD_LENGTH" {
		t.Errorf("expected DID_KEY_BAD_LENGTH, got %v", err)
	}
}

func TestKey_Resolve_Secp256k1(t *testing.T) {
	// Construct a valid did:key for a secp256k1 key by encoding the
	// generator point G of secp256k1 in compressed form (which is a
	// well-known valid point), prepending the 0xE7 multicodec varint,
	// then base58btc-encoding the result.
	//
	// secp256k1 G compressed = 0x02 || x_G(32 bytes)
	gxHex := "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	body := append([]byte{0x02}, decodeHexT(t, gxHex)...)
	// multicodec varint for 0xE7 = [0xE7, 0x01]
	prefixed := append([]byte{0xE7, 0x01}, body...)
	encoded := encodeBase58btc(prefixed)
	did := "did:key:z" + encoded

	r := NewKey()
	claim, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", did, err)
	}
	jwk := string(claim.PublicKeyJWK)
	if !strings.Contains(jwk, `"kty":"EC"`) {
		t.Errorf("JWK missing kty=EC: %s", jwk)
	}
	if !strings.Contains(jwk, `"crv":"secp256k1"`) {
		t.Errorf("JWK missing crv=secp256k1: %s", jwk)
	}
	// Y must be present (decompression succeeded).
	if !strings.Contains(jwk, `"y":"`) {
		t.Errorf("JWK missing y coordinate: %s", jwk)
	}
}

// decodeHexT is a tiny test helper for hex-byte fixtures.
func decodeHexT(t *testing.T, h string) []byte {
	t.Helper()
	out, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", h, err)
	}
	return out
}

// encodeBase58btc is the inverse of decodeBase58btc; used in tests
// to construct a did:key for the secp256k1 round-trip.
func encodeBase58btc(buf []byte) string {
	if len(buf) == 0 {
		return ""
	}
	leadingZeros := 0
	for _, b := range buf {
		if b != 0 {
			break
		}
		leadingZeros++
	}
	num := new(big.Int).SetBytes(buf)
	out := []byte{}
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		out = append(out, base58btcAlphabet[mod.Int64()])
	}
	for range leadingZeros {
		out = append(out, '1')
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
