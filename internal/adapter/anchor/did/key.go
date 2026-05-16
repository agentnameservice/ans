package did

// did:key resolution per the W3C did:key method specification
// (https://w3c-ccg.github.io/did-method-key/).
//
// did:key is the only DID method that requires no network call: the
// DID URI itself encodes the verification key. Resolution decodes
// the multibase-encoded suffix, validates the multicodec key-type
// prefix, and emits a JWK. This makes did:key the cheapest and most
// deterministic anchor profile to test against — every CI run
// produces identical results without external infrastructure.
//
// Currently supported key types (per the W3C method spec):
//   - Ed25519 (multicodec 0xED): 32-byte public key, JWK kty=OKP/crv=Ed25519.
//   - secp256k1 (multicodec 0xE7): 33-byte compressed public key, JWK kty=EC/crv=secp256k1.
//
// X25519 (0xEC) and P-256 (0x1200) are not yet supported; the
// resolver returns DID_KEY_TYPE_NOT_IMPLEMENTED for them. Adding
// them is mechanical: extend keyTypeFromMulticodec with the new
// codec and the conversion logic in keyToJWK. The two listed are the
// dominant types in production deployments today.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// KeyProfileID is the canonical identifier for did:key in the
// AnchorResolverRegistry advertised through SupportedProfiles().
const KeyProfileID = "0.B-did:key"

// keyFreshnessBudget is fixed at the resolver's clock precision for
// did:key: the DID is the key, so a "stale" claim is a contradiction
// in terms. The freshness budget is set to 24 hours to match did:web
// for cache-management consistency, but a verifier MAY treat did:key
// claims as never expiring.
const keyFreshnessBudget = 24 * time.Hour

// Key resolves did:key identifiers by decoding the multibase-encoded
// public key embedded in the DID itself. No HTTP, no chain, no
// directory lookup — the decode is the resolution.
type Key struct {
	clock func() time.Time
}

// NewKey constructs a Key resolver.
func NewKey() *Key {
	return &Key{clock: time.Now}
}

// WithClock returns a copy with a deterministic clock for tests.
func (k *Key) WithClock(clock func() time.Time) *Key {
	return &Key{clock: clock}
}

// SupportedProfiles satisfies port.AnchorResolver.
func (k *Key) SupportedProfiles() []string {
	return []string{KeyProfileID}
}

// Resolve decodes the input did:key URI to an IdentityClaim.
//
// Pipeline:
//  1. Lexical validation: did:key prefix; multibase prefix `z`
//     (base58btc).
//  2. Base58btc decode.
//  3. Multicodec varint decode → key-type code.
//  4. Validate the remaining bytes match the key type's expected
//     length.
//  5. JWK conversion per the key type.
//  6. Construct IdentityClaim.
func (k *Key) Resolve(_ context.Context, input string) (*domain.IdentityClaim, error) {
	suffix, err := parseDIDKey(input)
	if err != nil {
		return nil, err
	}
	keyBytes, err := decodeBase58btc(suffix)
	if err != nil {
		return nil, err
	}
	codec, body, err := decodeMulticodecVarint(keyBytes)
	if err != nil {
		return nil, err
	}
	jwk, err := keyToJWK(codec, body)
	if err != nil {
		return nil, err
	}
	now := k.clock().UTC()
	canonical := canonicalizeDIDKey(input)
	return &domain.IdentityClaim{
		AnchorType:   domain.AnchorTypeDID,
		ResolvedID:   canonical,
		PublicKeyJWK: jwk,
		IssuedAt:     now,
		ExpiresAt:    now.Add(keyFreshnessBudget),
	}, nil
}

// parseDIDKey strips did:key: prefix, validates the multibase prefix,
// returns the base58btc-encoded suffix.
func parseDIDKey(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if !strings.HasPrefix(trimmed, "did:key:") {
		return "", domain.NewValidationError(
			"DID_BAD_FORMAT",
			"expected did:key prefix",
		)
	}
	rest := strings.TrimPrefix(trimmed, "did:key:")
	if rest == "" {
		return "", domain.NewValidationError(
			"DID_BAD_FORMAT",
			"did:key URI missing identifier body",
		)
	}
	// Multibase prefix per IETF multibase: 'z' = base58btc, the only
	// shape the W3C did:key v0.7 spec emits.
	if rest[0] != 'z' {
		return "", domain.NewValidationError(
			"DID_KEY_BAD_MULTIBASE",
			fmt.Sprintf("expected base58btc multibase prefix 'z', got %q", rest[:1]),
		)
	}
	return rest[1:], nil
}

func canonicalizeDIDKey(input string) string {
	// The spec mandates no canonicalization beyond stripping fragment
	// (no fragments are admitted on did:key). Strip whitespace.
	return strings.TrimSpace(input)
}

// base58btcAlphabet matches the Bitcoin base58 alphabet exactly.
const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58btc decodes the input string to bytes per the Bitcoin
// base58 alphabet.
//
// Algorithm: accumulate the base-58 number into a math/big.Int, then
// extract big-endian bytes; preserve leading-zero handling by
// counting leading '1' characters in the input (each is a leading
// zero byte). math/big keeps the implementation short; performance
// is fine for the ≤80-byte payloads this profile produces.
func decodeBase58btc(s string) ([]byte, error) {
	if s == "" {
		return nil, domain.NewValidationError(
			"DID_KEY_DECODE",
			"base58btc input is empty",
		)
	}
	// Leading '1' characters in base58 represent leading zero bytes.
	leadingZeros := 0
	for i := range len(s) {
		if s[i] != '1' {
			break
		}
		leadingZeros++
	}
	num := big.NewInt(0)
	base := big.NewInt(58)
	for i := range len(s) {
		idx := strings.IndexByte(base58btcAlphabet, s[i])
		if idx < 0 {
			return nil, domain.NewValidationError(
				"DID_KEY_DECODE",
				fmt.Sprintf("invalid base58btc character %q at position %d", s[i], i),
			)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	body := num.Bytes()
	if leadingZeros == 0 {
		return body, nil
	}
	out := make([]byte, leadingZeros+len(body))
	copy(out[leadingZeros:], body)
	return out, nil
}

// decodeMulticodecVarint reads an unsigned LEB128 varint from the
// front of buf and returns (code, remainingBytes). The varint
// identifies the multicodec key type per
// https://github.com/multiformats/multicodec.
func decodeMulticodecVarint(buf []byte) (uint64, []byte, error) {
	var code uint64
	var shift uint
	for i, b := range buf {
		code |= uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			return code, buf[i+1:], nil
		}
		if shift >= 64 {
			return 0, nil, domain.NewValidationError(
				"DID_KEY_DECODE",
				"multicodec varint overflow",
			)
		}
	}
	return 0, nil, domain.NewValidationError(
		"DID_KEY_DECODE",
		"multicodec varint truncated",
	)
}

// keyToJWK converts a multicodec key (code + body bytes) into a JWK.
// Returned bytes are the canonical (sorted-key) JSON encoding so the
// hash chain stays deterministic.
func keyToJWK(code uint64, body []byte) ([]byte, error) {
	switch code {
	case 0xED: // Ed25519
		if len(body) != 32 {
			return nil, domain.NewValidationError(
				"DID_KEY_BAD_LENGTH",
				fmt.Sprintf("Ed25519 public key MUST be 32 bytes, got %d", len(body)),
			)
		}
		jwk := map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(body),
		}
		return marshalJWK(jwk)
	case 0xE7: // secp256k1 compressed
		if len(body) != 33 {
			return nil, domain.NewValidationError(
				"DID_KEY_BAD_LENGTH",
				fmt.Sprintf("secp256k1 public key MUST be 33 bytes (compressed form), got %d", len(body)),
			)
		}
		x, y, err := decompressSecp256k1(body)
		if err != nil {
			return nil, err
		}
		jwk := map[string]string{
			"kty": "EC",
			"crv": "secp256k1",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}
		return marshalJWK(jwk)
	case 0xEC: // X25519
		return nil, domain.NewValidationError(
			"DID_KEY_TYPE_NOT_IMPLEMENTED",
			"X25519 (multicodec 0xEC) decoding is not yet implemented in this resolver",
		)
	case 0x1200: // P-256
		return nil, domain.NewValidationError(
			"DID_KEY_TYPE_NOT_IMPLEMENTED",
			"P-256 (multicodec 0x1200) decoding is not yet implemented in this resolver",
		)
	default:
		return nil, domain.NewValidationError(
			"DID_KEY_TYPE_UNKNOWN",
			fmt.Sprintf("unknown multicodec key type 0x%X", code),
		)
	}
}

// marshalJWK emits a JSON object in canonical (sorted-key) order so
// downstream hashing is deterministic. Map iteration in Go is random;
// json.Marshal on a map sorts keys, which is exactly what we want.
func marshalJWK(jwk map[string]string) ([]byte, error) {
	// Convert to map[string]any so json.Marshal sees it as an object
	// not specific to string-only values; it preserves alphabetical
	// key order regardless.
	out, err := json.Marshal(jwk)
	if err != nil {
		return nil, domain.NewInternalError("DID_KEY_MARSHAL", "marshal JWK", err)
	}
	return out, nil
}

// decompressSecp256k1 decodes a 33-byte compressed point into raw
// big-endian X and Y coordinate byte slices.
//
// The compressed format per SEC 1 §2.3.3:
//   - Byte 0: 0x02 (y is even) or 0x03 (y is odd).
//   - Bytes 1..32: X coordinate, big-endian.
//
// Y is computed as the modular square root of (x³ + ax + b) mod p
// where (a, b, p) are the secp256k1 curve parameters. Since this
// resolver only emits the JWK for use in higher-spec verification
// rather than performing ECDSA itself, full point validation is not
// strictly required at the resolver layer; the simpler compressed-
// form check below catches malformed input. Point-on-curve validation
// should run in the Layer 1 cert-validator path before any signature
// is trusted.
func decompressSecp256k1(body []byte) ([]byte, []byte, error) {
	if body[0] != 0x02 && body[0] != 0x03 {
		return nil, nil, domain.NewValidationError(
			"DID_KEY_DECODE",
			fmt.Sprintf("secp256k1 compressed point MUST start with 0x02 or 0x03, got 0x%X", body[0]),
		)
	}
	x := body[1:]
	// secp256k1 curve parameters.
	// p = 2^256 - 2^32 - 977
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	// a = 0, b = 7 for secp256k1.
	b := big.NewInt(7)

	xBig := new(big.Int).SetBytes(x)
	// y^2 = x^3 + b mod p (a=0)
	rhs := new(big.Int).Exp(xBig, big.NewInt(3), p)
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)
	// Compute y = sqrt(rhs) mod p using Tonelli-Shanks. For secp256k1's
	// p ≡ 3 (mod 4), the square root is rhs^((p+1)/4) mod p.
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(rhs, exp, p)
	// Pick the parity matching the compressed form's leading byte.
	if (y.Bit(0) == 1) != (body[0] == 0x03) {
		y.Sub(p, y)
		y.Mod(y, p)
	}
	yBytes := y.Bytes()
	// Pad y to 32 bytes (big-endian) so JWK x and y are uniform width.
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}
	return x, yBytes, nil
}
