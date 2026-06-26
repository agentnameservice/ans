package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// This file holds the JWK / multibase key plumbing for the Verified
// Identities control proofs.
//
// Key-type allowlist: everything the JWS layer can honestly verify —
// Ed25519 (EdDSA), ECDSA P-256 (ES256), and RSA ≥ 2048 (RS256).
// Anything else is rejected with a *precise* error rather than a
// generic one: X25519 is a key-agreement key and can never sign;
// secp256k1 (ES256K) and the larger NIST curves have no verifier in
// this codebase. Admitting a new type means adding its verification
// arm in jws.go first — the allowlist here only names what that
// layer supports.

// ErrJWK classifies JWK parse/validation failures.
var ErrJWK = errors.New("crypto/jwk: invalid JWK")

// jwkFields is the wire shape of the JWK subset we accept.
type jwkFields struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ParseJWK parses a JWK into a verifying public key:
//
//	kty=EC,  crv=P-256   → *ecdsa.PublicKey  (ES256)
//	kty=OKP, crv=Ed25519 → ed25519.PublicKey (EdDSA)
//	kty=RSA              → *rsa.PublicKey    (RS256; CheckKeyStrength enforced)
//
// Everything else fails with a message naming exactly why.
func ParseJWK(raw json.RawMessage) (any, error) {
	var f jwkFields
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWK, err)
	}
	switch f.Kty {
	case "EC":
		return parseECJWK(f)
	case "OKP":
		return parseOKPJWK(f)
	case "RSA":
		return parseRSAJWK(f)
	default:
		return nil, fmt.Errorf("%w: unsupported kty %q (supported: EC/P-256, OKP/Ed25519, RSA)", ErrJWK, f.Kty)
	}
}

func parseECJWK(f jwkFields) (*ecdsa.PublicKey, error) {
	if f.Crv != "P-256" {
		return nil, fmt.Errorf("%w: EC curve %q has no verifier here (supported: P-256)", ErrJWK, f.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(f.X)
	if err != nil {
		return nil, fmt.Errorf("%w: decode x: %w", ErrJWK, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(f.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: decode y: %w", ErrJWK, err)
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: P-256 coordinates must be 32 bytes", ErrJWK)
	}
	// 0x04 || X || Y is the uncompressed SEC1 form;
	// ParseUncompressedPublicKey performs the on-curve check.
	point := make([]byte, 0, 65)
	point = append(point, 0x04)
	point = append(point, x...)
	point = append(point, y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWK, err)
	}
	return pub, nil
}

func parseOKPJWK(f jwkFields) (ed25519.PublicKey, error) {
	switch f.Crv {
	case "Ed25519":
		x, err := base64.RawURLEncoding.DecodeString(f.X)
		if err != nil {
			return nil, fmt.Errorf("%w: decode x: %w", ErrJWK, err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 key must be %d bytes", ErrJWK, ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil
	case "X25519":
		return nil, fmt.Errorf("%w: X25519 is a key-agreement key, not a signing key — it cannot prove control", ErrJWK)
	default:
		return nil, fmt.Errorf("%w: unsupported OKP curve %q (supported: Ed25519)", ErrJWK, f.Crv)
	}
}

func parseRSAJWK(f jwkFields) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(f.N)
	if err != nil {
		return nil, fmt.Errorf("%w: decode n: %w", ErrJWK, err)
	}
	e, err := base64.RawURLEncoding.DecodeString(f.E)
	if err != nil {
		return nil, fmt.Errorf("%w: decode e: %w", ErrJWK, err)
	}
	if len(n) == 0 || len(e) == 0 || len(e) > 8 {
		return nil, fmt.Errorf("%w: RSA JWK requires n and a small e", ErrJWK)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}
	if err := CheckKeyStrength(pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWK, err)
	}
	return pub, nil
}

// PublicKeyToJWK renders a supported public key as a JWK. Used by
// registrant-side tooling (the demo signer's embedded `jwk` header)
// and tests — never by sealing, which quotes the DID document's
// verification method verbatim instead of re-encoding anything.
func PublicKeyToJWK(pub any) (json.RawMessage, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		x, y, err := p256Coordinates(key)
		if err != nil {
			return nil, err
		}
		return marshalJWK(map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(x),
			"y": base64.RawURLEncoding.EncodeToString(y),
		})
	case ed25519.PublicKey:
		return marshalJWK(map[string]string{
			"kty": "OKP", "crv": "Ed25519",
			"x": base64.RawURLEncoding.EncodeToString(key),
		})
	case *rsa.PublicKey:
		return marshalJWK(map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		})
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrJWK, pub)
	}
}

func marshalJWK(members map[string]string) (json.RawMessage, error) {
	raw, err := json.Marshal(members)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWK, err)
	}
	return raw, nil
}

// p256Coordinates extracts the 32-byte X and Y coordinates from a
// P-256 public key via its uncompressed SEC1 encoding (the
// non-deprecated accessor path).
func p256Coordinates(pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, nil, fmt.Errorf("%w: not a P-256 key", ErrJWK)
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrJWK, err)
	}
	if len(point) != 65 || point[0] != 0x04 {
		return nil, nil, fmt.Errorf("%w: unexpected SEC1 encoding", ErrJWK)
	}
	return point[1:33], point[33:65], nil
}

// Multicodec prefixes (unsigned varint encoding) for the key types
// did:key and Multikey carry. ed25519-pub is code 0xed → varint
// {0xed, 0x01}; p256-pub is code 0x1200 → varint {0x80, 0x24}.
const (
	multicodecEd25519Hi = 0xed
	multicodecEd25519Lo = 0x01
	multicodecP256Hi    = 0x80
	multicodecP256Lo    = 0x24
)

// DecodeMultibase decodes a multibase-encoded public key (a did:key
// method-specific id or a DID document's publicKeyMultibase) into a
// verifying key. Only base58btc ('z' prefix) is accepted — the
// encoding both specs mandate. Supported multicodecs: ed25519-pub
// and p256-pub; others fail with the prefix named.
func DecodeMultibase(encoded string) (any, error) {
	if !strings.HasPrefix(encoded, "z") {
		return nil, fmt.Errorf("%w: multibase key must be base58btc ('z' prefix)", ErrJWK)
	}
	raw, err := base58Decode(encoded[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWK, err)
	}
	if len(raw) <= 2 {
		return nil, fmt.Errorf("%w: multibase payload too short", ErrJWK)
	}
	switch {
	case raw[0] == multicodecEd25519Hi && raw[1] == multicodecEd25519Lo:
		key := raw[2:]
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: ed25519-pub key must be %d bytes, got %d", ErrJWK, ed25519.PublicKeySize, len(key))
		}
		return ed25519.PublicKey(key), nil
	case raw[0] == multicodecP256Hi && raw[1] == multicodecP256Lo:
		key := raw[2:]
		if len(key) != 33 {
			return nil, fmt.Errorf("%w: p256-pub key must be 33 compressed bytes, got %d", ErrJWK, len(key))
		}
		// SAFETY: elliptic.UnmarshalCompressed is the only stdlib
		// decoder for compressed SEC1 points (crypto/ecdh and
		// ecdsa.ParseUncompressedPublicKey accept uncompressed
		// only). It validates on-curve internally and returns nil
		// on malformed input; we immediately re-encode to the
		// uncompressed form and round-trip through the supported
		// parser so the deprecated surface stays contained here.
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
		if x == nil {
			return nil, fmt.Errorf("%w: invalid compressed P-256 point", ErrJWK)
		}
		point := make([]byte, 0, 65)
		point = append(point, 0x04)
		point = append(point, x.FillBytes(make([]byte, 32))...)
		point = append(point, y.FillBytes(make([]byte, 32))...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWK, err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%w: unsupported multicodec prefix 0x%02x%02x (supported: ed25519-pub, p256-pub)", ErrJWK, raw[0], raw[1])
	}
}

// EncodeMultibase renders a supported public key in the did:key /
// Multikey form: 'z' + base58btc(multicodec varint || key bytes).
// The inverse of DecodeMultibase; used by tooling that mints did:key
// identifiers.
func EncodeMultibase(pub any) (string, error) {
	switch key := pub.(type) {
	case ed25519.PublicKey:
		payload := make([]byte, 0, 2+len(key))
		payload = append(payload, multicodecEd25519Hi, multicodecEd25519Lo)
		payload = append(payload, key...)
		return "z" + base58Encode(payload), nil
	case *ecdsa.PublicKey:
		x, y, err := p256Coordinates(key)
		if err != nil {
			return "", err
		}
		// SAFETY: see DecodeMultibase — MarshalCompressed is the only
		// stdlib encoder for compressed SEC1 points.
		compressed := elliptic.MarshalCompressed(
			elliptic.P256(), new(big.Int).SetBytes(x), new(big.Int).SetBytes(y))
		payload := make([]byte, 0, 2+len(compressed))
		payload = append(payload, multicodecP256Hi, multicodecP256Lo)
		payload = append(payload, compressed...)
		return "z" + base58Encode(payload), nil
	default:
		return "", fmt.Errorf("%w: unsupported public key type %T", ErrJWK, pub)
	}
}

// DecodeDIDKey decodes a did:key identifier into its public key and
// the verification-method id the did:key method defines
// ("{did}#{method-specific-id}").
func DecodeDIDKey(did string) (any, string, error) {
	msid, ok := strings.CutPrefix(did, "did:key:")
	if !ok || msid == "" {
		return nil, "", fmt.Errorf("%w: not a did:key identifier", ErrJWK)
	}
	pub, err := DecodeMultibase(msid)
	if err != nil {
		return nil, "", err
	}
	return pub, did + "#" + msid, nil
}

// base58Alphabet is the Bitcoin base58 alphabet, the one multibase
// 'z' (base58btc) uses.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Decode decodes a base58btc string. Hand-rolled (~30 lines)
// rather than importing the multiformats stack for one codec.
func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base58 input")
	}
	radix := big.NewInt(58)
	n := new(big.Int)
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", r)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}
	var out []byte
	if n.Sign() > 0 {
		out = n.Bytes()
	}
	// Leading '1's encode leading zero bytes.
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		out = append([]byte{0x00}, out...)
	}
	return out, nil
}

// base58Encode encodes bytes as base58btc.
func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append([]byte{base58Alphabet[mod.Int64()]}, out...)
	}
	for i := 0; i < len(b) && b[i] == 0x00; i++ {
		out = append([]byte{'1'}, out...)
	}
	return string(out)
}
