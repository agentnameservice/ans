package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

func TestPublicKeyToVerificationLine_FormatAndRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	line, err := anscrypto.PublicKeyToVerificationLine("ans-test", &priv.PublicKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Use SplitN to prevent `+` chars in the base64 segment from
	// being misinterpreted as separators. Matches the reference
	// verifier's parser.
	parts := strings.SplitN(line, "+", 3)
	if len(parts) != 3 {
		t.Fatalf("parts: got %d, want 3", len(parts))
	}

	if parts[0] != "ans-test" {
		t.Errorf("origin: got %q", parts[0])
	}
	// keyhash = first 4 bytes of SHA-256(SPKI-DER) as big-endian uint32,
	// formatted as 8-char zero-padded lower-case hex.
	if len(parts[1]) != 8 {
		t.Errorf("keyhash length: got %d want 8", len(parts[1]))
	}

	// Cross-check the hash against the input key independently.
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	wantHash := fmt.Sprintf("%08x", binary.BigEndian.Uint32(sum[:4]))
	if parts[1] != wantHash {
		t.Errorf("keyhash: got %q want %q", parts[1], wantHash)
	}

	// Decode the third segment and verify the byte shape:
	// 0x02 || SPKI-DER.
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw) < 2 || raw[0] != 0x02 {
		t.Fatalf("first byte: got 0x%02x want 0x02 (ECDSA marker)", raw[0])
	}
	pub, err := x509.ParsePKIXPublicKey(raw[1:])
	if err != nil {
		t.Fatalf("parse SPKI from line: %v", err)
	}
	got, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("not an ECDSA key: %T", pub)
	}
	// Compare via marshalled DER — the raw big.Int coordinates are
	// deprecated and the standard library's recommended check is
	// byte-wise DER comparison, which is what we mirror.
	roundTripDER, _ := x509.MarshalPKIXPublicKey(got)
	origDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if string(roundTripDER) != string(origDER) {
		t.Error("round-trip key DER mismatch")
	}
}

func TestPublicKeyToVerificationLine_RejectsUnmarshalableKey(t *testing.T) {
	t.Parallel()
	// A zero-valued ECDSA public key has nil Curve; MarshalPKIXPublicKey
	// returns "unsupported elliptic curve" — the error path worth
	// covering to prove we surface marshal failures instead of panicking.
	bad := &ecdsa.PublicKey{}
	_, err := anscrypto.PublicKeyToVerificationLine("origin", bad)
	if err == nil {
		t.Fatal("expected error on empty ECDSA key")
	}
}

// TestParseVerificationLine_RoundTrip asserts that parsing the output
// of PublicKeyToVerificationLine returns an ECDSA key DER-identical
// to the input. This is the path /checkpoint's publicKeyPem wiring
// depends on (sumdb-note verifier string → ecdsa pub → PEM).
func TestParseVerificationLine_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	line, err := anscrypto.PublicKeyToVerificationLine("ans-test", &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := anscrypto.ParseVerificationLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gotECDSA, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", got)
	}
	origDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	gotDER, _ := x509.MarshalPKIXPublicKey(gotECDSA)
	if string(origDER) != string(gotDER) {
		t.Error("parsed ECDSA key DER does not match input")
	}
}

// TestParseVerificationLine_Ed25519 asserts that ed25519 verification
// lines (algorithm byte 0x01 — the sumdb default) parse back to an
// `ed25519.PublicKey`. The TL's primary signer uses this path.
func TestParseVerificationLine_Ed25519(t *testing.T) {
	t.Parallel()
	// Build a synthetic ed25519 verification line: origin+hash+base64(0x01||pub32).
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte{0x01}, pub...)
	line := fmt.Sprintf("ans-test+%08x+%s", uint32(0x12345678), base64.StdEncoding.EncodeToString(body))
	got, err := anscrypto.ParseVerificationLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gotEd, ok := got.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("want ed25519.PublicKey, got %T", got)
	}
	if !bytes.Equal(gotEd, pub) {
		t.Error("round-tripped ed25519 pub mismatch")
	}
}

// TestParseVerificationLine_RejectsMalformed covers every defensive
// branch in the parser: wrong segment count, non-base64 body, empty
// body, wrong-length ed25519 payload, unknown algorithm byte, and
// non-ECDSA SPKI smuggled in under the 0x02 marker.
func TestParseVerificationLine_RejectsMalformed(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"too-few-parts":        "origin+onlytwo",
		"not-base64":           "origin+12345678+not-base64!!!",
		"empty-body":           "origin+12345678+" + base64.StdEncoding.EncodeToString([]byte{}),
		"ed25519-wrong-length": "origin+12345678+" + base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}),
		"unknown-alg":          "origin+12345678+" + base64.StdEncoding.EncodeToString([]byte{0x99, 0x00}),
		"ecdsa-bad-spki":       "origin+12345678+" + base64.StdEncoding.EncodeToString([]byte{0x02, 0x00, 0x01, 0x02}),
	}
	for name, line := range cases {
		if _, err := anscrypto.ParseVerificationLine(line); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestPublicKeyPEM_RoundTrip asserts the helper emits a PEM block that
// x509 can parse back into the same key material.
func TestPublicKeyPEM_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, err := anscrypto.PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("missing PEM header: %q", pemStr)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	got, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	gotDER, _ := x509.MarshalPKIXPublicKey(got)
	origDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if string(gotDER) != string(origDER) {
		t.Error("PEM round-trip lost key material")
	}
}

// TestPublicKeyPEM_RejectsUnmarshalable covers the error path when the
// input isn't a key x509 can marshal.
func TestPublicKeyPEM_RejectsUnmarshalable(t *testing.T) {
	t.Parallel()
	if _, err := anscrypto.PublicKeyPEM(&ecdsa.PublicKey{}); err == nil {
		t.Fatal("expected error on empty ECDSA key")
	}
}
