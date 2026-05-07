package logstore_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/logstore"
)

// TestJWSCheckpointSigner_SignParsesAndMatches verifies that the
// signer's Sign() output is a well-formed compact JWS over a payload
// matching the reference's checkpoint JSON shape. This is the
// contract Tessera depends on: give a checkpoint body, get back
// compact-JWS bytes Tessera can base64-encode into the signature
// line.
func TestJWSCheckpointSigner_SignParsesAndMatches(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(ctx, "tl-attest", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}

	signer, err := logstore.NewJWSCheckpointSigner(ctx, km, "tl-attest", "ans-test")
	if err != nil {
		t.Fatal(err)
	}
	signer.WithClock(func() int64 { return 1_700_000_000 })

	// Mimic what Tessera hands to Sign(): a Tessera-format checkpoint
	// body (no trailing signature lines).
	body := []byte("ans-test\n42\nVN9ZqUqdHEvETuCuBIT/aLf3ZeFqPyI8UJGoIoxCTI0=\n\n")
	sigBytes, err := signer.Sign(body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jws := string(sigBytes)

	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("jws: got %d parts, want 3 (header.payload.signature)", len(parts))
	}

	// Decode header + payload and check the shape matches the
	// reference TL's `TesseraJWSSigner.SignTreeHead` output.
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if got, want := p["origin"], "ans-test"; got != want {
		t.Errorf("payload.origin: got %v want %v", got, want)
	}
	if got, want := p["checkpointFormat"], "c2sp/v1"; got != want {
		t.Errorf("payload.checkpointFormat: got %v want %v", got, want)
	}
	// treesize comes back as float64 after json.Unmarshal.
	if got, want := p["treesize"], float64(42); got != want {
		t.Errorf("payload.treesize: got %v want %v", got, want)
	}
	if got, want := p["rootHash"], "VN9ZqUqdHEvETuCuBIT/aLf3ZeFqPyI8UJGoIoxCTI0="; got != want {
		t.Errorf("payload.rootHash: got %v want %v", got, want)
	}
	if got, want := p["timestamp"], float64(1_700_000_000); got != want {
		t.Errorf("payload.timestamp: got %v want %v", got, want)
	}
}

// TestJWSCheckpointSigner_NameMatchesOrigin asserts that Name()
// equals the origin string — Tessera rejects signer/checkpoint
// origin mismatches at wire-up time, so the invariant matters.
func TestJWSCheckpointSigner_NameMatchesOrigin(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	km, _ := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	_, _ = km.EnsureKey(ctx, "k", port.AlgorithmECDSAP256)
	s, err := logstore.NewJWSCheckpointSigner(ctx, km, "k", "my-origin")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "my-origin" {
		t.Errorf("Name: got %q want my-origin", s.Name())
	}
	if s.KeyHash() == 0 {
		t.Error("KeyHash should be non-zero for a real P-256 key")
	}
}

// TestJWSCheckpointSigner_OriginMismatch asserts Sign rejects a
// body whose origin doesn't match the signer's configured origin.
// Not a Tessera-level concern in practice (Tessera only hands us
// bodies for the log it owns) but cheap to check and useful for
// defending against library misuse.
func TestJWSCheckpointSigner_OriginMismatch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	km, _ := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	_, _ = km.EnsureKey(ctx, "k", port.AlgorithmECDSAP256)
	s, _ := logstore.NewJWSCheckpointSigner(ctx, km, "k", "my-origin")
	body := []byte("other-origin\n1\nAAAA\n\n")
	if _, err := s.Sign(body); err == nil {
		t.Fatal("want error on origin mismatch")
	}
}
