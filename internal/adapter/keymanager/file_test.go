package keymanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/port"
)

// newKM returns a FileKeyManager rooted in a fresh temp directory.
func newKM(t *testing.T) *FileKeyManager {
	t.Helper()
	km, err := NewFileKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return km
}

// ----- Constructor -----

func TestNewFileKeyManager_FailsOnUnwritableDir(t *testing.T) {
	// Create a file, then try to use it as a key directory.
	f, err := os.CreateTemp(t.TempDir(), "not-a-dir")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_, err = NewFileKeyManager(f.Name())
	if err == nil {
		t.Error("expected error when dir path is actually a file")
	}
}

// ----- EnsureKey -----

func TestEnsureKey_CreatesThenReuses(t *testing.T) {
	km := newKM(t)
	ctx := context.Background()

	id1, err := km.EnsureKey(ctx, "my-key", port.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	id2, err := km.EnsureKey(ctx, "my-key", port.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if id1 != id2 || id1 != "my-key" {
		t.Errorf("ensure did not reuse key: %q vs %q", id1, id2)
	}
}

func TestEnsureKey_PropagatesLoadErrors(t *testing.T) {
	km := newKM(t)
	// Pre-create a malformed key file so EnsureKey's loadLocked returns
	// a non-NotFound error.
	path := filepath.Join(km.dir, "broken.key")
	if err := os.WriteFile(path, []byte("definitely not a PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := km.EnsureKey(context.Background(), "broken", port.AlgorithmECDSAP256)
	if err == nil {
		t.Fatal("expected error on malformed PEM")
	}
}

// ----- CreateKey + Sign + Verify + GetPublicKey round-trip -----

func TestCreateKey_RoundTripES256(t *testing.T) {
	km := newKM(t)
	ctx := context.Background()
	id, err := km.CreateKey(ctx, port.AlgorithmECDSAP256)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	digest := sha256.Sum256([]byte("hello"))
	sig, err := km.Sign(ctx, id, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := km.Verify(ctx, id, digest[:], sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("verify returned false for a self-signed signature")
	}
	pub, err := km.GetPublicKey(ctx, id)
	if err != nil {
		t.Fatalf("get pub: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("pub wrong type: %T", pub)
	}
}

func TestCreateKey_RoundTripRS256(t *testing.T) {
	km := newKM(t)
	ctx := context.Background()
	id, err := km.CreateKey(ctx, port.AlgorithmRSA2048)
	if err != nil {
		t.Fatalf("create rsa: %v", err)
	}
	digest := sha256.Sum256([]byte("msg"))
	sig, err := km.Sign(ctx, id, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := km.Verify(ctx, id, digest[:], sig)
	if err != nil || !ok {
		t.Errorf("verify rsa: ok=%v err=%v", ok, err)
	}
}

func TestCreateKey_EmptyAlgorithmDefaultsToECDSAP256(t *testing.T) {
	km := newKM(t)
	id, err := km.CreateKey(context.Background(), "")
	if err != nil {
		t.Fatalf("create with empty alg: %v", err)
	}
	pub, _ := km.GetPublicKey(context.Background(), id)
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA default, got %T", pub)
	}
	if ec.Curve != elliptic.P256() {
		t.Errorf("expected P-256, got %s", ec.Curve.Params().Name)
	}
}

func TestCreateKey_UnsupportedAlgorithm(t *testing.T) {
	km := newKM(t)
	_, err := km.CreateKey(context.Background(), "magic")
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("want ErrUnsupportedAlgorithm, got %v", err)
	}
}

// ----- Verify failure paths -----

func TestVerify_WrongSignature(t *testing.T) {
	km := newKM(t)
	id, _ := km.CreateKey(context.Background(), port.AlgorithmECDSAP256)
	digest := sha256.Sum256([]byte("a"))
	ok, err := km.Verify(context.Background(), id, digest[:], []byte("not a sig"))
	if err != nil {
		t.Errorf("verify should not error on bad sig: %v", err)
	}
	if ok {
		t.Error("verify should return false for garbage signature")
	}
}

func TestVerify_WrongMessage(t *testing.T) {
	km := newKM(t)
	id, _ := km.CreateKey(context.Background(), port.AlgorithmRSA2048)
	digest := sha256.Sum256([]byte("signed"))
	sig, _ := km.Sign(context.Background(), id, digest[:])
	wrongDigest := sha256.Sum256([]byte("different"))
	ok, _ := km.Verify(context.Background(), id, wrongDigest[:], sig)
	if ok {
		t.Error("verify should return false for sig over different message")
	}
}

// ----- Load failures -----

func TestSign_UnknownKey(t *testing.T) {
	km := newKM(t)
	_, err := km.Sign(context.Background(), "does-not-exist", []byte("d"))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

func TestVerify_UnknownKey(t *testing.T) {
	km := newKM(t)
	_, err := km.Verify(context.Background(), "does-not-exist", []byte("d"), []byte("s"))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

func TestGetPublicKey_UnknownKey(t *testing.T) {
	km := newKM(t)
	_, err := km.GetPublicKey(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("want ErrKeyNotFound, got %v", err)
	}
}

func TestLoadSigner_BadPEM(t *testing.T) {
	km := newKM(t)
	// Write a .key file with content that isn't a PRIVATE KEY PEM.
	if err := os.WriteFile(filepath.Join(km.dir, "garbage.key"), []byte("not a PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := km.GetPublicKey(context.Background(), "garbage")
	if err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("want PEM error, got %v", err)
	}
}

func TestLoadSigner_PEMButNotPKCS8(t *testing.T) {
	km := newKM(t)
	// Emit a PRIVATE KEY block with junk bytes — decodes but ParsePKCS8 fails.
	bad := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x00, 0x01}})
	if err := os.WriteFile(filepath.Join(km.dir, "notpkcs8.key"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := km.GetPublicKey(context.Background(), "notpkcs8")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("want parse error, got %v", err)
	}
}

// ----- ListKeys -----

func TestListKeys(t *testing.T) {
	km := newKM(t)
	ctx := context.Background()
	_, _ = km.CreateKey(ctx, port.AlgorithmECDSAP256)
	_, _ = km.CreateKey(ctx, port.AlgorithmECDSAP256)
	// Drop a non-.key file to confirm it's filtered out.
	if err := os.WriteFile(filepath.Join(km.dir, "readme.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	// And a directory to confirm IsDir filter.
	if err := os.Mkdir(filepath.Join(km.dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}

	ids, err := km.ListKeys(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("list: got %d keys (%v), want 2", len(ids), ids)
	}
}

func TestListKeys_ReadDirError(t *testing.T) {
	// Construct a KM and then remove its directory so ReadDir fails.
	dir := t.TempDir() + "/sub"
	km, err := NewFileKeyManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := km.ListKeys(context.Background()); err == nil {
		t.Error("expected ReadDir error")
	}
}

// ----- P-384 algorithm (covers AlgorithmECDSAP384 branch) -----

func TestCreateKey_P384(t *testing.T) {
	km := newKM(t)
	id, err := km.CreateKey(context.Background(), port.AlgorithmECDSAP384)
	if err != nil {
		t.Fatalf("create p-384: %v", err)
	}
	pub, _ := km.GetPublicKey(context.Background(), id)
	ec := pub.(*ecdsa.PublicKey)
	if ec.Curve.Params().BitSize != 384 {
		t.Errorf("expected P-384, got %d-bit curve", ec.Curve.Params().BitSize)
	}
}

// ----- CreateKey conflict -----

func TestEnsureKey_DetectsExistingFileCollision(t *testing.T) {
	km := newKM(t)
	// Manually place a .key file so createLocked's stat check triggers
	// ErrKeyExists when EnsureKey's loadLocked fails (it will fail
	// because the file isn't a valid PEM).
	//
	// We can't cleanly invoke createLocked directly from outside the
	// package, but EnsureKey → loadLocked sees a non-PEM file and
	// returns a wrapped error; so this test just confirms the error
	// path propagates.
	path := filepath.Join(km.dir, "conflict.key")
	_ = os.WriteFile(path, []byte("junk"), 0o600)
	_, err := km.EnsureKey(context.Background(), "conflict", port.AlgorithmECDSAP256)
	if err == nil {
		t.Error("expected error on malformed pre-existing key")
	}
}

// ----- KeyFingerprint + PublicKeyToPEM -----

func TestKeyFingerprint(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fp := KeyFingerprint(&k.PublicKey)
	if len(fp) != 16 {
		t.Errorf("fingerprint: got %q len=%d, want 16 chars (8 bytes hex)", fp, len(fp))
	}
	if fp == "unknown" {
		t.Error("valid key shouldn't return 'unknown'")
	}
}

func TestKeyFingerprint_UnsupportedKey(t *testing.T) {
	if got := KeyFingerprint("not a key"); got != "unknown" {
		t.Errorf("unsupported input: got %q, want 'unknown'", got)
	}
}

func TestPublicKeyToPEM_RoundTrip(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p, err := PublicKeyToPEM(&k.PublicKey)
	if err != nil {
		t.Fatalf("to pem: %v", err)
	}
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Errorf("block: %#v", block)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("parse: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("wrong type: %T", pub)
	}
}

func TestPublicKeyToPEM_UnsupportedKey(t *testing.T) {
	if _, err := PublicKeyToPEM("not a key"); err == nil {
		t.Error("expected error")
	}
}

// Silence unused imports if refactored.
var _ = rsa.PublicKey{}
