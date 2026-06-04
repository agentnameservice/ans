package logstore_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"path/filepath"
	"testing"

	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/logstore"
)

// fakeKM lets us exercise the c2sp / JWS signer constructors against
// degenerate KeyManager states (missing key, non-ECDSA key) — the
// real file-backed adapter only emits ECDSA keys, so we need a stub
// to cover the type-mismatch and lookup-failure branches.
type fakeKM struct {
	pub      crypto.PublicKey
	getErr   error
	signErr  error
	signResp []byte
}

func (f *fakeKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.pub, nil
}

func (f *fakeKM) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signResp, nil
}

func (f *fakeKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return true, nil
}

func (f *fakeKM) CreateKey(_ context.Context, _ string) (string, error) {
	return "k", nil
}

func (f *fakeKM) ListKeys(_ context.Context) ([]string, error) {
	return []string{"k"}, nil
}

// ----- C2SPECDSASigner constructor branches -----

func TestNewC2SPECDSASigner_NilKM(t *testing.T) {
	if _, err := logstore.NewC2SPECDSASigner(context.Background(), nil, "k", "ans-test"); err == nil {
		t.Error("expected error for nil KeyManager")
	}
}

func TestNewC2SPECDSASigner_EmptyOrigin(t *testing.T) {
	dir := t.TempDir()
	km, _ := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	_, _ = km.EnsureKey(context.Background(), "k", port.AlgorithmECDSAP256)
	if _, err := logstore.NewC2SPECDSASigner(context.Background(), km, "k", ""); err == nil {
		t.Error("expected error for empty origin")
	}
}

func TestNewC2SPECDSASigner_KeyLookupFails(t *testing.T) {
	km := &fakeKM{getErr: errors.New("not found")}
	if _, err := logstore.NewC2SPECDSASigner(context.Background(), km, "missing", "ans-test"); err == nil {
		t.Error("expected error when GetPublicKey fails")
	}
}

func TestNewC2SPECDSASigner_NonECDSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	km := &fakeKM{pub: &rsaKey.PublicKey}
	_, err = logstore.NewC2SPECDSASigner(context.Background(), km, "rsa-k", "ans-test")
	if err == nil {
		t.Error("expected error for non-ECDSA key")
	}
}

// ----- JWSCheckpointSigner constructor branches -----

func TestNewJWSCheckpointSigner_NilKM(t *testing.T) {
	if _, err := logstore.NewJWSCheckpointSigner(context.Background(), nil, "k", "ans-test"); err == nil {
		t.Error("expected error for nil KeyManager")
	}
}

func TestNewJWSCheckpointSigner_EmptyOrigin(t *testing.T) {
	dir := t.TempDir()
	km, _ := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	_, _ = km.EnsureKey(context.Background(), "k", port.AlgorithmECDSAP256)
	if _, err := logstore.NewJWSCheckpointSigner(context.Background(), km, "k", ""); err == nil {
		t.Error("expected error for empty origin")
	}
}

func TestNewJWSCheckpointSigner_KeyLookupFails(t *testing.T) {
	km := &fakeKM{getErr: errors.New("not found")}
	if _, err := logstore.NewJWSCheckpointSigner(context.Background(), km, "missing", "ans-test"); err == nil {
		t.Error("expected error when GetPublicKey fails")
	}
}

func TestNewJWSCheckpointSigner_NonECDSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	km := &fakeKM{pub: &rsaKey.PublicKey}
	_, err = logstore.NewJWSCheckpointSigner(context.Background(), km, "rsa-k", "ans-test")
	if err == nil {
		t.Error("expected error for non-ECDSA key")
	}
}

// ----- VerifyC2SPECDSA negative paths -----

// VerifyC2SPECDSA's malformed-input branches return false instead of
// an error.
func TestVerifyC2SPECDSA_NilPubKey(t *testing.T) {
	if logstore.VerifyC2SPECDSA(nil, []byte("body"), []byte{0x01, 0x02}) {
		t.Error("expected false for nil public key")
	}
}

func TestVerifyC2SPECDSA_EmptySig(t *testing.T) {
	pub, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if logstore.VerifyC2SPECDSA(&pub.PublicKey, []byte("body"), nil) {
		t.Error("expected false for empty signature")
	}
}

func TestVerifyC2SPECDSA_MalformedSig(t *testing.T) {
	pub, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// 5 bytes is neither a valid DER signature nor a legacy P-256
	// P1363 signature.
	if logstore.VerifyC2SPECDSA(&pub.PublicKey, []byte("body"), []byte{1, 2, 3, 4, 5}) {
		t.Error("expected false for malformed signature")
	}
}

// ----- C2SPECDSASigner.Sign error path -----
//
// When the underlying KeyManager Sign fails, the signer must
// surface that error rather than silently returning nil bytes.
// Real KeyManagers don't fail in unit tests, so we drive this
// through fakeKM.
func TestC2SPSigner_SignError(t *testing.T) {
	pub, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	km := &fakeKM{pub: &pub.PublicKey, signErr: errors.New("kms unavailable")}
	s, err := logstore.NewC2SPECDSASigner(context.Background(), km, "k", "ans-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, sErr := s.Sign([]byte("checkpoint body")); sErr == nil {
		t.Error("expected error when KeyManager.Sign fails")
	}
}

// ----- JWSCheckpointSigner.Sign error path: malformed checkpoint body -----
//
// Tessera always hands well-formed bodies in production but the
// parseCheckpointBody guard exists for defensive reasons (library
// misuse, future Tessera version drift). Driving a too-short body
// through Sign exercises the parse-failure branch.
func TestJWSSigner_SignParseError(t *testing.T) {
	dir := t.TempDir()
	km, _ := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	_, _ = km.EnsureKey(context.Background(), "k", port.AlgorithmECDSAP256)
	s, err := logstore.NewJWSCheckpointSigner(context.Background(), km, "k", "ans-test")
	if err != nil {
		t.Fatal(err)
	}
	// 2-line body — parseCheckpointBody requires ≥3 lines.
	if _, sErr := s.Sign([]byte("only-two\nlines\n")); sErr == nil {
		t.Error("expected parse error on too-short body")
	}
	// 3 lines but the size isn't an integer.
	if _, sErr := s.Sign([]byte("ans-test\nnot-a-number\nAAAA\n\n")); sErr == nil {
		t.Error("expected parse error on non-numeric size")
	}
	// 3 lines but the root hash is not base64.
	if _, sErr := s.Sign([]byte("ans-test\n1\n!!not-base64!!\n\n")); sErr == nil {
		t.Error("expected parse error on non-base64 root hash")
	}
}
