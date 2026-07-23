package logstore_test

import (
	"context"
	"crypto/ecdsa"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/adapter/keymanager"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/logstore"
)

// TestC2SPSigner_PublicKey covers C2SPECDSASigner.PublicKey, which the
// checkpoint-read path uses to re-verify primary signatures. The
// returned key must be the same one the KeyManager holds for the
// signer's keyID.
func TestC2SPSigner_PublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(ctx, "tl-sign", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	signer, err := logstore.NewC2SPECDSASigner(ctx, km, "tl-sign", "ans-test")
	if err != nil {
		t.Fatal(err)
	}

	pub := signer.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey: nil")
	}
	expectAny, err := km.GetPublicKey(ctx, "tl-sign")
	if err != nil {
		t.Fatal(err)
	}
	expect, ok := expectAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("KM returned non-ECDSA key: %T", expectAny)
	}
	if !pub.Equal(expect) {
		t.Error("PublicKey doesn't match KeyManager.GetPublicKey")
	}
}

// TestLog_Signer exposes the primary checkpoint signer to callers
// (the checkpoint-read service uses it to verify stored signatures).
// Trivial getter, but counts toward the package's coverage gate.
func TestLog_Signer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(ctx, "tl-sign", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	signer, err := logstore.NewC2SPECDSASigner(ctx, km, "tl-sign", "ans-test")
	if err != nil {
		t.Fatal(err)
	}

	lg, err := logstore.Open(ctx, logstore.Config{
		DataDir:            filepath.Join(dir, "tiles"),
		Origin:             "ans-test",
		BatchSize:          1,
		BatchMaxAge:        50 * time.Millisecond,
		CheckpointInterval: 100 * time.Millisecond,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lg.Close(cctx)
	})

	got := lg.Signer()
	if got == nil {
		t.Fatal("Log.Signer: nil")
	}
	if got.Name() != "ans-test" {
		t.Errorf("signer name: got %q want %q", got.Name(), "ans-test")
	}
}
