package logstore_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/ans/internal/adapter/keymanager"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/logstore"
)

// realSigner builds a real C2SPECDSASigner — used by the Open
// negative-input tests so each one rejects on its own constraint
// rather than the nil-signer guard.
func realSigner(t *testing.T) *logstore.C2SPECDSASigner {
	t.Helper()
	dir := t.TempDir()
	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(context.Background(), "k", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	s, err := logstore.NewC2SPECDSASigner(context.Background(), km, "k", "ans-test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestOpen_RejectsEmptyDataDir covers the cfg.DataDir validation
// branch in logstore.Open. Pre-coverage tests always pass a real
// tempdir.
func TestOpen_RejectsEmptyDataDir(t *testing.T) {
	t.Parallel()
	signer := realSigner(t)
	if _, err := logstore.Open(context.Background(), logstore.Config{}, signer); err == nil {
		t.Error("expected error for empty DataDir")
	}
}

// TestOpen_RejectsEmptyOrigin covers the cfg.Origin validation
// branch.
func TestOpen_RejectsEmptyOrigin(t *testing.T) {
	t.Parallel()
	signer := realSigner(t)
	cfg := logstore.Config{
		DataDir: t.TempDir(),
		Origin:  "",
	}
	if _, err := logstore.Open(context.Background(), cfg, signer); err == nil {
		t.Error("expected error for empty Origin")
	}
}

// TestOpen_RejectsNilSigner covers the signer-nil guard.
func TestOpen_RejectsNilSigner(t *testing.T) {
	t.Parallel()
	cfg := logstore.Config{DataDir: t.TempDir(), Origin: "ans-test"}
	if _, err := logstore.Open(context.Background(), cfg, nil); err == nil {
		t.Error("expected error for nil signer")
	}
}

// TestOpen_AppliesDefaults_ZeroBatchSize covers the BatchSize <= 0
// default-application branch.
func TestOpen_AppliesDefaults_ZeroBatchSize(t *testing.T) {
	t.Parallel()
	signer := realSigner(t)
	cfg := logstore.Config{
		DataDir: t.TempDir(),
		Origin:  "ans-test",
		// BatchSize / BatchMaxAge / CheckpointInterval all 0 → defaults applied.
	}
	lg, err := logstore.Open(context.Background(), cfg, signer)
	if err != nil {
		t.Fatalf("Open with defaults: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_ = lg.Close(ctx)
	})
}
