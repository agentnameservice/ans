package receipt_test

import (
	"context"
	"crypto/ecdsa"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/adapter/keymanager"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/receipt"
)

// TestKeyManagerGenerator_KeyIDAndPublicKey covers the trivial
// accessors on the receipt generator. Both are forward-only methods
// that the HTTP layer uses to populate the kid header on outbound
// receipts; pinning their behaviour here gates against accidental
// drift if the generator's public/key plumbing changes.
func TestKeyManagerGenerator_KeyIDAndPublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "receipt-k"
	if _, err := km.EnsureKey(ctx, keyID, port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	gen, err := receipt.NewKeyManagerGenerator(ctx, km, keyID, "ans-test")
	if err != nil {
		t.Fatal(err)
	}

	if got := gen.KeyID(); got != keyID {
		t.Errorf("KeyID: got %q want %q", got, keyID)
	}
	pub := gen.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey: nil")
	}
	expectAny, err := km.GetPublicKey(ctx, keyID)
	if err != nil {
		t.Fatal(err)
	}
	expect, ok := expectAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("KM returned non-ECDSA: %T", expectAny)
	}
	if !pub.Equal(expect) {
		t.Error("PublicKey doesn't match KM.GetPublicKey")
	}
}

// TestKeyManagerStatusTokenGenerator_PublicKey covers the same
// shape on the status-token generator.
func TestKeyManagerStatusTokenGenerator_PublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(ctx, "tk", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	gen, err := receipt.NewKeyManagerStatusTokenGenerator(ctx, km, "tk", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if pub := gen.PublicKey(); pub == nil {
		t.Fatal("PublicKey: nil")
	}
}
