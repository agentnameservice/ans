package sqlite_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
)

func TestActivationSealPersistsFirstSignedPayloadAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ra.db")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	store := sqlite.NewOutboxStore(db)
	first := []byte(`{"innerEventCanonical":{"timestamp":"original"},"producerSignature":"original-signature"}`)
	lane, saved, err := store.PrepareActivationSeal(t.Context(), "agent", "V1", first)
	if err != nil || lane != "V1" || !bytes.Equal(saved, first) {
		t.Fatalf("prepare: %s %s %v", lane, saved, err)
	}
	rows, err := store.Claim(t.Context(), 100)
	if err != nil || len(rows) != 0 {
		t.Fatalf("synchronous evidence was queued for worker: %v %v", rows, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store = sqlite.NewOutboxStore(db)
	lane, saved, err = store.PrepareActivationSeal(t.Context(), "agent", "V2", []byte(`{"different":true}`))
	if err != nil || lane != "V1" || !bytes.Equal(saved, first) {
		t.Fatalf("retry replaced evidence: %s %s %v", lane, saved, err)
	}
}
