package sqlite_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
)

func TestActivationSealPersistsFirstSignedPayloadAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ra.db")
	db, err := sqlite.Open(t.Context(), path)
	require.NoError(t, err)
	store := sqlite.NewOutboxStore(db)
	first := []byte(`{"innerEventCanonical":{"timestamp":"original"},"producerSignature":"original-signature"}`)
	lane, saved, err := store.PrepareActivationSeal(t.Context(), "agent", "V1", first)
	require.NoError(t, err)
	require.Equal(t, "V1", lane)
	require.Equal(t, first, saved)
	rows, err := store.Claim(t.Context(), 100)
	require.NoError(t, err)
	require.Empty(t, rows, "synchronous evidence must not be queued for the worker")
	require.NoError(t, db.Close())
	db, err = sqlite.Open(t.Context(), path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store = sqlite.NewOutboxStore(db)
	lane, saved, err = store.PrepareActivationSeal(t.Context(), "agent", "V2", []byte(`{"different":true}`))
	require.NoError(t, err)
	require.Equal(t, "V1", lane)
	require.Equal(t, first, saved, "retry must preserve the original signed evidence")
}
