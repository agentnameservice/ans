package sqlitetl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

// newDB opens an in-memory sqlite_tl DB for tests.
func newDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// ----- DB.DBX -----

func TestDB_DBX_ReturnsLiveHandle(t *testing.T) {
	db := newDB(t)
	x := db.DBX()
	if x == nil {
		t.Fatal("DBX must be non-nil")
	}
	if err := x.PingContext(context.Background()); err != nil {
		t.Errorf("ping: %v", err)
	}
}

// ----- CheckpointStore -----

func TestCheckpointRecord_CreatedAt(t *testing.T) {
	r := &CheckpointRecord{CreatedAtMs: 1_700_000_000_000}
	got := r.CreatedAt()
	if got.Location() != time.UTC {
		t.Errorf("want UTC, got %s", got.Location())
	}
	if got.UnixMilli() != 1_700_000_000_000 {
		t.Errorf("round-trip: %d", got.UnixMilli())
	}
}

func TestCheckpointStore_StoreLatestAndByTreeSizeAtLeast(t *testing.T) {
	db := newDB(t)
	store := NewCheckpointStore(db)
	ctx := context.Background()

	// Store three checkpoints at sizes 1, 5, 10.
	for _, spec := range []struct {
		size uint64
		hash []byte
	}{
		{1, []byte{0x01}},
		{5, []byte{0x05}},
		{10, []byte{0x0a}},
	} {
		if err := store.Store(ctx, spec.size, spec.hash, []byte("raw"), "origin"); err != nil {
			t.Fatalf("store %d: %v", spec.size, err)
		}
	}

	// Latest == size 10.
	latest, err := store.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest.TreeSize != 10 {
		t.Errorf("Latest.TreeSize: got %d, want 10", latest.TreeSize)
	}

	// ByTreeSizeAtLeast(3) → smallest >= 3 == 5.
	match, err := store.ByTreeSizeAtLeast(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if match == nil || match.TreeSize != 5 {
		t.Errorf("ByTreeSizeAtLeast(3): got %+v, want size=5", match)
	}

	// ByTreeSizeAtLeast(100) → no match, (nil, nil).
	none, err := store.ByTreeSizeAtLeast(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		t.Errorf("expected nil for size beyond store, got %+v", none)
	}
}

func TestCheckpointStore_Latest_EmptyStore(t *testing.T) {
	store := NewCheckpointStore(newDB(t))
	_, err := store.Latest(context.Background())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("want ErrNotFound on empty store, got %v", err)
	}
}

// ----- EventRecord helpers -----

func TestEventRecord_CreatedAt(t *testing.T) {
	r := &EventRecord{CreatedAtMs: 1_750_000_000_000}
	got := r.CreatedAt()
	if got.Location() != time.UTC {
		t.Errorf("want UTC")
	}
	if got.UnixMilli() != 1_750_000_000_000 {
		t.Errorf("round-trip")
	}
}
