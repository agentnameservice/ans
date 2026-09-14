package sqlite_test

import (
	"slices"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
)

func TestOutbox_RetryBackoffPreservesPerAgentOrder(t *testing.T) {
	db, err := sqlite.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.NewOutboxStore(db)
	enqueue := func(agent string, when time.Time) int64 {
		t.Helper()
		id, err := store.Enqueue(t.Context(), "AGENT_RENEWED", agent, "V2", []byte(`{"snapshot":true}`), when)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := enqueue("agent-a", time.Now().Add(-time.Minute))
	if err := store.MarkFailed(t.Context(), first, 8, "temporary TL outage", time.Hour); err != nil {
		t.Fatal(err)
	}
	second := enqueue("agent-a", time.Now().Add(-time.Minute))
	other := enqueue("agent-b", time.Now().Add(-time.Minute))
	assertClaimedOutboxIDs(t, store, other)
	if err := store.MarkSent(t.Context(), first, "first-log-id"); err != nil {
		t.Fatal(err)
	}
	assertClaimedOutboxIDs(t, store, second, other)
}

func assertClaimedOutboxIDs(t *testing.T, store *sqlite.OutboxStore, want ...int64) {
	t.Helper()
	rows, err := store.Claim(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]int64, len(rows))
	for i, row := range rows {
		got[i] = row.ID
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ready outbox IDs = %v, want %v", got, want)
	}
}
