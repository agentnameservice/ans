package sqlitetl

import (
	"context"
	"testing"
)

// insertRawEvent writes a minimal tl_events row directly via SQL,
// bypassing StoreEvent (which requires a real event.View). Used by
// the GetByAgentID pagination tests below.
func insertRawEvent(t *testing.T, db *DB, leafIndex uint64, agentID string) {
	t.Helper()
	_, err := db.db.ExecContext(context.Background(), `
        INSERT INTO tl_events(
            leaf_index, leaf_hash, event_hash, log_id,
            agent_id, ans_name, agent_fqdn, event_type,
            schema_version, raw_event, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		leafIndex,
		"deadbeef",
		"hash-"+agentID+"-"+itoa(int(leafIndex)),
		"log-id",
		agentID,
		"ans://v1.0.0."+agentID,
		agentID+".example.com",
		"AGENT_REGISTERED",
		"V2",
		`{"payload":{}}`,
		nowMs(),
	)
	if err != nil {
		t.Fatalf("insert raw event: %v", err)
	}
}

// itoa avoids dragging strconv into a single-use call. Stays inline so
// the test file's import block remains minimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	x := n
	if x < 0 {
		x = -x
	}
	for x > 0 {
		i--
		buf[i] = byte('0' + x%10)
		x /= 10
	}
	if n < 0 {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestEventStore_GetByAgentID_HappyPath covers the unbounded branch
// of GetByAgentID — `maxLeafIndex == 0` reaches the unfiltered
// SQL branch.
func TestEventStore_GetByAgentID_HappyPath(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	store := NewEventStore(db)

	for i := range uint64(5) {
		insertRawEvent(t, db, i, "agent-1")
	}
	got, err := store.GetByAgentID(context.Background(), "agent-1", 50, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("got %d events, want 5", len(got))
	}
	// Newest-first ordering: first row has leaf 4.
	if got[0].LeafIndex != 4 {
		t.Errorf("first row LeafIndex: got %d want 4", got[0].LeafIndex)
	}
}

// TestEventStore_GetByAgentID_BoundedByMaxLeafIndex covers the
// `maxLeafIndex > 0` branch — caller wants events strictly below
// the latest checkpoint's leaf-index horizon.
func TestEventStore_GetByAgentID_BoundedByMaxLeafIndex(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	store := NewEventStore(db)

	for i := range uint64(10) {
		insertRawEvent(t, db, i, "agent-1")
	}
	// maxLeafIndex=3 → leaves 0, 1, 2 are eligible.
	got, err := store.GetByAgentID(context.Background(), "agent-1", 50, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("got %d events, want 3", len(got))
	}
	for _, e := range got {
		if e.LeafIndex >= 3 {
			t.Errorf("leaf %d violates maxLeafIndex=3", e.LeafIndex)
		}
	}
}

// TestEventStore_GetByAgentID_LimitClamping covers the limit-out-of-
// bounds branches: <=0 and >200 both fall back to the default 50.
func TestEventStore_GetByAgentID_LimitClamping(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	store := NewEventStore(db)

	for i := range uint64(5) {
		insertRawEvent(t, db, i, "agent-1")
	}

	// limit=0 → defaults to 50, all 5 events come back.
	got, err := store.GetByAgentID(context.Background(), "agent-1", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("limit=0 default: got %d want 5", len(got))
	}

	// limit=999 → clamps to 50, all 5 still come back.
	got, err = store.GetByAgentID(context.Background(), "agent-1", 999, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("limit=999 clamp: got %d want 5", len(got))
	}

	// offset=-1 → clamps to 0.
	got, err = store.GetByAgentID(context.Background(), "agent-1", 50, -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("offset=-1 clamp: got %d want 5", len(got))
	}
}

// TestEventStore_GetByAgentID_NoMatch returns an empty slice for
// an agent with no events. Exercises the empty-result code path
// implicitly (no rows scanned).
func TestEventStore_GetByAgentID_NoMatch(t *testing.T) {
	t.Parallel()
	store := NewEventStore(newDB(t))
	got, err := store.GetByAgentID(context.Background(), "no-such-agent", 50, 0, 0)
	if err != nil {
		t.Fatalf("GetByAgentID: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}
}

// TestEventStore_ExistsByEventHash covers both arms of the
// switch + the leafIdx.Valid path.
func TestEventStore_ExistsByEventHash(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	store := NewEventStore(db)
	insertRawEvent(t, db, 7, "agent-7")

	exists, leaf, err := store.ExistsByEventHash(context.Background(), "hash-agent-7-7")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("expected exists=true for stored hash")
	}
	if leaf != 7 {
		t.Errorf("leaf: got %d want 7", leaf)
	}

	// Unknown hash → exists=false, leaf=0, no error.
	exists, leaf, err = store.ExistsByEventHash(context.Background(), "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expected exists=false for unknown hash")
	}
	if leaf != 0 {
		t.Errorf("leaf for unknown hash: got %d want 0", leaf)
	}
}
