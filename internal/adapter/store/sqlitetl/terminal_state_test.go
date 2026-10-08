package sqlitetl

import "testing"

func TestHistoricalDuplicatesCannotReplaceTerminalState(t *testing.T) {
	for _, terminal := range []string{"AGENT_REVOKED", "AGENT_DEPRECATED"} {
		t.Run(terminal, func(t *testing.T) {
			db := newDB(t)
			store := NewEventStore(db)
			for i := range uint64(4) {
				insertRawEvent(t, db, i, "agent-1")
			}
			if _, err := db.db.Exec(`UPDATE tl_events SET event_type = ? WHERE leaf_index = 2`, terminal); err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec(`UPDATE tl_events SET event_hash = 'hash-agent-1-1' WHERE leaf_index = 3`); err != nil {
				t.Fatal(err)
			}
			for _, bound := range []uint64{0, 4, 2} {
				got, err := store.GetLatestByAgentID(t.Context(), "agent-1", bound)
				if err != nil {
					t.Fatal(err)
				}
				want := uint64(2)
				if bound == 2 {
					want = 1
				}
				if got.LeafIndex != want {
					t.Fatalf("bound %d: leaf %d, want %d", bound, got.LeafIndex, want)
				}
			}
			got, err := store.LatestAgentState(t.Context(), "ans://v1.0.0.agent-1", "agent-1")
			if err != nil || got.LeafIndex != 2 {
				t.Fatalf("ingest state = %+v, %v", got, err)
			}
			audit, err := store.GetByAgentID(t.Context(), "agent-1", 50, 0, 0)
			if err != nil || len(audit) != 4 {
				t.Fatalf("audit lost raw duplicate: %d, %v", len(audit), err)
			}
		})
	}
}
