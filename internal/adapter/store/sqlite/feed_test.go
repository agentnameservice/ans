package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// feedRowSpec describes one outbox row to seed for a feed test.
type feedRowSpec struct {
	agentID   string
	eventType string
	logID     string // empty => log_id stays NULL
	sent      bool   // false => sent_at_ms stays NULL
	createdAt time.Time
}

// seedOutbox inserts an outbox row with explicit control over the
// columns the feed query gates on (sent_at_ms, log_id, created_at_ms),
// returning the row's id. payload_json is a minimal valid blob.
func seedOutbox(t *testing.T, db *DB, spec feedRowSpec) int64 {
	t.Helper()
	inner, _ := json.Marshal(map[string]any{
		"ansId":     spec.agentID,
		"ansName":   "ans://v1.0.0." + spec.agentID + ".example.com",
		"eventType": spec.eventType,
		"timestamp": spec.createdAt.UTC().Format(time.RFC3339),
		"agent":     map[string]any{"host": spec.agentID + ".example.com", "version": "1.0.0"},
	})
	payload, _ := json.Marshal(map[string]any{
		"innerEventCanonical": json.RawMessage(inner),
		"producerSignature":   "h..s",
	})

	var sentVal, logVal any
	if spec.sent {
		sentVal = spec.createdAt.UnixMilli()
	}
	if spec.logID != "" {
		logVal = spec.logID
	}

	res, err := db.DBX().ExecContext(context.Background(), `
        INSERT INTO outbox_events(event_type, agent_id, schema_version, payload_json,
            next_attempt_at_ms, created_at_ms, sent_at_ms, log_id)
        VALUES (?, ?, 'V1', ?, ?, ?, ?, ?)`,
		spec.eventType, spec.agentID, string(payload),
		spec.createdAt.UnixMilli(), spec.createdAt.UnixMilli(), sentVal, logVal)
	if err != nil {
		t.Fatalf("seed outbox: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// seedRegistration inserts a minimal agent_registrations row so the
// feed JOIN can pull display metadata + fallback identity.
func seedRegistration(t *testing.T, db *DB, agentID, displayName, description string) {
	t.Helper()
	now := time.Now().UnixMilli()
	_, err := db.DBX().ExecContext(context.Background(), `
        INSERT INTO agent_registrations(agent_id, owner_id, ans_name, agent_host, version,
            status, display_name, description, registration_timestamp_ms, created_at_ms, updated_at_ms)
        VALUES (?, 'owner-1', ?, ?, '1.0.0', 'ACTIVE', ?, ?, ?, ?, ?)`,
		agentID, "ans://v1.0.0."+agentID+".example.com", agentID+".example.com",
		displayName, description, now, now, now)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
}

func TestFeedStore_GatesOnSentAndLogged(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)

	// Visible: sent + logged.
	seedOutbox(t, db, feedRowSpec{agentID: "a", eventType: "AGENT_REGISTERED", logID: "log-a", sent: true, createdAt: base})
	// Hidden: sent but no logId (e.g., pre-migration row).
	seedOutbox(t, db, feedRowSpec{agentID: "b", eventType: "AGENT_REGISTERED", logID: "", sent: true, createdAt: base.Add(time.Minute)})
	// Hidden: logged but not sent (impossible in practice, but the
	// gate must hold both ways).
	seedOutbox(t, db, feedRowSpec{agentID: "c", eventType: "AGENT_REGISTERED", logID: "log-c", sent: false, createdAt: base.Add(2 * time.Minute)})
	// Hidden: neither.
	seedOutbox(t, db, feedRowSpec{agentID: "d", eventType: "AGENT_REGISTERED", logID: "", sent: false, createdAt: base.Add(3 * time.Minute)})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 visible row, got %d", len(rows))
	}
	if rows[0].LogID != "log-a" {
		t.Errorf("visible row logId = %q, want log-a", rows[0].LogID)
	}
}

func TestFeedStore_RetentionWindow(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()

	// Inside the window.
	seedOutbox(t, db, feedRowSpec{agentID: "fresh", eventType: "AGENT_REGISTERED", logID: "log-fresh", sent: true, createdAt: now.Add(-1 * time.Hour)})
	// Outside the window (older than retention).
	seedOutbox(t, db, feedRowSpec{agentID: "stale", eventType: "AGENT_REGISTERED", logID: "log-stale", sent: true, createdAt: now.Add(-48 * time.Hour)})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].LogID != "log-fresh" {
		t.Fatalf("retention window not applied: got %+v", rows)
	}
}

func TestFeedStore_OrdersByOutboxIDAscending(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	// Insert in order; ids ascend with insertion.
	seedOutbox(t, db, feedRowSpec{agentID: "first", eventType: "AGENT_REGISTERED", logID: "log-1", sent: true, createdAt: base})
	seedOutbox(t, db, feedRowSpec{agentID: "second", eventType: "AGENT_REGISTERED", logID: "log-2", sent: true, createdAt: base.Add(time.Minute)})
	seedOutbox(t, db, feedRowSpec{agentID: "third", eventType: "AGENT_REGISTERED", logID: "log-3", sent: true, createdAt: base.Add(2 * time.Minute)})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{rows[0].LogID, rows[1].LogID, rows[2].LogID}
	want := []string{"log-1", "log-2", "log-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order: got %v, want %v", got, want)
			break
		}
	}
}

func TestFeedStore_CursorReturnsRowsAfter(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	seedOutbox(t, db, feedRowSpec{agentID: "a", eventType: "AGENT_REGISTERED", logID: "log-1", sent: true, createdAt: base})
	seedOutbox(t, db, feedRowSpec{agentID: "b", eventType: "AGENT_REGISTERED", logID: "log-2", sent: true, createdAt: base.Add(time.Minute)})
	seedOutbox(t, db, feedRowSpec{agentID: "c", eventType: "AGENT_REGISTERED", logID: "log-3", sent: true, createdAt: base.Add(2 * time.Minute)})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{AfterLogID: "log-1", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].LogID != "log-2" || rows[1].LogID != "log-3" {
		t.Fatalf("cursor after log-1 = %+v, want [log-2 log-3]", logIDs(rows))
	}
}

func TestFeedStore_UnknownCursorStartsFromOldest(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	seedOutbox(t, db, feedRowSpec{agentID: "a", eventType: "AGENT_REGISTERED", logID: "log-1", sent: true, createdAt: base})
	seedOutbox(t, db, feedRowSpec{agentID: "b", eventType: "AGENT_REGISTERED", logID: "log-2", sent: true, createdAt: base.Add(time.Minute)})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{AfterLogID: "log-does-not-exist", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("unknown cursor should restart from oldest, got %v", logIDs(rows))
	}
}

func TestFeedStore_AgedOutCursorStartsFromOldest(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	// The cursor row itself is outside the retention window; the
	// resolveCursor query filters it out, so we fall back to oldest.
	seedOutbox(t, db, feedRowSpec{agentID: "old", eventType: "AGENT_REGISTERED", logID: "log-old", sent: true, createdAt: now.Add(-48 * time.Hour)})
	seedOutbox(t, db, feedRowSpec{agentID: "fresh", eventType: "AGENT_REGISTERED", logID: "log-fresh", sent: true, createdAt: now.Add(-1 * time.Hour)})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{AfterLogID: "log-old", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	// Only the fresh row is retained, and the aged-out cursor falls
	// back to oldest-retained → returns the fresh row.
	if len(rows) != 1 || rows[0].LogID != "log-fresh" {
		t.Fatalf("aged-out cursor = %v, want [log-fresh]", logIDs(rows))
	}
}

func TestFeedStore_LimitCaps(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	for i := range 5 {
		seedOutbox(t, db, feedRowSpec{
			agentID:   "a" + string(rune('0'+i)),
			eventType: "AGENT_REGISTERED",
			logID:     "log-" + string(rune('0'+i)),
			sent:      true,
			createdAt: base.Add(time.Duration(i) * time.Minute),
		})
	}
	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("limit not applied: got %d rows", len(rows))
	}
}

func TestFeedStore_ProviderFilterReturnsEmpty(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	seedOutbox(t, db, feedRowSpec{agentID: "a", eventType: "AGENT_REGISTERED", logID: "log-1", sent: true, createdAt: base})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{ProviderFilter: "PC_123", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("provider filter must return empty in OSS, got %d", len(rows))
	}
}

func TestFeedStore_JoinsRegistrationAndEndpoints(t *testing.T) {
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	seedOutbox(t, db, feedRowSpec{agentID: "joined", eventType: "AGENT_REGISTERED", logID: "log-1", sent: true, createdAt: base})
	seedRegistration(t, db, "joined", "Joined Agent", "has metadata")

	epStore := NewEndpointStore(db)
	if err := epStore.Save(context.Background(), &domain.AgentEndpoints{
		AgentID: "joined",
		Endpoints: []domain.AgentEndpoint{
			{Protocol: domain.ProtocolMCP, AgentURL: "https://joined.example.com/mcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.RegDisplayName != "Joined Agent" || r.RegDescription != "has metadata" {
		t.Errorf("registration join = %q / %q", r.RegDisplayName, r.RegDescription)
	}
	if r.RegAnsName != "ans://v1.0.0.joined.example.com" || r.RegAgentHost != "joined.example.com" {
		t.Errorf("registration identity join = %q / %q", r.RegAnsName, r.RegAgentHost)
	}
	if len(r.EndpointsJSON) == 0 {
		t.Error("endpoints JSON not joined")
	}
}

func TestFeedStore_MissingRegistrationJoinIsLenient(t *testing.T) {
	// A delivered outbox row with no matching registration row (e.g.,
	// the registration was hard-deleted) still surfaces, with empty
	// fallback columns — the LEFT JOIN must not drop it.
	db := newTestDB(t)
	base := time.Now().Add(-time.Hour)
	seedOutbox(t, db, feedRowSpec{agentID: "orphan", eventType: "AGENT_REVOKED", logID: "log-1", sent: true, createdAt: base})

	store := NewFeedStore(db, 24*time.Hour)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("orphan row dropped by JOIN: got %d", len(rows))
	}
	if rows[0].RegDisplayName != "" || rows[0].RegAnsName != "" {
		t.Errorf("expected empty fallback columns, got %q / %q", rows[0].RegDisplayName, rows[0].RegAnsName)
	}
}

func TestFeedStore_NoRetentionLowerBound(t *testing.T) {
	// Non-positive retention disables the lower bound (test-only mode).
	db := newTestDB(t)
	seedOutbox(t, db, feedRowSpec{agentID: "ancient", eventType: "AGENT_REGISTERED", logID: "log-1", sent: true, createdAt: time.Now().Add(-10000 * time.Hour)})

	store := NewFeedStore(db, 0)
	rows, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("no-lower-bound mode should serve ancient rows, got %d", len(rows))
	}
}

func TestFeedStore_ReadFeed_ClosedDBErrors(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	store := NewFeedStore(db, 24*time.Hour)
	_ = db.Close() // force a query error on the next read.

	if _, err := store.ReadFeed(context.Background(), port.FeedQuery{Limit: 10}); err == nil {
		t.Fatal("expected error reading from a closed DB")
	}
}

func TestFeedStore_ResolveCursor_ClosedDBErrors(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	store := NewFeedStore(db, 24*time.Hour)
	_ = db.Close()

	// A non-empty cursor forces resolveCursor's query, which errors on
	// the closed handle.
	if _, err := store.ReadFeed(context.Background(), port.FeedQuery{AfterLogID: "log-x", Limit: 10}); err == nil {
		t.Fatal("expected error resolving cursor on a closed DB")
	}
}

// TestFeedStore_QueryPlansUseIndexes pins BLOCKER H2: both feed queries
// must use an index (SEARCH, not SCAN) so the unauthenticated feed
// cannot be forced into a full scan that grows with deployment age. It
// asserts the EXPLAIN QUERY PLAN names the expected partial indexes —
// regression catch if a future migration drops them or Open() stops
// seeding sqlite_stat1 (which is what flips the planner off the rowid
// default for the no-cursor read).
func TestFeedStore_QueryPlansUseIndexes(t *testing.T) {
	db := newTestDB(t) // Open() runs ANALYZE → sqlite_stat1 seeded.
	now := time.Now()
	// Realistic mix: many aged-out rows (small ids) + a few fresh ones,
	// so a rowid scan and an index search are genuinely different plans.
	for i := range 50 {
		seedOutbox(t, db, feedRowSpec{
			agentID: fmt.Sprintf("old%d", i), eventType: "AGENT_REGISTERED",
			logID: fmt.Sprintf("old-%d", i), sent: true, createdAt: now.Add(-200 * time.Hour),
		})
	}
	for i := range 5 {
		seedOutbox(t, db, feedRowSpec{
			agentID: fmt.Sprintf("new%d", i), eventType: "AGENT_REGISTERED",
			logID: fmt.Sprintf("new-%d", i), sent: true, createdAt: now.Add(-time.Hour),
		})
	}

	floor := now.Add(-24 * time.Hour).UnixMilli()
	cases := []struct {
		name      string
		query     string
		args      []any
		wantIndex string
	}{
		{
			name: "no-cursor feed read seeks the retention floor",
			query: `SELECT o.log_id FROM outbox_events o
                LEFT JOIN agent_registrations r ON r.agent_id = o.agent_id
                LEFT JOIN agent_endpoints e ON e.agent_id = o.agent_id
                WHERE o.sent_at_ms IS NOT NULL AND o.log_id IS NOT NULL
                  AND o.created_at_ms >= ? AND o.id > ? ORDER BY o.id ASC LIMIT ?`,
			args:      []any{floor, int64(0), 100},
			wantIndex: "idx_outbox_feed",
		},
		{
			name: "cursor resolution seeks log_id",
			query: `SELECT id FROM outbox_events WHERE log_id = ? AND sent_at_ms IS NOT NULL
                  AND created_at_ms >= ? ORDER BY id ASC LIMIT 1`,
			args:      []any{"new-1", floor},
			wantIndex: "idx_outbox_log_id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := explainPlan(t, db, tc.query, tc.args...)
			if strings.Contains(plan, "SCAN o ") || strings.Contains(plan, "SCAN outbox_events") {
				t.Errorf("plan contains a table SCAN (must be a SEARCH): %s", plan)
			}
			if !strings.Contains(plan, tc.wantIndex) {
				t.Errorf("plan does not use %s: %s", tc.wantIndex, plan)
			}
		})
	}
}

// explainPlan returns the concatenated EXPLAIN QUERY PLAN detail rows.
func explainPlan(t *testing.T, db *DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.DBX().QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		b.WriteString(detail)
		b.WriteString(" | ")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	return b.String()
}

func logIDs(rows []port.FeedRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.LogID
	}
	return out
}
