package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// ----- EndpointStore -----

func TestEndpointStore_SaveAndFind(t *testing.T) {
	db := newTestDB(t)
	store := NewEndpointStore(db)
	ctx := context.Background()

	eps := &domain.AgentEndpoints{
		AgentID: "agent-1",
		Endpoints: []domain.AgentEndpoint{
			{Protocol: domain.ProtocolMCP, AgentURL: "https://a.example.com/mcp"},
		},
	}
	if err := store.Save(ctx, eps); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := store.FindByAgentID(ctx, "agent-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.AgentID != "agent-1" || len(got.Endpoints) != 1 {
		t.Errorf("got %+v", got)
	}
	if got.Endpoints[0].Protocol != domain.ProtocolMCP {
		t.Errorf("protocol: got %q", got.Endpoints[0].Protocol)
	}

	// Upsert: replace endpoints and re-save.
	eps.Endpoints = []domain.AgentEndpoint{
		{Protocol: domain.ProtocolA2A, AgentURL: "https://a.example.com/a2a"},
	}
	if err := store.Save(ctx, eps); err != nil {
		t.Fatalf("resave: %v", err)
	}
	got, _ = store.FindByAgentID(ctx, "agent-1")
	if got.Endpoints[0].Protocol != domain.ProtocolA2A {
		t.Errorf("upsert didn't replace: %v", got.Endpoints)
	}
}

func TestEndpointStore_Save_Nil(t *testing.T) {
	store := NewEndpointStore(newTestDB(t))
	if err := store.Save(context.Background(), nil); err == nil {
		t.Error("want error for nil endpoints")
	}
}

func TestEndpointStore_FindByAgentID_NotFound(t *testing.T) {
	store := NewEndpointStore(newTestDB(t))
	_, err := store.FindByAgentID(context.Background(), "missing")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestEndpointStore_FindByAgentIDs_Batch(t *testing.T) {
	store := NewEndpointStore(newTestDB(t))
	ctx := context.Background()

	for _, id := range []string{"a", "b", "c"} {
		_ = store.Save(ctx, &domain.AgentEndpoints{
			AgentID:   id,
			Endpoints: []domain.AgentEndpoint{{Protocol: domain.ProtocolMCP, AgentURL: "https://" + id + "/"}},
		})
	}

	got, err := store.FindByAgentIDs(ctx, []string{"a", "c", "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("batch: got %d (%v), want 2", len(got), got)
	}
	if _, ok := got["a"]; !ok {
		t.Error("missing 'a'")
	}
	if _, ok := got["c"]; !ok {
		t.Error("missing 'c'")
	}

	// Empty input yields empty map, not a query.
	got, err = store.FindByAgentIDs(ctx, nil)
	if err != nil || len(got) != 0 {
		t.Errorf("empty: got=%v err=%v", got, err)
	}
}

// ----- OutboxStore -----

func TestOutboxStore_EnqueueAndClaim(t *testing.T) {
	db := newTestDB(t)
	store := NewOutboxStore(db)
	ctx := context.Background()

	id, err := store.Enqueue(ctx, "AGENT_REGISTERED", "agent-1", "V2",
		[]byte(`{"foo":1}`), time.Now().Add(-time.Second))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if id <= 0 {
		t.Errorf("bad id: %d", id)
	}

	claimed, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("want 1 claim, got %d", len(claimed))
	}
	if claimed[0].EventType != "AGENT_REGISTERED" {
		t.Errorf("event type: got %q", claimed[0].EventType)
	}
	if claimed[0].SchemaVersion != "V2" {
		t.Errorf("schema: got %q", claimed[0].SchemaVersion)
	}

	// MarkSent hides the event from future claims and records the
	// TL-assigned logId atomically with sent_at_ms.
	if err := store.MarkSent(ctx, id, "log-abc"); err != nil {
		t.Fatal(err)
	}
	claimed2, err := store.Claim(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed2) != 0 {
		t.Errorf("MarkSent didn't remove from claim set: %d", len(claimed2))
	}

	// The logId is persisted on the delivered row.
	var gotLogID string
	if err := db.DBX().GetContext(ctx, &gotLogID,
		`SELECT log_id FROM outbox_events WHERE id = ?`, id); err != nil {
		t.Fatalf("read log_id: %v", err)
	}
	if gotLogID != "log-abc" {
		t.Errorf("log_id: got %q, want %q", gotLogID, "log-abc")
	}
}

func TestOutboxStore_Enqueue_RejectsEmptyPayload(t *testing.T) {
	store := NewOutboxStore(newTestDB(t))
	_, err := store.Enqueue(context.Background(), "T", "a", "V2", nil, time.Now())
	if err == nil {
		t.Error("expected empty-payload rejection")
	}
}

func TestOutboxStore_Enqueue_RejectsInvalidSchema(t *testing.T) {
	store := NewOutboxStore(newTestDB(t))
	_, err := store.Enqueue(context.Background(), "T", "a", "V99", []byte("{}"), time.Now())
	if err == nil {
		t.Error("expected invalid-schema rejection")
	}
}

func TestOutboxStore_MarkFailed_BackoffAndRetryVisible(t *testing.T) {
	store := NewOutboxStore(newTestDB(t))
	ctx := context.Background()

	id, _ := store.Enqueue(ctx, "T", "a", "V2", []byte("{}"), time.Now().Add(-time.Second))
	// Fail with a large maxDelay — the backoff delay itself gets applied
	// (1<<1 = 2s for attempt=1). Event should NOT be in the next claim
	// set when we poll immediately.
	if err := store.MarkFailed(ctx, id, 1, "boom", 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	claimed, _ := store.Claim(ctx, 10)
	if len(claimed) != 0 {
		t.Errorf("MarkFailed did not push next_attempt into the future: %d claimed", len(claimed))
	}

	// With maxDelay=0, next_attempt is pinned to now → visible again
	// on the next Claim.
	if err := store.MarkFailed(ctx, id, 2, "boom2", 0); err != nil {
		t.Fatal(err)
	}
	claimed, _ = store.Claim(ctx, 10)
	if len(claimed) != 1 {
		t.Errorf("MarkFailed+0-maxDelay should be immediately retryable: got %d", len(claimed))
	}
	if claimed[0].LastError != "boom2" {
		t.Errorf("last_error: got %q", claimed[0].LastError)
	}
}

func TestOutboxStore_Claim_DefaultsBatchSize(t *testing.T) {
	// batchSize<=0 uses the default.
	store := NewOutboxStore(newTestDB(t))
	got, err := store.Claim(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty outbox, want 0 claims, got %d", len(got))
	}
}

func TestMinInt(t *testing.T) {
	if minInt(3, 7) != 3 {
		t.Error("minInt(3,7) != 3")
	}
	if minInt(7, 3) != 3 {
		t.Error("minInt(7,3) != 3")
	}
	if minInt(5, 5) != 5 {
		t.Error("minInt(5,5) != 5")
	}
}

// ----- RevocationStore -----
//
// agent_revocations has a FK to agent_registrations.id, so tests
// seed a parent row first.

// seedAgent creates an agent row and returns its ID + AnsName for
// the FK. Tests use it as the registration_id on the revocation.
func seedAgent(t *testing.T, db *DB, agentID, host string) (int64, domain.AnsName) {
	t.Helper()
	agents := NewAgentStore(db)
	a := newAgentFixture(t, agentID, host)
	if err := agents.Save(context.Background(), a); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return a.ID, a.AnsName
}

func TestRevocationStore_SaveAndFind(t *testing.T) {
	db := newTestDB(t)
	store := NewRevocationStore(db)
	ctx := context.Background()

	regID, ansName := seedAgent(t, db, "rev-agent", "revoked.example.com")
	rev := &domain.AgentRevocation{
		RegistrationID: regID,
		AgentID:        "rev-agent",
		AnsName:        ansName,
		PreviousStatus: domain.StatusActive,
		Reason:         domain.RevocationKeyCompromise,
		Comments:       "test note",
		RevokedAt:      time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := store.Save(ctx, rev); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := store.FindByAgentID(ctx, "rev-agent")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.AgentID != "rev-agent" {
		t.Errorf("mismatch: got %+v", got)
	}
	if got.Comments != "test note" {
		t.Errorf("comments round-trip: got %q", got.Comments)
	}
	if got.Reason != domain.RevocationKeyCompromise {
		t.Errorf("reason: got %q", got.Reason)
	}
}

func TestRevocationStore_SaveWithoutComments(t *testing.T) {
	// Exercises the `comments == ""` → NULL branch.
	db := newTestDB(t)
	store := NewRevocationStore(db)
	ctx := context.Background()
	regID, ansName := seedAgent(t, db, "a", "r.example.com")
	if err := store.Save(ctx, &domain.AgentRevocation{
		RegistrationID: regID, AgentID: "a", AnsName: ansName,
		PreviousStatus: domain.StatusActive,
		Reason:         domain.RevocationCessationOfOperation,
		RevokedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.FindByAgentID(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Comments != "" {
		t.Errorf("want empty comments, got %q", got.Comments)
	}
}

func TestRevocationStore_FindByAgentID_NotFound(t *testing.T) {
	store := NewRevocationStore(newTestDB(t))
	_, err := store.FindByAgentID(context.Background(), "missing")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

// ----- isUniqueViolation + DBX coverage is exercised by TestAgentStore_Save_UniqueAnsNameViolation + TestDB_DBX above -----
