package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
)

func TestOutboxClaimsFenceSeparateConnectionsAndCancellation(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "shared.db")
	first, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	a, b := sqlite.NewOutboxStore(first), sqlite.NewOutboxStore(second)
	id, err := a.Enqueue(ctx, "AGENT_RENEWED", "agent", "V2", []byte(`{"signed":"unchanged"}`), time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := a.Acquire(ctx, id, 0, "worker-a", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("first claim: %v, %v", acquired, err)
	}
	acquired, err = b.Acquire(ctx, id, 0, "worker-b", time.Minute)
	if err != nil || acquired {
		t.Fatalf("concurrent claim: %v, %v", acquired, err)
	}
	if _, err := first.DBX().Exec(`UPDATE outbox_events SET claimed_until_ms = 0 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	acquired, err = b.Acquire(ctx, id, 0, "worker-b", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("crash recovery claim: %v, %v", acquired, err)
	}
	if err := a.MarkSent(ctx, id, "worker-a", "stale-log"); err == nil {
		t.Fatal("stale worker acknowledged reclaimed row")
	}
	if err := first.Run(ctx, func(txCtx context.Context) error { return a.CancelPending(txCtx, "agent") }); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkSent(ctx, id, "worker-b", "late-log"); err == nil {
		t.Fatal("cancelled in-flight row acknowledged")
	}
	var payload string
	if err := first.DBX().Get(&payload, `SELECT payload_json FROM outbox_events WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if payload != `{"signed":"unchanged"}` {
		t.Fatal("cancellation changed signed bytes")
	}
}

func TestRevocationBypassesPoisonAndCannotBeDeadLettered(t *testing.T) {
	db, err := sqlite.Open(t.Context(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.NewOutboxStore(db)
	first, err := store.Enqueue(t.Context(), "AGENT_RENEWED", "agent", "V2", []byte(`{}`), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	revoke, err := store.Enqueue(t.Context(), "AGENT_REVOKED", "agent", "V2", []byte(`{}`), time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.Ready(t.Context(), 10)
	if err != nil || len(rows) != 1 || rows[0].ID != revoke {
		t.Fatalf("revocation blocked: %+v, %v", rows, err)
	}
	if err := store.MarkDead(t.Context(), revoke, "", "permanent rejection"); err == nil {
		t.Fatal("revocation dead-lettered")
	}
	if err := store.MarkDead(t.Context(), first, "", "malformed"); err != nil {
		t.Fatal(err)
	}
	backlog, err := store.Backlog(t.Context())
	if err != nil || backlog.Pending != 1 || backlog.Dead != 1 {
		t.Fatalf("backlog: %+v, %v", backlog, err)
	}
}
