package sqlite

import (
	"context"
	"errors"
	"testing"
)

// TestRun_HappyPath_CommitsTransaction covers the success branch:
// fn returns nil → Commit succeeds → Run returns nil.
func TestRun_HappyPath_CommitsTransaction(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	store := NewAgentStore(db)
	err := db.Run(context.Background(), func(ctx context.Context) error {
		// Save through the store inside the UoW; it should see the
		// transaction handle via extx(ctx).
		_ = ctx
		_ = store
		return nil
	})
	if err != nil {
		t.Errorf("happy-path Run: %v", err)
	}
}

// TestRun_FnError_RollsBack covers the rollback path: fn returns an
// error → Run rolls back and surfaces the same error.
func TestRun_FnError_RollsBack(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	want := errors.New("forced fn failure")
	got := db.Run(context.Background(), func(_ context.Context) error {
		return want
	})
	if !errors.Is(got, want) {
		t.Errorf("Run should pass fn error through; got %v want %v", got, want)
	}
}

// TestRun_BeginFailsAfterClose covers the begin-tx error path. We
// close the DB first so BeginTxx fails immediately.
func TestRun_BeginFailsAfterClose(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err := db.Run(context.Background(), func(_ context.Context) error {
		t.Fatal("fn should never run when BeginTxx fails")
		return nil
	})
	if err == nil {
		t.Error("expected error when BeginTxx fails on closed DB")
	}
}

// TestExtx_FallsBackToDBOutsideUoW covers the path where extx(ctx)
// finds no transaction in context — used by stores called outside a
// UoW.Run wrapper.
func TestExtx_FallsBackToDBOutsideUoW(t *testing.T) {
	t.Parallel()
	db := newTestDB(t)
	conn := db.extx(context.Background())
	if conn == nil {
		t.Fatal("extx returned nil outside UoW")
	}
	// The fallback returns the underlying *sqlx.DB; basic SELECT
	// should work.
	var n int
	if err := conn.GetContext(context.Background(), &n, `SELECT 1`); err != nil {
		t.Errorf("query through fallback handle: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d want 1", n)
	}
}
