package sqlitetl

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jmoiron/sqlx"

	identityevent "github.com/agentnameservice/ans/internal/tl/event/identity"
)

func TestDuplicateLeafMigration_PreservesExistingIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.db")
	conn, err := sqlx.ConnectContext(t.Context(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &DB{db: conn}
	t.Cleanup(func() { _ = legacy.Close() })
	if _, err := conn.ExecContext(t.Context(), `CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at_ms INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	// Build the schema that shipped before the ingestion/recovery changes.
	for _, name := range []string{
		"001_initial.sql", "002_producer_keys.sql",
		"003_schema_version.sql", "004_identity_events.sql",
	} {
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(t.Context(), string(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(t.Context(),
			`INSERT INTO schema_migrations VALUES (?, 1)`, name); err != nil {
			t.Fatal(err)
		}
	}
	insertRawEvent(t, legacy, 0, "agent-before-upgrade")
	store := NewEventStore(legacy)
	storeIdentityEvent(t, store, 1, buildIdentityEnvelope(t,
		identityevent.TypeIdentityLinked, "identity-before-upgrade", []string{"agent-before-upgrade"}))
	var before []EventRecord
	if err := conn.SelectContext(t.Context(), &before,
		`SELECT `+eventCols+` FROM tl_events ORDER BY leaf_index`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	var after []EventRecord
	if err := upgraded.db.SelectContext(t.Context(), &after,
		`SELECT `+eventCols+` FROM tl_events ORDER BY leaf_index`); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("migration changed existing event bytes or index metadata")
	}
	var links int
	if err := upgraded.db.GetContext(t.Context(), &links, `
		SELECT COUNT(*) FROM tl_identity_event_agents a
		JOIN tl_events e ON e.leaf_index = a.leaf_index
		WHERE a.identity_id = ? AND a.ans_id = ?`,
		"identity-before-upgrade", "agent-before-upgrade"); err != nil || links != 1 {
		t.Fatalf("migration lost the identity/agent association: count=%d err=%v", links, err)
	}
	var integrity string
	if err := upgraded.db.GetContext(t.Context(), &integrity, "PRAGMA integrity_check"); err != nil || integrity != "ok" {
		t.Fatalf("migrated database integrity: %q err=%v", integrity, err)
	}
}
