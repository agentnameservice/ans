package sqlitefinder

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/agentnameservice/ans/internal/finder/index"
)

// TestMigration002_RepopulatesFTSFromExistingRows exercises the upgrade
// path a deployed Finder takes: a database created at schema 001 —
// with entries already indexed under the four-column FTS shape — is
// opened by a binary that ships 002. FTS5 has no ALTER TABLE, so 002
// drops and recreates the FTS table; this test proves the repopulation
// preserves the existing searchable text (display, capabilities) AND
// makes the publisher host searchable, without replaying the feed.
//
// Setup applies 001 verbatim from the embedded FS (not a hand-copied
// schema, so the test cannot drift from what shipped), seeds one ACTIVE
// and one REVOKED row exactly as the 001-era store would have left them
// (the revoked row has no FTS row — tombstones clear it), then lets
// Open apply 002.
func TestMigration002_RepopulatesFTSFromExistingRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "finder.db")

	seedSchema001(ctx, t, path)

	// Open applies pending migrations — only 002 here.
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open at schema 002: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// The upgrade must be observable: callers log AppliedMigrations at
	// startup, so it has to report exactly the migration that ran.
	if got := s.AppliedMigrations(); len(got) != 1 || got[0] != "002_fts_publisher.sql" {
		t.Fatalf("AppliedMigrations = %v, want [002_fts_publisher.sql]", got)
	}

	cases := []struct {
		name string
		text string
		want int
	}{
		{name: "publisher host token now matches", text: "translator", want: 1},
		{name: "pre-existing display text preserved", text: "converter", want: 1},
		{name: "pre-existing description text preserved", text: "conversion", want: 1},
		{name: "pre-existing capabilities text preserved", text: "translate_text", want: 1},
		{name: "pre-existing tags text preserved", text: "linguistics", want: 1},
		{name: "revoked row not resurrected into FTS", text: "revokedhost", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Search(ctx, index.SearchQuery{Text: tc.text, Limit: 10},
				time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatalf("search %q: %v", tc.text, err)
			}
			if len(res.Results) != tc.want {
				t.Fatalf("text %q: got %d results, want %d", tc.text, len(res.Results), tc.want)
			}
		})
	}
}

// seedSchema001 builds a database exactly as a 001-era store would have
// left it: 001 applied and recorded, one ACTIVE row with side values and
// a four-column FTS row, one REVOKED row with blanked display fields and
// no FTS or side rows.
func seedSchema001(ctx context.Context, t *testing.T, path string) {
	t.Helper()

	body, err := migrationsFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatalf("read embedded 001: %v", err)
	}

	db, err := sqlx.ConnectContext(ctx, "sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("connect for seed: %v", err)
	}
	defer func() { _ = db.Close() }()

	stmts := []string{
		`CREATE TABLE schema_migrations (
            version       TEXT PRIMARY KEY,
            applied_at_ms INTEGER NOT NULL
        )`,
		string(body),
		`INSERT INTO schema_migrations(version, applied_at_ms)
         VALUES('001_initial.sql', 0)`,

		// ACTIVE row: display fields share no tokens with the host, so a
		// post-migration host match can only come from the new column.
		`INSERT INTO finder_entries (
            id, ans_name, type, url, identifier, publisher, agent_id, log_id,
            display_name, description, lifecycle, created_at, entry_json
        ) VALUES (
            1, 'ans://v1.0.0.translator.example.com',
            'application/mcp-server-card+json',
            'https://translator.example.com/.well-known/mcp.json',
            'urn:air:translator.example.com:agents:converter',
            'translator.example.com', 'agent-1', 'log-1',
            'converter', 'language conversion service',
            'ACTIVE', '2025-01-01T00:00:00Z',
            '{"identifier":"urn:air:translator.example.com:agents:converter","displayName":"converter"}'
        )`,
		`INSERT INTO finder_entry_capabilities (entry_rowid, value)
         VALUES (1, 'translate_text')`,
		`INSERT INTO finder_entry_tags (entry_rowid, value)
         VALUES (1, 'linguistics')`,
		`INSERT INTO finder_entries_fts (
            rowid, display_name, description, capabilities_text, tags_text
        ) VALUES (1, 'converter', 'language conversion service', 'translate_text', 'linguistics')`,

		// REVOKED row, as a tombstone leaves it: blanked display fields,
		// no FTS row, no side rows. 002 must not give it one.
		`INSERT INTO finder_entries (
            id, ans_name, type, url, identifier, publisher, agent_id, log_id,
            display_name, description, lifecycle, created_at, entry_json
        ) VALUES (
            2, 'ans://v1.0.0.revokedhost.example.com',
            'application/mcp-server-card+json',
            'https://revokedhost.example.com/.well-known/mcp.json',
            'urn:air:revokedhost.example.com:agents:gone',
            'revokedhost.example.com', 'agent-2', 'tomb-2',
            '', '', 'REVOKED', '2025-02-01T00:00:00Z', '{}'
        )`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed stmt failed: %v\n%s", err, stmt)
		}
	}
}
