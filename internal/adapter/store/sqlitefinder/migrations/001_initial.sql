-- Finder catalog index schema.
--
-- One row per projected catalog entry. An AGENT_REGISTERED /
-- AGENT_RENEWED event fans out into one entry per discoverable endpoint,
-- so a single agent registration can occupy several rows sharing an
-- ans_name but differing by (type, url). The primary key is therefore
-- (ans_name, type, url): re-applying the same registration replaces its
-- own rows in place, which keeps Apply idempotent.
--
-- Lifecycle: 'ACTIVE' rows are discoverable; a tombstone flips every row
-- for an ans_name to 'REVOKED' / 'DEPRECATED' and nulls the searchable
-- display fields, so a revoked agent never surfaces again. created_at
-- (the sealing event's RFC 3339 timestamp, stored as text) orders
-- suppression: a tombstone only applies when it is at least as new as the
-- rows it would suppress.
CREATE TABLE finder_entries (
    -- Explicit rowid alias. A composite-PK table hides its rowid, which a
    -- foreign key cannot then reference; an INTEGER PRIMARY KEY column is
    -- the rowid under a stable name the side-table FKs can point at. The
    -- per-registration key is a separate UNIQUE constraint below.
    id INTEGER PRIMARY KEY,

    -- Per-registration key. ans_name binds to one registration; type+url
    -- distinguish the endpoints a single registration fans out into.
    ans_name TEXT NOT NULL,
    type     TEXT NOT NULL,
    url      TEXT NOT NULL,

    -- Identity / correlation columns lifted out of the entry for filtering
    -- and tombstone application.
    identifier TEXT NOT NULL DEFAULT '',
    publisher  TEXT NOT NULL DEFAULT '', -- URN <publisher> segment (agent host)
    agent_id   TEXT NOT NULL DEFAULT '',
    log_id     TEXT NOT NULL DEFAULT '',

    -- Free-text searchable columns (mirrored into the FTS5 table).
    display_name TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',

    version    TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',

    -- Lifecycle + ordering. created_at is the event timestamp verbatim;
    -- expires_at is the wrapper ExpiresAt (empty when the event carried
    -- none). Both are RFC 3339 text so lexical compare matches chronology
    -- for the Z-normalized values the feed emits.
    lifecycle  TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL DEFAULT '',

    -- The wire-ready project.Entry JSON, returned verbatim in search
    -- results so the handler never re-derives it.
    entry_json TEXT NOT NULL DEFAULT '',

    UNIQUE (ans_name, type, url)
);

-- Active-entry lookups: search and explore both scope to lifecycle =
-- 'ACTIVE', and tombstones address rows by ans_name.
CREATE INDEX idx_finder_entries_lifecycle ON finder_entries (lifecycle);
CREATE INDEX idx_finder_entries_ans_name ON finder_entries (ans_name);
CREATE INDEX idx_finder_entries_publisher ON finder_entries (publisher);
CREATE INDEX idx_finder_entries_type ON finder_entries (type);

-- Multi-valued filter/facet dimensions, normalized one value per row and
-- keyed by the owning entry's rowid. ON DELETE CASCADE keeps them in sync
-- when an entry row is replaced (delete-then-insert on upsert).
CREATE TABLE finder_entry_tags (
    entry_rowid INTEGER NOT NULL REFERENCES finder_entries(id) ON DELETE CASCADE,
    value       TEXT NOT NULL
);
CREATE INDEX idx_finder_entry_tags_rowid ON finder_entry_tags (entry_rowid);
CREATE INDEX idx_finder_entry_tags_value ON finder_entry_tags (value);

CREATE TABLE finder_entry_capabilities (
    entry_rowid INTEGER NOT NULL REFERENCES finder_entries(id) ON DELETE CASCADE,
    value       TEXT NOT NULL
);
CREATE INDEX idx_finder_entry_caps_rowid ON finder_entry_capabilities (entry_rowid);
CREATE INDEX idx_finder_entry_caps_value ON finder_entry_capabilities (value);

CREATE TABLE finder_entry_attestation_types (
    entry_rowid INTEGER NOT NULL REFERENCES finder_entries(id) ON DELETE CASCADE,
    value       TEXT NOT NULL
);
CREATE INDEX idx_finder_entry_att_rowid ON finder_entry_attestation_types (entry_rowid);
CREATE INDEX idx_finder_entry_att_value ON finder_entry_attestation_types (value);

-- FTS5 full-text index over the searchable fields. A standalone
-- (non-external-content) table: it keeps its own copy of the indexed
-- text, and the store manages its rows explicitly by rowid — INSERT on
-- upsert, a plain `DELETE FROM finder_entries_fts WHERE rowid = ?` on
-- removal/suppression (a standalone FTS5 table supports row deletes
-- directly, so the external-content 'delete' command protocol is not
-- needed — and modernc's FTS5 rejects it). Standalone rather than
-- external-content because two of the FTS columns (capabilities_text,
-- tags_text) are derived (space-joined from the normalized side-tables)
-- and have no matching column on the base table, so the external-content
-- reconstruction protocol would have nothing to read. The duplicated text
-- is small. tokenize unicode61 with diacritic folding gives case- and
-- accent-insensitive matching.
CREATE VIRTUAL TABLE finder_entries_fts USING fts5(
    display_name,
    description,
    capabilities_text,
    tags_text,
    tokenize='unicode61 remove_diacritics 2'
);

-- Singleton cursor row. id is pinned to 1 so SaveCursor upserts in place.
-- last_poll_ok_ms is 0 until the first successful poll completes.
CREATE TABLE finder_cursor (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    last_log_id     TEXT NOT NULL DEFAULT '',
    last_poll_ok_ms INTEGER NOT NULL DEFAULT 0
);
INSERT INTO finder_cursor (id, last_log_id, last_poll_ok_ms) VALUES (1, '', 0);
