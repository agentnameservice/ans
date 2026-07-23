-- Add the publisher host to the free-text search surface.
--
-- The publisher (the agent's verified host, the URN's <publisher>
-- segment) is the one text every entry reliably carries, and the first
-- thing a user types when they know the agent's domain — but 001 indexed
-- it only as a structured-filter column on the base table, so free-text
-- "translator" found nothing for translator.example.com unless the
-- publisher happened to repeat the word in its display fields. Adding
-- the column to the FTS table makes host words match: unicode61 treats
-- "." as a token separator, so translator.example.com indexes as the
-- tokens translator / example / com. Shared TLD tokens ("example",
-- "com") appear in nearly every row and bm25 down-weights them
-- accordingly, so they add no meaningful noise.
--
-- FTS5 virtual tables do not support ALTER TABLE ADD COLUMN, so the
-- table is dropped and recreated with the new shape, then repopulated
-- from the base + side tables. Repopulation is self-contained — no feed
-- replay — because every indexed value survives outside the FTS copy:
-- display_name/description/publisher on finder_entries, capabilities
-- and tags in their side tables (group_concat ORDER BY rowid mirrors
-- insertFTS's space-joining in insertion order). Only ACTIVE rows are
-- rebuilt: that is the runtime invariant (insertActiveRow adds the FTS
-- row, tombstone suppression deletes it), and rebuilding a
-- REVOKED/DEPRECATED row would resurrect it into search results.
--
-- Who this migration protects: any deployment created from a released
-- 001-schema binary (v0.1.x and later ship the finder). Amending 001 in
-- place would silently skip those databases, whose 001 row is already
-- recorded in schema_migrations.
DROP TABLE finder_entries_fts;

CREATE VIRTUAL TABLE finder_entries_fts USING fts5(
    display_name,
    description,
    capabilities_text,
    tags_text,
    publisher,
    tokenize='unicode61 remove_diacritics 2'
);

INSERT INTO finder_entries_fts (
    rowid, display_name, description, capabilities_text, tags_text, publisher
)
SELECT
    e.id,
    e.display_name,
    e.description,
    COALESCE((SELECT group_concat(c.value, ' ' ORDER BY c.rowid)
                FROM finder_entry_capabilities c
               WHERE c.entry_rowid = e.id), ''),
    COALESCE((SELECT group_concat(t.value, ' ' ORDER BY t.rowid)
                FROM finder_entry_tags t
               WHERE t.entry_rowid = e.id), ''),
    e.publisher
FROM finder_entries e
WHERE e.lifecycle = 'ACTIVE';
