-- Initial schema for the ans-tl SQLite index.
--
-- Tessera owns the Merkle tree, tiles, and checkpoints on disk (POSIX
-- storage). These tables are a searchable mirror that lets us answer
-- "what events exist for agent X?" and serve cached receipts without
-- walking the tree.

-- tl_events mirrors Tessera-appended leaves with a searchable index.
--
-- Hash columns (two of them — each answers a different question):
--   leaf_hash  = hex of RFC 6962 §2.1 leaf hash: SHA-256(0x00 || JCS(envelope))
--                Matches what Tessera computed internally; used when
--                walking an inclusion proof back to the checkpoint root.
--   event_hash = hex of SHA-256(JCS(inner producer event)).
--                UNIQUE — this is the dedup key. If the RA outbox
--                retries the same signed event, the content hash is
--                identical and the INSERT fails, making retries safely
--                idempotent without extra bookkeeping.
--
-- log_id is the TL-assigned UUIDv7 stamped onto each envelope's
-- Payload.LogID. Informative only (not a dedup key): a retry of the
-- same event gets a fresh logId on each append attempt, which is why
-- uniqueness lives on event_hash instead.
CREATE TABLE IF NOT EXISTS tl_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    leaf_index      INTEGER NOT NULL UNIQUE,
    leaf_hash       TEXT    NOT NULL,
    event_hash      TEXT    NOT NULL UNIQUE,
    log_id          TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    ans_name        TEXT    NOT NULL,
    agent_fqdn      TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL,
    raw_event       TEXT    NOT NULL CHECK (json_valid(raw_event)),
    created_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tl_events_agent_leaf
    ON tl_events(agent_id, leaf_index DESC);

CREATE INDEX IF NOT EXISTS idx_tl_events_fqdn
    ON tl_events(agent_fqdn);

CREATE TABLE IF NOT EXISTS tl_checkpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size       INTEGER NOT NULL,
    tree_hash_hex   TEXT    NOT NULL UNIQUE,
    checkpoint_raw  TEXT    NOT NULL, -- full sumdb note text including signatures
    origin          TEXT    NOT NULL,
    created_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tl_checkpoints_size
    ON tl_checkpoints(tree_size DESC);

CREATE TABLE IF NOT EXISTS tl_receipts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    leaf_index      INTEGER NOT NULL,
    agent_id        TEXT    NOT NULL,
    tree_size       INTEGER NOT NULL,
    receipt_blob    BLOB    NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    UNIQUE(leaf_index, tree_size)
);

CREATE INDEX IF NOT EXISTS idx_tl_receipts_agent
    ON tl_receipts(agent_id, leaf_index DESC);
