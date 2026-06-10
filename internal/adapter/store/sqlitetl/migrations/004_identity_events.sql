-- Identity events: the Verified Identities (the "who") event family.
--
-- There is ONE transparency log — a single Merkle tree. Identity
-- events append to the same tree as agent events and mirror into the
-- same tl_events table; the "identity stream" is nothing more than a
-- read index over that single log, keyed by identity_id. This is the
-- normative model: streams are read indexes, never separate trees.
--
-- identity_id is NULL for agent events and set for IDENTITY_* events
-- (whose agent_id / ans_name columns are '' — an identity event names
-- no single agent). The partial index keeps the identity read path
-- O(log n) without taxing the agent-event hot path.
ALTER TABLE tl_events ADD COLUMN identity_id TEXT;

CREATE INDEX IF NOT EXISTS idx_tl_events_identity_leaf
    ON tl_events(identity_id, leaf_index DESC)
    WHERE identity_id IS NOT NULL;

-- tl_identity_event_agents is the read-join index for link events.
--
-- IDENTITY_LINKED / IDENTITY_UNLINKED seal ONE event on the identity
-- stream carrying the whole batch in ansIds[]; this table fans those
-- ids out so reads can join in both directions:
--
--   - badge join: "which identities are currently linked to agent X?"
--     → latest row per identity_id for ans_id = X, keep LINKED ones.
--   - association history: "which link events ever named agent X?"
--     → all rows for ans_id = X, resolved to tl_events by leaf_index.
--
-- The rows are derivable from the log (they mirror sealed events) —
-- this is an index, not a source of truth. Agent streams are never
-- written by identity operations; this table is how reads cross over.
CREATE TABLE IF NOT EXISTS tl_identity_event_agents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    leaf_index      INTEGER NOT NULL,
    identity_id     TEXT    NOT NULL,
    ans_id          TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,  -- IDENTITY_LINKED | IDENTITY_UNLINKED
    created_at_ms   INTEGER NOT NULL,
    UNIQUE(leaf_index, ans_id)
);

CREATE INDEX IF NOT EXISTS idx_tl_identity_event_agents_ans
    ON tl_identity_event_agents(ans_id, leaf_index DESC);

CREATE INDEX IF NOT EXISTS idx_tl_identity_event_agents_identity
    ON tl_identity_event_agents(identity_id, leaf_index DESC);
