-- A mirror must represent every committed leaf, including duplicate producer
-- events appended by older writers before their index INSERT failed. Content
-- deduplication now runs before append under the single-writer ingest gate.
-- Keep leaf_index unique, but allow recovery to index historical duplicates
-- without changing any signed envelope or Merkle-tree bytes.
CREATE TABLE tl_events_recovered (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    leaf_index      INTEGER NOT NULL UNIQUE,
    leaf_hash       TEXT    NOT NULL,
    event_hash      TEXT    NOT NULL,
    log_id          TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    ans_name        TEXT    NOT NULL,
    agent_fqdn      TEXT    NOT NULL DEFAULT '',
    event_type      TEXT    NOT NULL,
    raw_event       TEXT    NOT NULL CHECK (json_valid(raw_event)),
    created_at_ms   INTEGER NOT NULL,
    schema_version  TEXT    NOT NULL DEFAULT 'V2'
        CHECK (schema_version IN ('V0', 'V1', 'V2')),
    identity_id     TEXT
);

INSERT INTO tl_events_recovered (
    id, leaf_index, leaf_hash, event_hash, log_id, agent_id, ans_name,
    agent_fqdn, event_type, raw_event, created_at_ms, schema_version, identity_id
)
SELECT id, leaf_index, leaf_hash, event_hash, log_id, agent_id, ans_name,
       agent_fqdn, event_type, raw_event, created_at_ms, schema_version, identity_id
FROM tl_events;

DROP TABLE tl_events;
ALTER TABLE tl_events_recovered RENAME TO tl_events;

CREATE INDEX idx_tl_events_agent_leaf ON tl_events(agent_id, leaf_index DESC);
CREATE INDEX idx_tl_events_fqdn ON tl_events(agent_fqdn);
CREATE INDEX idx_tl_events_identity_leaf
    ON tl_events(identity_id, leaf_index DESC) WHERE identity_id IS NOT NULL;
CREATE INDEX idx_tl_events_ans_name_leaf ON tl_events(ans_name, leaf_index DESC);
CREATE INDEX idx_tl_events_event_hash_leaf ON tl_events(event_hash, leaf_index);
