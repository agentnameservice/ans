-- Third outbox lane: identity events.
--
-- The schema_version column routes each outbox row to its TL ingest
-- lane ('V1' → /v1/internal/agents/event, 'V2' →
-- /v2/internal/agents/event). Identity events ride a third lane,
-- 'IDENTITY' → /v1/internal/identities/event — same producer
-- signature, same replay-verbatim invariant, different inner-event
-- schema (keyed by identityId).
--
-- SQLite cannot widen a column CHECK in place, so this rebuilds the
-- table with the widened constraint (the standard
-- create-copy-drop-rename dance; the migration runner wraps it in one
-- transaction). Index is recreated to match 001's definition.
CREATE TABLE outbox_events_new (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type         TEXT    NOT NULL,
    agent_id           TEXT    NOT NULL,
    schema_version     TEXT    NOT NULL DEFAULT 'V2'
        CHECK (schema_version IN ('V1', 'V2', 'IDENTITY')),
    payload_json       TEXT    NOT NULL CHECK (json_valid(payload_json)),
    attempts           INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT,
    next_attempt_at_ms INTEGER NOT NULL,
    sent_at_ms         INTEGER,
    created_at_ms      INTEGER NOT NULL
);

INSERT INTO outbox_events_new (
    id, event_type, agent_id, schema_version, payload_json,
    attempts, last_error, next_attempt_at_ms, sent_at_ms, created_at_ms
)
SELECT id, event_type, agent_id, schema_version, payload_json,
       attempts, last_error, next_attempt_at_ms, sent_at_ms, created_at_ms
FROM outbox_events;

DROP TABLE outbox_events;

ALTER TABLE outbox_events_new RENAME TO outbox_events;

CREATE INDEX IF NOT EXISTS idx_outbox_next
    ON outbox_events(sent_at_ms, next_attempt_at_ms);
