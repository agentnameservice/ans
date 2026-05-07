-- Dual-schema outbox routing: each row carries the envelope schema
-- version it was serialized for, so the outbox worker can POST it to
-- the matching TL ingest lane.
--
-- Without this column the worker would have to peek inside
-- `payload_json` to decide between `/v1/internal/agents/event` and
-- `/v2/internal/agents/event` — that's both slower (JSON parse per
-- row) and couples the worker to the payload shape. Hoisting to a
-- column is O(1) lookup and keeps the worker shape-blind.
--
-- Backfill: rows inserted before this migration were written by the
-- V2 RA routes (the only RA surface we've had). Default to 'V2' for
-- those; the V1 RA routes (added next) will write 'V1' explicitly.

ALTER TABLE outbox_events
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'V2'
        CHECK (schema_version IN ('V1', 'V2'));

-- The worker scans by (sent_at_ms, next_attempt_at_ms) first; adding
-- schema_version to the existing index would widen it for no real
-- gain (the worker processes every pending row regardless of version
-- and just picks the URL per row). The schema-version filter is
-- diagnostic-only at the worker layer.
