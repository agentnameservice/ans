-- Stage V1-parity: the TL now accepts events in two schema
-- versions (V1 + V2) depending on which RA surface ingested them.
-- Each leaf already carries `schemaVersion` inside the JCS'd
-- envelope JSON, but hoisting that to a column means:
--
--   - per-agent badge/audit queries can return the correct
--     `TransparencyLog.schemaVersion` without re-parsing raw_event
--   - filter queries ("all V1 events" or "all V2 events") are
--     index-only rather than JSON-parse-per-row
--
-- Backfill: rows inserted before this migration are V2 by
-- definition (the /v2/ans/agents/* RA routes were the only
-- producer up to this point). We set the default to 'V2' for
-- existing + backward-compat rows; V1 ingest (added alongside)
-- writes 'V1' explicitly.

ALTER TABLE tl_events
    ADD COLUMN schema_version TEXT NOT NULL DEFAULT 'V2'
        CHECK (schema_version IN ('V0', 'V1', 'V2'));

-- The badge endpoint reads the newest event per agent; an index
-- that lets us filter by (agent, version) later would help, but
-- queries today just project the existing (agent, leaf_index)
-- index and extract schema_version from the matching row — no
-- new index needed.
