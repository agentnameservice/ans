-- 006_outbox_log_id.sql
-- Record the TL-assigned logId on each successfully-delivered outbox
-- row so the agent-events feed (GET /v1/agents/events) can serve a
-- stable, strictly-ordered cursor without re-deriving it.
--
-- The TL's ingest response already echoes `logId` on every append
-- (and on idempotent duplicate retries — see AppendResult.LogID in
-- internal/adapter/tlclient/client.go); migration 006 just lets the
-- worker persist it alongside `sent_at_ms` when it marks the row sent.
--
-- The column is nullable: it stays NULL until the worker delivers the
-- row. The feed gates on `sent_at_ms IS NOT NULL AND log_id IS NOT
-- NULL` so an item only surfaces once it is provably sealed in the
-- log and a receipt is resolvable from its logId.
--
-- Backfill: rows already marked sent before this migration have no
-- recorded logId and stay NULL. They are therefore invisible to the
-- feed — acceptable because the feed is bounded by a retention window
-- (default 30d) and pre-migration rows age out; no historical TL data
-- is lost (it lives in the log itself).

ALTER TABLE outbox_events ADD COLUMN log_id TEXT;

-- Cursor resolution: the feed turns a caller's `lastLogId` into the
-- outbox id to page after via `WHERE log_id = ?`. Without an index this
-- is a full table scan on every cursored request — and the Finder polls
-- with a cursor every interval, on an unauthenticated route, over a
-- table that is never pruned. Index it.
--
-- NOT unique: the TL content-hash-dedupes events, so two distinct
-- outbox rows whose inner events canonicalize identically would receive
-- the same logId (duplicate append). A UNIQUE index would make the
-- second row's MarkSent UPDATE fail and wedge a delivered row in
-- permanent retry. The store instead resolves a logId deterministically
-- to its lowest outbox id (ORDER BY id LIMIT 1 in resolveCursor), which
-- removes the ambiguity without risking a write failure.
CREATE INDEX IF NOT EXISTS idx_outbox_log_id
    ON outbox_events(log_id)
    WHERE log_id IS NOT NULL;

-- Feed read path: serve delivered+logged rows within the retention
-- window, ordered by outbox id. The index leads with created_at_ms so
-- the retention floor (`created_at_ms >= ?`) is an index SEARCH range
-- rather than a scan that skips every aged-out row, then carries id for
-- the `id > cursor` range and the ORDER BY id. Anonymous clients drive
-- the no-cursor path at will, and the aged-out prefix grows for the life
-- of the deployment, so this must not be a SCAN.
CREATE INDEX IF NOT EXISTS idx_outbox_feed
    ON outbox_events(created_at_ms, id)
    WHERE sent_at_ms IS NOT NULL AND log_id IS NOT NULL;
