-- Claims are durable across workers sharing this database. Cancellation fences
-- acknowledgements from workers that already had a request in flight.
ALTER TABLE outbox_events ADD COLUMN claim_token TEXT;
ALTER TABLE outbox_events ADD COLUMN claimed_until_ms INTEGER;
ALTER TABLE outbox_events ADD COLUMN dead_at_ms INTEGER;
ALTER TABLE outbox_events ADD COLUMN cancelled_at_ms INTEGER;
ALTER TABLE outbox_events ADD COLUMN permanent_attempts INTEGER NOT NULL DEFAULT 0;
DROP INDEX idx_outbox_pending_agent_order;
CREATE INDEX idx_outbox_pending_agent_order ON outbox_events(agent_id, id)
    WHERE sent_at_ms IS NULL AND dead_at_ms IS NULL AND cancelled_at_ms IS NULL;
