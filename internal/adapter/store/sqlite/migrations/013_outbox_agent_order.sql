CREATE INDEX IF NOT EXISTS idx_outbox_pending_agent_order
    ON outbox_events(agent_id, id)
    WHERE sent_at_ms IS NULL;
