-- Version is part of the canonical ANS name. State validation consults its
-- latest event; AGENT_RENEWED intentionally remains repeatable with new certs.
CREATE INDEX IF NOT EXISTS idx_tl_events_ans_name_leaf
    ON tl_events(ans_name, leaf_index DESC);
