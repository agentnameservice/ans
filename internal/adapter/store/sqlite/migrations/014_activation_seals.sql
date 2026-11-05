-- Synchronous activation evidence is durable before the network call.
-- These rows are not worker-claimable outbox jobs.
CREATE TABLE IF NOT EXISTS activation_seals (
    agent_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL CHECK (schema_version IN ('V1', 'V2')),
    payload_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
