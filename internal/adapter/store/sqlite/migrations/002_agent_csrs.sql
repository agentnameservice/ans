-- Generalize the identity-only CSR table into agent_csrs so server
-- CSRs can share the same storage. Matches the reference RA's
-- AgentCsr abstraction (discriminated union with identity and server
-- CSR variants). The schema is intentionally minimal — the only new
-- column versus 001 is `csr_type`.
--
-- SQLite doesn't have ALTER TABLE RENAME COLUMN on older versions,
-- but it has table RENAME and column ADD. We:
--   1. Rename identity_csrs → agent_csrs (preserves existing rows
--      which are all IDENTITY-type by construction).
--   2. Add csr_type column with a default of 'IDENTITY' so any row
--      carried over is correctly typed.
--   3. Drop the default (via a no-op — SQLite CHECK constraint
--      enforces the valid set instead).
--
-- The type column is CHECKed against the two-value set to keep bad
-- data out of the store — the handler validates too, but the DB
-- constraint is the belt-and-braces defense.

ALTER TABLE identity_csrs RENAME TO agent_csrs;

ALTER TABLE agent_csrs
    ADD COLUMN csr_type TEXT NOT NULL DEFAULT 'IDENTITY'
        CHECK (csr_type IN ('IDENTITY', 'SERVER'));

-- Drop + recreate the agent index under the new table name.
DROP INDEX IF EXISTS idx_identity_csrs_agent;
CREATE INDEX IF NOT EXISTS idx_agent_csrs_agent
    ON agent_csrs(agent_id);

-- Secondary index on (agent_id, csr_type) for the reference's
-- lookup patterns — "latest pending server CSR for this agent"
-- and "is there an identity CSR pending". Cheap to maintain and
-- makes the status-page queries index-only.
CREATE INDEX IF NOT EXISTS idx_agent_csrs_agent_type
    ON agent_csrs(agent_id, csr_type, status);
