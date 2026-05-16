-- 008_agent_ans_name_nullable.sql
--
-- ANS_SPEC.md §3.2.0 (base-only registrations) introduces a path where
-- the registrant submits NEITHER a version nor an Identity CSR — the
-- resulting registration has no ANSName at all and is identified by
-- FQDN alone. The pre-Plan-F schema declared ans_name as
-- "TEXT NOT NULL UNIQUE", which forced empty-string for base-only and
-- collided on the second base-only insert via the UNIQUE constraint
-- (two empty strings → 2067 UNIQUE violation).
--
-- This migration relaxes ans_name to NULLable. SQLite's default UNIQUE
-- behavior treats each NULL as distinct, so multiple base-only rows
-- coexist while versioned rows still get the uniqueness guarantee.
--
-- SQLite cannot ALTER COLUMN; the rebuild ceremony copies all data
-- through a temp table, swaps it in, and rebuilds dependent indexes.
-- The trailing UPDATE migrates any existing empty-string ans_name rows
-- to NULL so the new constraint is consistent.

CREATE TABLE agent_registrations_new (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id                      TEXT    NOT NULL UNIQUE,
    owner_id                      TEXT    NOT NULL,
    ans_name                      TEXT             UNIQUE,
    agent_host                    TEXT    NOT NULL,
    version                       TEXT    NOT NULL,
    status                        TEXT    NOT NULL,
    display_name                  TEXT,
    description                   TEXT,
    registration_timestamp_ms     INTEGER NOT NULL,
    last_renewal_timestamp_ms     INTEGER,
    supersedes_registration_id    INTEGER,
    acme_dns01_token              TEXT,
    acme_challenge_expires_at_ms  INTEGER,
    capabilities_hash             TEXT,
    dns_record_style              TEXT,
    created_at_ms                 INTEGER NOT NULL,
    updated_at_ms                 INTEGER NOT NULL
);

INSERT INTO agent_registrations_new
SELECT * FROM agent_registrations;

DROP TABLE agent_registrations;
ALTER TABLE agent_registrations_new RENAME TO agent_registrations;

UPDATE agent_registrations SET ans_name = NULL WHERE ans_name = '';

CREATE INDEX IF NOT EXISTS idx_agent_registrations_owner
    ON agent_registrations(owner_id);
CREATE INDEX IF NOT EXISTS idx_agent_registrations_host
    ON agent_registrations(agent_host);
CREATE INDEX IF NOT EXISTS idx_agent_registrations_status
    ON agent_registrations(status);
