-- 001_initial.sql
-- Initial schema for the ans-ra SQLite store.
--
-- Guidelines:
--   * All monetary timestamps use INTEGER milliseconds-since-epoch.
--   * Text columns storing JSON use TEXT with a CHECK(json_valid(...)).
--   * Every row has created_at for audit ordering.

CREATE TABLE IF NOT EXISTS agent_registrations (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id                      TEXT    NOT NULL UNIQUE,
    owner_id                      TEXT    NOT NULL,
    ans_name                      TEXT    NOT NULL UNIQUE,
    agent_host                    TEXT    NOT NULL,
    version                       TEXT    NOT NULL,
    status                        TEXT    NOT NULL,
    display_name                  TEXT    NOT NULL DEFAULT '',
    description                   TEXT    NOT NULL DEFAULT '',
    registration_timestamp_ms     INTEGER NOT NULL,
    last_renewal_timestamp_ms     INTEGER,
    supersedes_registration_id    INTEGER,
    created_at_ms                 INTEGER NOT NULL,
    updated_at_ms                 INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_registrations_owner
    ON agent_registrations(owner_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_registrations_host
    ON agent_registrations(agent_host);
CREATE INDEX IF NOT EXISTS idx_agent_registrations_status
    ON agent_registrations(status);

CREATE TABLE IF NOT EXISTS agent_endpoints (
    agent_id   TEXT    NOT NULL,
    endpoints  TEXT    NOT NULL CHECK (json_valid(endpoints)),
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (agent_id)
);

CREATE TABLE IF NOT EXISTS identity_csrs (
    csr_id                  TEXT PRIMARY KEY,
    agent_id                TEXT NOT NULL,
    csr_pem                 TEXT NOT NULL,
    status                  TEXT NOT NULL,
    submission_timestamp_ms INTEGER NOT NULL,
    processed_timestamp_ms  INTEGER,
    rejection_reason        TEXT,
    FOREIGN KEY (agent_id) REFERENCES agent_registrations(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_identity_csrs_agent
    ON identity_csrs(agent_id);

CREATE TABLE IF NOT EXISTS issued_certificates (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id                 TEXT    NOT NULL,
    csr_id                   TEXT    NOT NULL,
    certificate_type         TEXT    NOT NULL,
    certificate_pem          TEXT    NOT NULL,
    chain_pem                TEXT,
    status                   TEXT    NOT NULL,
    issue_timestamp_ms       INTEGER NOT NULL,
    expiration_timestamp_ms  INTEGER NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agent_registrations(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_issued_certs_agent
    ON issued_certificates(agent_id, certificate_type);

CREATE TABLE IF NOT EXISTS byoc_certificates (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id                TEXT    NOT NULL,
    leaf_pem                TEXT    NOT NULL,
    chain_pem               TEXT,
    cn                      TEXT    NOT NULL,
    sans                    TEXT    NOT NULL CHECK (json_valid(sans)),
    issuer_dn               TEXT    NOT NULL,
    valid_from_ms           INTEGER NOT NULL,
    valid_to_ms             INTEGER NOT NULL,
    fingerprint             TEXT    NOT NULL,
    created_at_ms           INTEGER NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agent_registrations(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_byoc_agent
    ON byoc_certificates(agent_id, valid_to_ms DESC);

CREATE TABLE IF NOT EXISTS server_cert_renewals (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id               TEXT    NOT NULL,
    registration_id        INTEGER NOT NULL,
    renewal_type           TEXT    NOT NULL,
    byoc_cert_pem          TEXT,
    byoc_chain_pem         TEXT,
    dns01_token            TEXT    NOT NULL,
    http01_token           TEXT    NOT NULL,
    validation_status      TEXT    NOT NULL,
    validation_expires_ms  INTEGER NOT NULL,
    failure_reason         TEXT,
    completed_at_ms        INTEGER,
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL,
    FOREIGN KEY (registration_id) REFERENCES agent_registrations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_renewals_pending
    ON server_cert_renewals(agent_id, completed_at_ms);

CREATE TABLE IF NOT EXISTS agent_revocations (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_id       INTEGER NOT NULL,
    agent_id              TEXT    NOT NULL,
    ans_name              TEXT    NOT NULL,
    previous_status       TEXT    NOT NULL,
    reason                TEXT    NOT NULL,
    comments              TEXT,
    revoked_at_ms         INTEGER NOT NULL,
    FOREIGN KEY (registration_id) REFERENCES agent_registrations(id) ON DELETE CASCADE
);

-- Outbox for durable RA → TL event delivery.
-- Events are written here in the same SQLite transaction as the
-- domain-state change that produced them. A background worker polls
-- this table and pushes to the Transparency Log. On success the row
-- is marked sent; on failure the row's attempts counter is bumped and
-- a delay is applied before the next retry.
CREATE TABLE IF NOT EXISTS outbox_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type        TEXT    NOT NULL,
    agent_id          TEXT    NOT NULL,
    payload_json      TEXT    NOT NULL CHECK (json_valid(payload_json)),
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT,
    next_attempt_at_ms INTEGER NOT NULL,
    sent_at_ms        INTEGER,
    created_at_ms     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_next
    ON outbox_events(sent_at_ms, next_attempt_at_ms);
