-- Verified Identities — the "who" behind an agent (the "what").
--
-- An identity is a first-class object owned by the providerId, proven
-- through a per-kind control proof, sealed onto its own Transparency
-- Log stream, and linked to any number of that owner's agents. The
-- agent_registrations table is UNCHANGED — agents carry no identity
-- fields; the association lives in the identity_links junction below.
--
-- No public-key column anywhere (ANS-0 §6.2 key transience): proven
-- keys are sealed in the identity's TL events, never persisted as
-- live state.
CREATE TABLE IF NOT EXISTS identities (
    identity_id              TEXT    PRIMARY KEY,   -- UUIDv7, RA-assigned
    provider_id              TEXT    NOT NULL,      -- owner (authentication principal)
    -- kind carries the identifier kind ('did:web', 'did:key', 'lei',
    -- and future kinds: 'did:plc', 'did:ion', …). Deliberately NO
    -- CHECK constraint: kind validity is enforced by the domain's
    -- closed dispatcher (domain.InferIdentifierKind) + the service's
    -- control-verifier registry — one source of truth. A CHECK here
    -- would force a table rebuild for every kind added.
    kind                     TEXT    NOT NULL,
    value                    TEXT    NOT NULL,      -- canonical identifier
    -- status IS checked: the lifecycle machine is genuinely frozen.
    status                   TEXT    NOT NULL CHECK (status IN ('PENDING_CONTROL', 'VERIFIED', 'REVOKED')),
    proof_method             TEXT    NOT NULL DEFAULT '',
    pending_value            TEXT    NOT NULL DEFAULT '',  -- staged PUT replacement; '' unless rotating
    challenge_nonce          TEXT,                  -- transient anti-replay nonce
    challenge_expires_at_ms  INTEGER,
    challenge_consumed_at_ms INTEGER,               -- one-time-use guard, set in the verify tx
    verified_at_ms           INTEGER,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL
);

-- One LIVE row per (owner, identifier): re-add idempotency. REVOKED
-- rows fall out, so history never blocks an owner re-proving an
-- identity.
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_live
    ON identities(provider_id, kind, value) WHERE status != 'REVOKED';

-- Global uniqueness of PROVEN identities: one (kind, value) is
-- VERIFIED by at most one owner across the RA; an unproven
-- PENDING_CONTROL row cannot squat. Competing claims race to
-- verify-control; first to PROVE wins (the loser's verify-time flip
-- violates this index → IDENTIFIER_DUPLICATE).
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_proven
    ON identities(kind, value) WHERE status = 'VERIFIED';

CREATE INDEX IF NOT EXISTS idx_identities_owner
    ON identities(provider_id, created_at_ms DESC);

-- identity_links is the one-to-many (formally many-to-many: an agent
-- legitimately carries several identities — a did:web AND an lei)
-- junction between an owner's identities and that same owner's
-- agents. Rows are read-side caches of the sealed IDENTITY_LINKED /
-- IDENTITY_UNLINKED events. No challenge columns: links carry no
-- proof — a link is a single owner-gated call (§4.3).
CREATE TABLE IF NOT EXISTS identity_links (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id              TEXT    NOT NULL REFERENCES identities(identity_id),
    agent_id                 TEXT    NOT NULL REFERENCES agent_registrations(agent_id),
    status                   TEXT    NOT NULL CHECK (status IN ('LINKED', 'UNLINKED')),
    linked_at_ms             INTEGER,
    created_at_ms            INTEGER NOT NULL,
    updated_at_ms            INTEGER NOT NULL
);

-- One live link per (identity, agent) pair; UNLINKED rows are history
-- and never block re-linking.
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_links_live
    ON identity_links(identity_id, agent_id) WHERE status = 'LINKED';

CREATE INDEX IF NOT EXISTS idx_identity_links_agent
    ON identity_links(agent_id, status);
