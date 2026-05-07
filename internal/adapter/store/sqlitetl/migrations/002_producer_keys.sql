-- Stage 4: runtime-mutable producer-key trust store.
--
-- Before this migration the TL trusted producer keys loaded from
-- YAML at startup (see internal/tl/producerkey/memory.go). That works
-- for a quickstart but can't handle rotation without a restart. This
-- table lets the TL load keys from disk on boot and add/revoke them
-- through the admin API at runtime.
--
-- Reference shape: the reference TL's `producer_keys` table in
-- its managed MySQL backend. Deviations from the reference are
-- intentional and minimal:
--
--   - No stored procedures (SQLite doesn't support them); rotation
--     logic lives in Go.
--   - `key_id_opaque` / `ra_id_opaque` (C2SP privacy-preserving
--     identifiers) are recorded but the TL does not enforce use of
--     them — the plaintext raId/keyId stays authoritative for
--     lookup. Enforcement can land later if the project decides to
--     follow the reference's privacy model.
--   - `metadata` is a TEXT column carrying raw JSON (CHECK
--     `json_valid`) rather than a typed relation. The reference's
--     Metadata struct is three optional fields; this keeps schema
--     evolution cheap.
--
-- Column semantics:
--   key_id         — producer-chosen identifier (carried in JWS `kid`).
--                    Unique across the whole log: two RAs can't pick
--                    the same keyId. Matches the reference.
--   ra_id          — Registration Authority identifier. Multiple
--                    active keys per raId are allowed to support
--                    overlap during rotation.
--   fingerprint    — `SHA256:<hex>` of the SPKI DER. Informational
--                    (shown in admin lists + logs); not the lookup
--                    key.
--   status         — `active` | `revoked`. `expired` is derived from
--                    expires_at vs now() at query time, not stored.
--   valid_from_ms,
--   expires_at_ms  — inclusive start / exclusive end of the key's
--                    validity window, in unix milliseconds.
--   revoked_at_ms  — nullable; set when status flips to `revoked`.
--   revokes_key_id — nullable; set on a rotation that supersedes a
--                    prior key. Informational in this schema — the
--                    old key's status/expires_at_ms are updated in
--                    the same transaction.
--
-- Indexes:
--   - Primary key is key_id (unique globally).
--   - Secondary index on (ra_id, status, valid_from_ms) supports the
--     hot path: "give me the active keys for this raId right now".

CREATE TABLE IF NOT EXISTS tl_producer_keys (
    key_id          TEXT PRIMARY KEY,
    ra_id           TEXT NOT NULL,
    algorithm       TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    valid_from_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    revoked_at_ms   INTEGER,
    revokes_key_id  TEXT,
    metadata        TEXT CHECK (metadata IS NULL OR json_valid(metadata)),
    key_id_opaque   TEXT,
    ra_id_opaque    TEXT,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tl_producer_keys_raid_active
    ON tl_producer_keys(ra_id, status, valid_from_ms DESC);

CREATE INDEX IF NOT EXISTS idx_tl_producer_keys_fingerprint
    ON tl_producer_keys(fingerprint);
