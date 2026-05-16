-- 009_agent_anchor_claim.sql
--
-- Plan G Slice 5b: persist the AnchorClaim that produced a
-- registration. ANS-0 admits three anchor types (fqdn, did, lei);
-- the storage shape captures the type plus the canonical resolved
-- ID. The verification key (PublicKeyJWK) is intentionally NOT
-- stored on this row — verifiers re-resolve through the
-- AnchorResolver to honor the per-profile freshness budget, and
-- a stale stored JWK would defeat that.
--
-- Both columns are nullable. Pre-Plan-G registrations have no
-- AnchorClaim recorded; their anchor_type stays NULL and the
-- aggregate exposes a nil AnchorClaim downstream. The application
-- layer infers an FQDN claim from agent_host for those legacy rows
-- when needed without writing into this column on read.
--
-- Adding columns to an existing SQLite table is a simple ALTER;
-- no rebuild ceremony required.

ALTER TABLE agent_registrations
    ADD COLUMN anchor_type TEXT;

ALTER TABLE agent_registrations
    ADD COLUMN anchor_resolved_id TEXT;
