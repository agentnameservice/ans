-- 006_agent_capabilities_hash.sql
-- Persist the SHA-256(JCS(agentCardContent)) hash on the
-- agent_registrations row so the activation flow can seal it into
-- attestations.metadataHashes.capabilitiesHash without re-hashing
-- (or re-storing) the full agentCardContent body.
--
-- ANS_SPEC.md §A.1 prescribes the "hash and forget" semantic: the RA
-- accepts the operator's ANS Trust Card body on the V2 registration
-- request, hashes it, and persists only the digest. The body itself
-- is the operator's to host (or not). The AIM later verifies the
-- live hosted Trust Card content against this digest.
--
-- The column is nullable for backwards compatibility with agents
-- registered before this migration, and for the spec-conformant
-- "agent registered without agentCardContent" path. When NULL, the
-- AGENT_REGISTERED event omits the metadataHashes.capabilitiesHash
-- key (the existing omitempty path on the struct).

ALTER TABLE agent_registrations
    ADD COLUMN capabilities_hash TEXT;
