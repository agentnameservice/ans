-- 006_agent_discovery_profiles.sql
-- Persist the operator's chosen set of DNS record families on the
-- registration row so verify-acme / verify-dns / badge responses
-- carry the same shape the operator chose at registration time.
--
-- Stored as a JSON array of CONSTANT_CASE strings matching the V2
-- register schema's DiscoveryProfile enum:
--   "ANS_SVCB" — Consolidated Approach SVCB rows + shared records
--                (RFC 9460; recommended default).
--   "ANS_TXT"  — original `_ans` TXT shape + HTTPS RR + shared
--                records. Supported indefinitely for operators with
--                existing zone-edit tooling targeting `_ans.{fqdn}`.
--
-- Examples:
--   '["ANS_SVCB"]'              — default for new V2 registrations
--   '["ANS_TXT"]'                — V1 lane + pre-PR rows
--   '["ANS_SVCB","ANS_TXT"]'     — §4.4.2 transition union
--
-- Nullable to allow rows that pre-date this migration to load. The
-- backfill below sets every such row to ["ANS_TXT"] because every
-- agent registered before this PR shipped received the original
-- `_ans` TXT shape — defaulting them to ["ANS_SVCB"] would silently
-- demand SVCB records they were never told to publish. CHECK uses
-- json_valid() (SQLite JSON1) so a malformed array fails at the
-- storage boundary instead of silently coercing in the domain.
-- Element-level validation lives in the service layer, where the
-- INVALID_DISCOVERY_PROFILE error is raised before the row is written.

ALTER TABLE agent_registrations
    ADD COLUMN discovery_profiles TEXT
    CHECK (discovery_profiles IS NULL OR json_valid(discovery_profiles));

-- Backfill: every row registered before this migration shipped was
-- emitting the legacy `_ans` TXT shape (the only shape pre-PR-13).
-- Stamp them as ["ANS_TXT"] so post-deploy verify-dns calls demand
-- the record family the operator actually published. New rows get
-- the value written explicitly by applyDiscoveryProfiles in the service.
UPDATE agent_registrations
    SET discovery_profiles = '["ANS_TXT"]'
    WHERE discovery_profiles IS NULL;
