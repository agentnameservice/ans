-- 007_agent_dns_record_style.sql
-- Persist the operator's chosen DNS-record-style on the registration
-- row so the verify-acme/verify-dns flow and the badge response carry
-- the same shape the operator chose at registration time.
--
-- One of (CONSTANT_CASE matching the V2 register schema enum):
--   "CONSOLIDATED" — Consolidated Approach SVCB rows + shared records
--                    (default; recommended; aligned with §4.4.2).
--   "LEGACY"       — original `_ans` TXT shape + shared records.
--                    Backwards-compatible with operators registered
--                    before the Consolidated Approach landed.
--   "BOTH"         — union; the §4.4.2 transition shape for operators
--                    running both record families during migration.
--
-- Nullable to allow rows that pre-date this migration to load. The
-- backfill below sets every such row to LEGACY because every agent
-- registered before this PR shipped received the original `_ans` TXT
-- shape — defaulting them to CONSOLIDATED would silently demand SVCB
-- records they were never told to publish. CHECK matches the
-- precedent set by migrations 002 (csr_type) and 003 (schema_version)
-- so corrupt rows fail at the storage boundary instead of silently
-- coercing to default in the domain layer.

ALTER TABLE agent_registrations
    ADD COLUMN dns_record_style TEXT
    CHECK (dns_record_style IS NULL
           OR dns_record_style IN ('CONSOLIDATED', 'LEGACY', 'BOTH'));

-- Backfill: every row registered before this migration shipped was
-- emitting the legacy `_ans` TXT shape (the only shape pre-PR-13).
-- Stamp them as LEGACY so post-deploy verify-dns calls demand the
-- record family the operator actually published. New rows get the
-- value written explicitly by applyDNSRecordStyle in the service.
UPDATE agent_registrations
    SET dns_record_style = 'LEGACY'
    WHERE dns_record_style IS NULL;
