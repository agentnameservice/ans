-- 007_agent_dns_record_style.sql
-- Persist the operator's chosen DNS-record-style on the registration
-- row so the verify-acme/verify-dns flow and the badge response carry
-- the same shape the operator chose at registration time.
--
-- One of:
--   "consolidated" — Consolidated Approach SVCB rows + shared records
--                    (default; recommended; aligned with §4.4.2).
--   "legacy"       — original `_ans` TXT shape + shared records.
--                    Backwards-compatible with operators registered
--                    before the Consolidated Approach landed.
--   "both"         — union; the §4.4.2 transition shape for operators
--                    running both record families during migration.
--
-- Nullable for backwards compatibility with agents registered before
-- this migration. The domain helper ComputeRequiredDNSRecords treats
-- empty value as the default ("consolidated") via DefaultDNSRecordStyle,
-- so old agents do not lose attestation behavior.

ALTER TABLE agent_registrations
    ADD COLUMN dns_record_style TEXT;
