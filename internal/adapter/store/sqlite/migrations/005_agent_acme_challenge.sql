-- 005_agent_acme_challenge.sql
-- Persist the ACME DNS-01 challenge on the agent_registrations row so
-- the RA's RegistrationPending response can surface the `challenges`
-- array on the initial register 202, on the verify-acme response, and
-- on any subsequent GET /agents/{id} while the agent is in
-- PENDING_VALIDATION or PENDING_DNS.
--
-- ans does DNS-01 only (per the documented "no HTTP-01" deviation),
-- so the schema carries a single token + its expiry. When ACME-style
-- key authorization becomes a requirement, add a `key_authorization`
-- column alongside.
--
-- Columns are nullable for backwards compatibility with agents
-- registered before this migration (their rows predate token
-- generation; their challenges array will be empty — harmless because
-- they must already be past PENDING_VALIDATION to exist).

ALTER TABLE agent_registrations
    ADD COLUMN acme_dns01_token       TEXT;

ALTER TABLE agent_registrations
    ADD COLUMN acme_challenge_expires_at_ms INTEGER;
