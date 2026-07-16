-- 012_cert_order_verified_challenge.sql
-- Persist which challenge type satisfied the domain-control gate.
--
-- The gate (verify-acme) is any-of — DNS-01 TXT record or HTTP-01
-- resource — but the terminal AGENT_REGISTERED attestation that
-- reports the validation method (`attestations.domainValidation`) is
-- built in a later call (verify-dns), where the gate result is no
-- longer in scope. Before this column the event builders hardcoded
-- "ACME-DNS-01", sealing a wrong method token into the append-only
-- log for HTTP-01-validated agents (issue #61).
--
-- NULL means "not recorded": either the gate has not passed yet, or
-- the row predates this migration. Event builders omit the field for
-- such rows rather than fabricate a method.

ALTER TABLE agent_registrations
    ADD COLUMN cert_order_verified_challenge TEXT;
