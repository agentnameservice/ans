-- 006_certificate_orders.sql
-- Persist the certificate order — provider order ref, order state,
-- and the full challenge set — on both agent registrations and
-- server-cert renewals.
--
-- Challenges now originate from the certificate issuer port
-- (`ServerCertificateIssuer.CreateOrder`) instead of being invented
-- by the service layer, so the row must carry whatever the provider
-- minted: token, key authorization, and any provider-computed DNS
-- record value (an ACME provider's DNS-01 TXT value is a digest of
-- the key authorization, not the raw token). A JSON column holds the
-- challenge array verbatim; order ref and state get their own
-- columns so the state machine is queryable.
--
-- The pre-existing token columns (`acme_dns01_token` on agents,
-- `dns01_token` / `http01_token` on renewals) are frozen as legacy:
-- readers synthesize a self-issued challenge set from them when the
-- JSON column is NULL; writers no longer touch them. The
-- `acme_challenge_expires_at_ms` column is NOT legacy — its semantic
-- (challenge-window expiry) is unchanged, so it carries the order's
-- expiry for both old and new rows.

ALTER TABLE agent_registrations
    ADD COLUMN cert_order_ref TEXT;

ALTER TABLE agent_registrations
    ADD COLUMN cert_order_state TEXT;

ALTER TABLE agent_registrations
    ADD COLUMN cert_order_challenges TEXT CHECK (cert_order_challenges IS NULL OR json_valid(cert_order_challenges));

ALTER TABLE server_cert_renewals
    ADD COLUMN order_ref TEXT;

ALTER TABLE server_cert_renewals
    ADD COLUMN challenges TEXT CHECK (challenges IS NULL OR json_valid(challenges));
