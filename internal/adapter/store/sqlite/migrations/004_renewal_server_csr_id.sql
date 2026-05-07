-- Renewals persist `server_csr_id` so the post-verify-acme issuance
-- path can look up the CSR content to sign. Without this column,
-- CSR renewals lose the CSR reference after the row is reloaded
-- from disk and the sync-issue flow 404s.
--
-- NULL-able because BYOC renewals never set it.

ALTER TABLE server_cert_renewals
    ADD COLUMN server_csr_id TEXT;
