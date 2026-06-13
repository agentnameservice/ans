-- 007_certificate_identifiers.sql
-- Persist the issued certificate's serial number and the issuing
-- provider's opaque handle on issued_certificates.
--
-- Both come back from the issuer port at signing time and were
-- previously discarded. They are required for CA-side revocation:
-- the in-process self-signed CA, AWS Private CA, and Vault revoke by
-- serial; GCP Private CA Service revokes by certificate resource
-- name, which only exists if captured at issuance. NULL on rows
-- written before this migration — readers fall back to parsing the
-- certificate PEM for the serial, and legacy rows never have a
-- provider handle (they were all self-CA issued).

ALTER TABLE issued_certificates
    ADD COLUMN serial_number TEXT;

ALTER TABLE issued_certificates
    ADD COLUMN certificate_ref TEXT;
