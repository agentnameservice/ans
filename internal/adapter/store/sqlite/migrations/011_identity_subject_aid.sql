-- lei (vLEI) subject AID pinning.
--
-- The lei kind carries its credential presentation at REGISTER time;
-- the verifier extracts the holder AID from that presentation and the
-- RA pins it on the aggregate (the §3.6 pinning rule — the caller
-- never re-supplies the signer at verify-control). The AID must
-- therefore persist between register and verify-control.
--
-- Nullable: every other kind (did:web, did:key, and future DID
-- methods) carries no register-time presentation and leaves this NULL.
-- No CHECK and no index — the column is read only on the verify-control
-- path for the row already loaded by identity_id.
ALTER TABLE identities ADD COLUMN subject_aid TEXT;

-- pending_subject_aid stages the AID a rotation presents; it is
-- promoted to subject_aid only on a successful verify-control, so an
-- abandoned rotation never overwrites the proven signer. Mirrors
-- pending_value. Nullable; NULL for every other kind.
ALTER TABLE identities ADD COLUMN pending_subject_aid TEXT;
