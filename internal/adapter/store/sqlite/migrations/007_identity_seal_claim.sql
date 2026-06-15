-- Seal-before-success (design §5.6.1 item 6): identity operations
-- return success only after the TL acknowledges the seal, so the
-- verify path now spans a network call. challenge_claimed_at_ms is a
-- short-TTL provisional claim taken BEFORE the seal — it serializes
-- concurrent verify-control attempts on one nonce so at most one
-- in-flight attempt can seal (the conditional consume remains the
-- authoritative guard at commit). A claim is NOT consumption: failed
-- attempts release it, and a stale claim (crashed claimer) is
-- reclaimable after the claim TTL.
ALTER TABLE identities ADD COLUMN challenge_claimed_at_ms INTEGER;
