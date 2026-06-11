#!/usr/bin/env bash
#
# vLEI demo: drive the ans-ra RA-mediated register-with-presentation +
# verify-control flow end-to-end against a REAL vlei-verifier, on the
# identity-scoped /v2/ans/identities routes.
#
#   register+present → POST /v2/ans/identities
#                      { value: $LEI, vleiPresentation:{ cesr: $CESR } }
#                      the RA reads the leaf credential SAID out of the CESR,
#                      presents the full chain to the verifier itself, pins the
#                      verifier-reported subject AID on the identity, and
#                      returns the challenge round (nonce + signingInput) plus
#                      the advisory presentationStatus.
#   sign             → the HOLDER signs the served `signingInput` (NOT the bare
#                      nonce) with the role AID via signify (sign-proof.ts in
#                      the signify container) — see below.
#   re-present       → re-POST /v2/ans/identities (same body) while the row is
#                      PENDING_CONTROL to refresh the verifier's authorization
#                      window (it ages off after 10 minutes). Returns the SAME
#                      identityId with a fresh nonce; if the signingInput
#                      rotated, re-sign it.
#   verify-control   → POST /v2/ans/identities/{identityId}/verify-control
#                      { cesrSignature: $SIG } → status: VERIFIED (the RA pins
#                      the signer AID to the identity; it is never a body value)
#   link             → POST /v2/ans/identities/{identityId}/links
#                      { agentIds: [ $AGENT_ID ] } → { linked: 1 }
#   show             → GET /v2/ans/agents/{agentId} → the computed identities[]
#                      badge carries the lei identity; poll the TL identity
#                      audit for the sealed IDENTITY_VERIFIED.
#
#
# WHY sign the signingInput, not the nonce: the lei control proof is uniform
# with the JWS kinds — every kind signs the served `signingInput` (the
# base64url of the JCS-canonical IdentityProofInput), which binds the nonce,
# the identity id, the identifier, and the proof purpose. The RA forwards the
# signature to the verifier as `non_prefixed_digest = signingInput`.
#
# WHY re-present right before verify: the vlei-verifier ages credential
# authorizations off after TimeoutAuth = 600s (10 minutes). verify-control
# re-checks authorization LIVE on every call (it does NOT trust the AUTHORIZED
# status recorded at present time), so a slow manual signing step can let the
# window lapse — surfacing as LEI_NOT_AUTHORIZED even though the signature is
# valid. Re-presenting immediately before the verify keeps the window fresh.
#
# The RA is the SINGLE touchpoint for the verifier: this script never calls the
# verifier directly. build-chain.ts and sign-proof.ts only register the
# synthetic GLEIF root of trust, export the holder's full-chain CESR + LEI, and
# sign the signingInput with the holder key; everything else flows through the RA.
#
# PRECONDITIONS (manual — see README.md):
#   1. vLEI stack is up:            scripts/demo/vlei/up.sh
#   2. ans-ra is running with vlei.type: verifier and vlei.base-url pointing at
#      the verifier (the `vlei:` block in config/ra-local.yaml).
#   3. An agent owned by the same caller is registered and its id is in
#      $AGENT_ID (e.g. from scripts/demo/run-lifecycle.sh).
#   4. build-chain.sh has run (scripts/demo/vlei/build-chain.sh) — it registered
#      the root of trust and exported $PRESENTATION_FILE (the holder's
#      full-chain CESR + claimed LEI + holder AID) and, for AUTO_SIGN,
#      $OUTPUTS_FILE (which carries the holder's roleBran). The signify
#      container stays up so the signingInput can be signed with the holder AID.
#
# Required env:
#   AGENT_ID   the registered agent to link the verified lei identity to
#
# Env overrides:
#   PRESENTATION_FILE  exported {cesr,lei,aid} JSON
#                      (default: $DATA/ecr-presentation.json)
#   OUTPUTS_FILE       exported {roleBran,...} JSON, used by AUTO_SIGN
#                      (default: alongside PRESENTATION_FILE / tier1-outputs.json)
#   LEI                claimed LEI (default: read from PRESENTATION_FILE)
#   SIGNED_PROOF       the signature over the signingInput (indexed Siger qb64).
#                      When set, the script uses it directly — highest
#                      precedence. NOTE: a re-present that rotates the nonce
#                      invalidates a pre-computed SIGNED_PROOF; prefer AUTO_SIGN
#                      for the live flow.
#   AUTO_SIGN          when 1 (and SIGNED_PROOF unset), sign the signingInput
#                      non-interactively by running sign-proof.ts in the signify
#                      container with the roleBran from $OUTPUTS_FILE. Falls back
#                      to the interactive /dev/tty paste when unset.
#   COMPOSE            docker compose command (default: "docker compose")
#   RA_URL             ans-ra base URL (default: http://localhost:18080)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DATA="${DATA:-$(cd "$SCRIPT_DIR/../../.." && pwd)/data/demo/vlei}"
# shellcheck source=../common.sh
. "$SCRIPT_DIR/../common.sh"

PRESENTATION_FILE="${PRESENTATION_FILE:-$DATA/ecr-presentation.json}"
OUTPUTS_FILE="${OUTPUTS_FILE:-$(dirname "$PRESENTATION_FILE")/tier1-outputs.json}"
COMPOSE="${COMPOSE:-docker compose}"

require_cmd curl
require_cmd jq

: "${AGENT_ID:?set AGENT_ID to the registered agent id}"
[ -f "$PRESENTATION_FILE" ] || fail "presentation file not found: $PRESENTATION_FILE — run build-chain.sh (README step 2) so it exports the artifacts"

CESR="$(jq -r '.cesr' "$PRESENTATION_FILE")"
[ -n "$CESR" ] && [ "$CESR" != "null" ] || fail "no .cesr in $PRESENTATION_FILE"
LEI="${LEI:-$(jq -r '.lei' "$PRESENTATION_FILE")}"
[ -n "$LEI" ] && [ "$LEI" != "null" ] || fail "no LEI — set \$LEI or add .lei to $PRESENTATION_FILE"
# The holder AID is the credential's subject — exported by build-chain.ts and
# the value the RA pins at register time (read from the verifier, not the body).
# We use it only to sanity-check the challenge's kid; the RA derives it itself.
HOLDER_AID="$(jq -r '.aid // empty' "$PRESENTATION_FILE")"

header "RA-mediated register + verify-control demo (identity routes)"
note "RA: $RA_URL   verifier-backed   agent: $AGENT_ID   LEI: $LEI"
[ -n "$HOLDER_AID" ] && note "holder AID (credential subject): $HOLDER_AID"

# register_identity — POST /v2/ans/identities { value, vleiPresentation }.
# Echoes the raw response body on stdout so the caller can extract fields and
# fail with the body on a non-2xx. The validate MUST live in the caller, not
# here: this runs inside a $(...) subshell, where `fail` (exit 1) only ends the
# subshell — under `set -e` that does NOT abort the parent.
register_identity() {
  local body
  body="$(jq -n --arg v "$LEI" --arg cesr "$CESR" \
    '{value:$v, vleiPresentation:{cesr:$cesr}}')"
  curl_json POST "/v2/ans/identities" "$body"
}

# sign_signing_input SIGNING_INPUT — apply the SIGNED_PROOF > AUTO_SIGN >
# interactive-paste precedence and echo ONLY the signature on stdout. The role
# AID's keys live in the KERIA cloud agent, so every path signs with signify.
sign_signing_input() {
  local signing_input="$1" sig role_bran
  if [ -n "${SIGNED_PROOF:-}" ]; then
    printf '%s' "$SIGNED_PROOF"
    return 0
  fi
  if [ "${AUTO_SIGN:-0}" = "1" ]; then
    [ -f "$OUTPUTS_FILE" ] || { echo "AUTO_SIGN=1 but $OUTPUTS_FILE not found — run build-chain.sh first" >&2; return 1; }
    role_bran="$(jq -r '.roleBran // empty' "$OUTPUTS_FILE")"
    [ -n "$role_bran" ] || { echo "no .roleBran in $OUTPUTS_FILE — re-run build-chain.sh" >&2; return 1; }
    # sign-proof.ts prints ONLY the indexed Siger qb64 on stdout; diagnostics
    # go to stderr, so command substitution captures just the signature.
    # shellcheck disable=SC2086  # COMPOSE may be a multi-word command
    sig="$($COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" exec -T signify \
      deno run -A scripts_ts/sign-proof.ts "$role_bran" "$signing_input")" || return 1
    printf '%s' "$sig"
    return 0
  fi
  if [ -r /dev/tty ]; then
    role_bran="$(jq -r '.roleBran // empty' "$OUTPUTS_FILE" 2>/dev/null)"
    note "Sign this signingInput with the holder (role) AID, then paste the result:" >&2
    note "  ROLE_BRAN=\$(jq -r .roleBran '$OUTPUTS_FILE')" >&2
    note "  $COMPOSE -f $SCRIPT_DIR/docker-compose.yml exec -T signify \\" >&2
    note "    deno run -A scripts_ts/sign-proof.ts \"\$ROLE_BRAN\" \"$signing_input\"" >&2
    note "(or just re-run this script with AUTO_SIGN=1 to do it automatically)" >&2
    printf "${C_BOLD}paste cesrSignature here:${C_RESET} " >&2
    IFS= read -r sig </dev/tty
    printf '%s' "$sig"
    return 0
  fi
  echo "no tty to read the signature — set AUTO_SIGN=1 (with build-chain.sh having run) or SIGNED_PROOF=<qb64 indexed Siger>" >&2
  return 1
}

# ----- 1. register+present: RA presents to the verifier, pins the AID -----
header "1. register+present — POST /v2/ans/identities { value, vleiPresentation }"
note "the RA reads the leaf SAID from the CESR and presents the chain itself"
REG_RESP="$(register_identity)"
IDENTITY_ID="$(printf '%s' "$REG_RESP" | jq -r '.identityId // empty')"
[ -n "$IDENTITY_ID" ] || fail "register did not return an identityId — response: $REG_RESP"
PRESENTATION_STATUS="$(printf '%s' "$REG_RESP" | jq -r '.presentationStatus // empty')"
NONCE="$(printf '%s' "$REG_RESP" | jq -r '.nonce // empty')"
SUBJECT_AID="$(printf '%s' "$REG_RESP" | jq -r '.challenges[0].kid // empty')"
SIGNING_INPUT="$(printf '%s' "$REG_RESP" | jq -r '.challenges[0].signingInput // empty')"
[ -n "$SIGNING_INPUT" ] || fail "register did not return a challenge signingInput — response: $REG_RESP"
ok "identity recorded: $IDENTITY_ID   presentationStatus: ${PRESENTATION_STATUS:-<none>}"
note "subject AID (challenge kid): $SUBJECT_AID"
note "nonce: $NONCE"
if [ -n "$HOLDER_AID" ] && [ -n "$SUBJECT_AID" ] && [ "$SUBJECT_AID" != "$HOLDER_AID" ]; then
  fail "challenge kid ($SUBJECT_AID) != exported holder AID ($HOLDER_AID) — the signingInput must be signed by the credential subject, so these must match"
fi

# ----- 2. holder signs the signingInput with the role AID (signify) -----
header "2. Holder signs the signingInput with the role AID (signify)"
SIG="$(sign_signing_input "$SIGNING_INPUT")" || fail "sign failed — is the signify container up? ($COMPOSE -f $SCRIPT_DIR/docker-compose.yml logs signify)"
SIG="$(printf '%s' "$SIG" | tr -d '[:space:]')"
[ -n "$SIG" ] || fail "no cesrSignature provided"
ok "signature over signingInput: $SIG"

# ----- 3. re-present: refresh the verifier's 10-min authorization window -----
# verify-control checks authorization LIVE; the manual signing step above is
# human-paced and may exceed TimeoutAuth (600s). Re-POSTing the same value
# while PENDING_CONTROL is the idempotent re-add: it refreshes the window and
# returns the SAME identityId with a fresh nonce. If the nonce rotated, the
# signingInput changed too, so we re-sign it.
header "3. re-present — refresh the verifier's authorization window"
note "the verifier ages authorizations off after 10 minutes; re-present keeps it fresh"
REPRESENT_RESP="$(register_identity)"
REPRESENTED_ID="$(printf '%s' "$REPRESENT_RESP" | jq -r '.identityId // empty')"
[ -n "$REPRESENTED_ID" ] || fail "re-present did not return an identityId — response: $REPRESENT_RESP"
[ "$REPRESENTED_ID" = "$IDENTITY_ID" ] || fail "re-present returned a different identityId ($REPRESENTED_ID != $IDENTITY_ID) — the idempotent re-add must reuse the row"
SIGNING_INPUT2="$(printf '%s' "$REPRESENT_RESP" | jq -r '.challenges[0].signingInput // empty')"
[ -n "$SIGNING_INPUT2" ] || fail "re-present did not return a challenge signingInput — response: $REPRESENT_RESP"
ok "re-presented (same identity): $REPRESENTED_ID"
if [ "$SIGNING_INPUT2" != "$SIGNING_INPUT" ]; then
  note "nonce rotated on re-present — re-signing the new signingInput"
  SIGNING_INPUT="$SIGNING_INPUT2"
  SIG="$(sign_signing_input "$SIGNING_INPUT")" || fail "re-sign failed"
  SIG="$(printf '%s' "$SIG" | tr -d '[:space:]')"
  [ -n "$SIG" ] || fail "no cesrSignature provided on re-sign"
  ok "re-signed over the fresh signingInput: $SIG"
fi

# ----- 4. verify-control: RA verifies signature + authorized LEI, pins the AID -----
header "4. verify-control — POST .../verify-control { cesrSignature }"
note "no aid in the body — the RA pins the signer AID to the recorded identity"
VERIFY_BODY="$(jq -n --arg sig "$SIG" '{cesrSignature:$sig}')"
VERIFY_RESP="$(curl_json POST "/v2/ans/identities/$IDENTITY_ID/verify-control" "$VERIFY_BODY")"
STATUS="$(printf '%s' "$VERIFY_RESP" | jq -r '.status // empty')"
if [ "$STATUS" = "VERIFIED" ]; then
  ok "status:VERIFIED — the AID controls a vLEI authorizing $LEI, and signed our challenge"
else
  CODE="$(printf '%s' "$VERIFY_RESP" | jq -r '.code // "unknown"')"
  DETAIL="$(printf '%s' "$VERIFY_RESP" | jq -r '.detail // empty')"
  case "$CODE" in
    PRICC_SIGNATURE_INVALID)
      fail "verify-control failed (code=$CODE) — the cesrSignature was not signed by the role AID over THIS signingInput. Make sure sign-proof.ts signed the served signingInput with the 'role' alias, not a kli/other key." ;;
    LEI_NOT_AUTHORIZED)
      fail "verify-control failed (code=$CODE) — the verifier reports no authorized LEI for the AID right now. Confirm the root of trust is registered (build-chain.sh) and the chain authorizes this LEI; if signing took >10 min, just re-run the demo." ;;
    LEI_MISMATCH)
      fail "verify-control failed (code=$CODE) — the verifier authorized a different LEI than $LEI. Check the credential's LEI matches the claim." ;;
    *)
      fail "verify-control failed (code=$CODE): ${DETAIL:-no detail} — response: $VERIFY_RESP" ;;
  esac
fi

# The sealed IDENTITY_VERIFIED reaches the TL through the outbox worker.
header "verify the seal landed on the TL identity stream"
poll_tl_identity_audit "$IDENTITY_ID" 1
ok "IDENTITY_VERIFIED sealed with a Merkle proof on the TL"

# ----- 5. link: bind the verified identity to the agent (one event) -----
header "5. link — POST .../links { agentIds: [ $AGENT_ID ] }"
LINK_BODY="$(jq -n --arg a "$AGENT_ID" '{agentIds:[$a]}')"
LINK_RESP="$(curl_json POST "/v2/ans/identities/$IDENTITY_ID/links" "$LINK_BODY")"
LINKED="$(printf '%s' "$LINK_RESP" | jq -r '.linked // empty')"
[ "$LINKED" = "1" ] || fail "link did not report linked:1 — response: $LINK_RESP"
ok "linked: 1"

# ----- 6. show: the computed identities[] badge on the agent -----
header "6. show — GET /v2/ans/agents/$AGENT_ID (computed identities[] badge)"
AGENT_RESP="$(curl_json GET "/v2/ans/agents/$AGENT_ID")"
BADGE_KIND="$(printf '%s' "$AGENT_RESP" | jq -r --arg id "$IDENTITY_ID" \
  '.identities[]? | select(.identityId==$id) | .kind // empty')"
BADGE_STATUS="$(printf '%s' "$AGENT_RESP" | jq -r --arg id "$IDENTITY_ID" \
  '.identities[]? | select(.identityId==$id) | .identityStatus // empty')"
[ "$BADGE_KIND" = "lei" ] || fail "agent identities[] does not carry the lei badge for $IDENTITY_ID — response: $AGENT_RESP"
[ "$BADGE_STATUS" = "VERIFIED" ] || fail "lei badge status is '$BADGE_STATUS', expected VERIFIED — response: $AGENT_RESP"
ok "agent carries the lei identity badge: $IDENTITY_ID (VERIFIED)"

header "Done"
note "register-with-presentation pins the verifier-reported subject AID; verify-control"
note "is a single CESR-signature proof over the served signingInput (uniform with the"
note "JWS kinds), and the RA pins the signer AID to the identity — never a body value."
