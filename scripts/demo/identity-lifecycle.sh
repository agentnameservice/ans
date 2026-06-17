#!/usr/bin/env bash
# Exercise EVERY Verified Identity operation end-to-end, printing
# every request + response pair in color. The identity is the "who"
# behind an agent (the "what"): proven once through a control proof,
# sealed onto its own Transparency Log stream, and linked to any
# number of the owner's agents.
#
#   1.  POST   /v2/ans/identities                          register did:web → 202 + challenges
#   2.  POST   /v2/ans/identities                          idempotent re-add (same identityId, fresh nonce)
#   3.  POST   .../verify-control                          MULTI-KEY proof — one ES256 + one EdDSA JWS over the
#                                                          same nonce → VERIFIED, seals IDENTITY_VERIFIED with
#                                                          BOTH verification methods quoted verbatim
#   4.  GET    /v2/ans/identities                          list (mine)
#   5.  GET    /v2/ans/identities/{id}                     detail
#   6.  POST   /v2/ans/identities                          register did:key (zero-I/O kind)
#   7.  POST   .../verify-control                          did:key proof → VERIFIED
#   8.  (register TWO fresh agents to ACTIVE — the fleet)
#   9.  POST   .../links                                   did:web → BOTH agents in one call (ONE IDENTITY_LINKED,
#                                                          ansIds[2]); did:key → agent #1 (its own stream's event)
#                                                          — one agent now carries TWO identities
#   10. GET    /v2/ans/agents/{agentId}                    RA detail now carries computed identities[]
#   11. TL     /v1/identities/{id} + /audit + /agents      both identity badges (did:web AND did:key Multikey
#                                                          seal), chains, reverse joins
#   12. TL     /v1/agents/{agentId}                        agent-1 badge shows identities[2] (did:web + did:key);
#                                                          agent-2 shows the did:web
#   13. TL     /v1/agents/{agentId}/identities{,/history}  agent-side computed views
#   14. PUT    /v2/ans/identities/{id}                     rotate → fresh challenges
#   15. POST   .../verify-control                          new key proof → seals ONE IDENTITY_UPDATED
#                                                          (proven set goes 2 keys → 1 key)
#   16. TL     both linked badges reflect the rotation — ONE event, zero agent-stream writes
#   17. TL     /v1/identities/{id}/receipt                 SCITT COSE receipt for the identity leaf
#   18. DELETE .../links/{agentId}                         unlink the did:web from agent #1 ONLY → agent #1
#                                                          keeps its did:key link; agent #2 keeps the did:web
#   18b. POST  .../links → 422 AGENT_NOT_LINKABLE          liveness gate: a REVOKED agent rejects the whole
#                                                          batch and seals NOTHING
#   19. POST   /v2/ans/identities/{id}/revoke              revoke the did:web → IDENTITY_REVOKED (one event)
#   20. TL     did:web badge REVOKED — agent-2's join shows it at the next read; agent-1's did:key
#              stays VERIFIED with no keys quoted; both agents stay ACTIVE (the whats survive the who)
#
# Every sealing operation above is SEAL-BEFORE-SUCCESS (§5.6.1): the
# RA reports success only after the TL acknowledges the seal, so the
# TL reads in this script run immediately after each call — no
# polling anywhere. Badge views quote the current proven keys[]
# VERBATIM from the latest sealed proof event (+ keysLogId to it).
#
# The demo runs against the noop did:web resolver (the default —
# `identity.resolver.type: noop`): signature verification is real,
# only the "does the live did.json list this key" binding is waived.
# Point `identity.resolver.type: web` at a real deployment and the
# same flow works against a hosted did.json. did:key (step 6-7) uses
# real key decoding either way — zero I/O by construction.
#
# Usage:
#   scripts/demo/identity-lifecycle.sh            # random did:web value
#   scripts/demo/identity-lifecycle.sh acme.test  # did:web:acme.test

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd jq
require_cmd openssl
require_cmd go

DID_HOST="${1:-identity-$(openssl rand -hex 4).example.com}"
DID_WEB="did:web:${DID_HOST}"

header "Demo target"
printf "  identity   %s\n" "$DID_WEB" >&2
printf "  resolver   noop (quickstart) — real JWS verification, waived live-document binding\n" >&2

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

KEY_DIR="$DATA/identity-keys"
rm -rf "$KEY_DIR"
mkdir -p "$KEY_DIR"

# signproof is the registrant-side tool: keys are minted and proofs
# are signed locally; the private key never touches the RA.
signproof() { (cd "$ROOT" && go run ./scripts/demo/signproof "$@"); }

# register_agent HOST — drive a fresh agent to ACTIVE and echo its
# agentId on stdout. The identity demo needs a small fleet to link.
register_agent() {
  local host="$1"
  local ans_name="ans://v1.0.0.${host}"
  local csr_dir="$DATA/identity-agent-csr/$host"
  rm -rf "$csr_dir" && mkdir -p "$csr_dir"
  cat >"$csr_dir/openssl.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $ans_name
[v3_req]
subjectAltName = URI:$ans_name
CNF
  openssl ecparam -name prime256v1 -genkey -noout -out "$csr_dir/key.pem" 2>/dev/null
  openssl req -new -key "$csr_dir/key.pem" -config "$csr_dir/openssl.cnf" -out "$csr_dir/csr.pem" 2>/dev/null
  cat >"$csr_dir/server.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $host
[v3_req]
subjectAltName = DNS:$host
CNF
  openssl ecparam -name prime256v1 -genkey -noout -out "$csr_dir/server.key" 2>/dev/null
  openssl req -new -key "$csr_dir/server.key" -config "$csr_dir/server.cnf" -out "$csr_dir/server.csr" 2>/dev/null

  local resp agent_id
  resp=$(curl_json POST /v2/ans/agents "$(jq -n \
    --arg host "$host" \
    --arg csr "$(cat "$csr_dir/csr.pem")" \
    --arg srv "$(cat "$csr_dir/server.csr")" '
    { agentDisplayName: "identity-demo-agent",
      version: "1.0.0",
      agentHost: $host,
      endpoints: [{agentUrl: ("https://" + $host + "/mcp"), protocol: "MCP", transports: ["SSE"]}],
      identityCsrPEM: $csr,
      serverCsrPEM: $srv }')")
  agent_id=$(printf '%s' "$resp" | jq -r '.agentId // empty')
  [ -n "$agent_id" ] || fail "agent registration failed for $host"
  curl_json POST "/v2/ans/agents/$agent_id/verify-acme" >/dev/null
  assert_2xx "verify-acme ($host)"
  if [ -n "${ANS_DNS_ZONE:-}" ] && [ -x "$BIN/ans-dns" ]; then
    "$BIN/ans-dns" install --zone "$ANS_DNS_ZONE" --api-key "$RA_API_KEY" "$RA_URL" "$agent_id"
  fi
  curl_json POST "/v2/ans/agents/$agent_id/verify-dns" >/dev/null
  assert_2xx "verify-dns ($host)"
  printf '%s' "$agent_id"
}

header "0. Mint the operator's identity keypairs (locally — the RA never sees them)"
signproof keygen -out "$KEY_DIR/who-p256.pem" >/dev/null
signproof keygen -alg ed25519 -out "$KEY_DIR/who-ed25519.pem" >/dev/null
ok "two keys minted: P-256 (ES256 proofs) + Ed25519 (EdDSA proofs)"

# ----- 1. Register the did:web identity -----
header "1. POST /v2/ans/identities  (register $DID_WEB → 202 + challenges)"
REG_RESP=$(curl_json POST /v2/ans/identities "$(jq -n --arg v "$DID_WEB" '{value: $v}')")
IDENTITY_ID=$(printf '%s' "$REG_RESP" | jq -r '.identityId // empty')
SIGNING_INPUT=$(printf '%s' "$REG_RESP" | jq -r '.challenges[0].signingInput')
NONCE_1=$(printf '%s' "$REG_RESP" | jq -r '.nonce')
[ -n "$IDENTITY_ID" ] || fail "no identityId in register response"
echo "$IDENTITY_ID" >"$DATA/last-identity-id"
ok "identityId=$IDENTITY_ID (PENDING_CONTROL)"

# ----- 2. Idempotent re-add -----
header "2. POST /v2/ans/identities  (re-add while PENDING_CONTROL → same identityId, fresh nonce)"
READD_RESP=$(curl_json POST /v2/ans/identities "$(jq -n --arg v "$DID_WEB" '{value: $v}')")
READD_ID=$(printf '%s' "$READD_RESP" | jq -r '.identityId // empty')
NONCE_2=$(printf '%s' "$READD_RESP" | jq -r '.nonce')
[ "$READD_ID" = "$IDENTITY_ID" ] || fail "re-add returned a different identityId"
[ "$NONCE_1" != "$NONCE_2" ] || fail "re-add did not supersede the nonce"
SIGNING_INPUT=$(printf '%s' "$READD_RESP" | jq -r '.challenges[0].signingInput')
ok "same identityId, superseded nonce — the §4.2 idempotent re-add"

# ----- 3. Verify control — MULTI-KEY -----
header "3. POST /v2/ans/identities/$IDENTITY_ID/verify-control  (TWO keys, one nonce → seals both verbatim)"
note "did:web supports multi-key attestation: one JWS per key over the SAME signingInput"
note "  #key-1 → P-256 / ES256;  #key-2 → Ed25519 / EdDSA"
PROOF_1=$(signproof sign -key "$KEY_DIR/who-p256.pem" -kid "${DID_WEB}#key-1" -input "$SIGNING_INPUT")
PROOF_2=$(signproof sign -key "$KEY_DIR/who-ed25519.pem" -kid "${DID_WEB}#key-2" -input "$SIGNING_INPUT")
curl_json POST "/v2/ans/identities/$IDENTITY_ID/verify-control" \
  "$(jq -n --arg p1 "$PROOF_1" --arg p2 "$PROOF_2" '{signedProofs: [$p1, $p2]}')" >/dev/null
assert_2xx "multi-key verify-control"
ok "BOTH keys proven against one nonce — every proof must pass (one bad proof fails the call closed)"

# ----- 4. List -----
header "4. GET /v2/ans/identities  (list mine)"
curl_json GET /v2/ans/identities >/dev/null

# ----- 5. Detail -----
header "5. GET /v2/ans/identities/$IDENTITY_ID  (detail)"
curl_json GET "/v2/ans/identities/$IDENTITY_ID" >/dev/null

# ----- 6-7. did:key — the zero-I/O kind -----
header "6. POST /v2/ans/identities  (register an Ed25519 did:key — the key IS the identifier)"
DID_KEY=$(signproof keygen -alg ed25519 -out "$KEY_DIR/didkey.pem")
note "minted $DID_KEY (z6Mk… = ed25519-pub; proofs use EdDSA)"
DK_RESP=$(curl_json POST /v2/ans/identities "$(jq -n --arg v "$DID_KEY" '{value: $v}')")
DK_ID=$(printf '%s' "$DK_RESP" | jq -r '.identityId // empty')
[ -n "$DK_ID" ] || fail "did:key register failed"
DK_KID=$(printf '%s' "$DK_RESP" | jq -r '.challenges[0].kid')
DK_INPUT=$(printf '%s' "$DK_RESP" | jq -r '.challenges[0].signingInput')

header "7. POST /v2/ans/identities/$DK_ID/verify-control  (did:key proof — real crypto, zero I/O)"
DK_PROOF=$(signproof sign -key "$KEY_DIR/didkey.pem" -kid "$DK_KID" -input "$DK_INPUT")
curl_json POST "/v2/ans/identities/$DK_ID/verify-control" \
  "$(jq -n --arg p "$DK_PROOF" '{signedProofs: [$p]}')" >/dev/null
assert_2xx "did:key verify-control"
ok "did:key identity VERIFIED — the keyless-future test track"

# ----- 8. Register a small fleet (the WHATs) -----
header "8. Register TWO fresh agents to ACTIVE (the fleet to link)"
AGENT_1=$(register_agent "linked-a-$(openssl rand -hex 4).example.com")
AGENT_2=$(register_agent "linked-b-$(openssl rand -hex 4).example.com")
# The AGENT lane still seals via the async outbox (flagged 2026-06-11
# as a bug in the design doc §5.6.1 — agents should also wait for seal
# confirmation; tracked separately). Until that lands, wait for both
# agents' TL streams here: the identity-side reads below join against
# agent TL status, which needs the AGENT_REGISTERED leaves present.
poll_tl_audit "$AGENT_1" 1 30
poll_tl_audit "$AGENT_2" 1 30
ok "fleet ready: $AGENT_1 + $AGENT_2"

# ----- 9. Link the fleet — one owner-gated call per identity -----
header "9a. POST /v2/ans/identities/$IDENTITY_ID/links  (did:web → BOTH agents, one call)"
LINK_RESP=$(curl_json POST "/v2/ans/identities/$IDENTITY_ID/links" \
  "$(jq -n --arg a "$AGENT_1" --arg b "$AGENT_2" '{agentIds: [$a, $b]}')")
LINKED_COUNT=$(printf '%s' "$LINK_RESP" | jq -r '.linked // 0')
[ "$LINKED_COUNT" = "2" ] || fail "expected linked: 2, got $LINKED_COUNT"
ok "linked: 2 — ONE IDENTITY_LINKED carries the whole batch; fleet linking is O(1) sealed events"

header "9b. POST /v2/ans/identities/$DK_ID/links  (did:key → agent #1 — a second WHO on the same agent)"
note "an agent legitimately carries several identities; each link seals on ITS identity's stream"
DK_LINK=$(curl_json POST "/v2/ans/identities/$DK_ID/links" \
  "$(jq -n --arg a "$AGENT_1" '{agentIds: [$a]}')")
[ "$(printf '%s' "$DK_LINK" | jq -r '.linked // 0')" = "1" ] || fail "did:key link failed"
ok "agent-1 now carries TWO identities: the multi-key did:web and the Ed25519 did:key"

# ----- 10. RA-side computed identities[] -----
header "10. GET /v2/ans/agents/$AGENT_1  (RA detail — computed identities[], never stored on the agent)"
curl_json GET "/v2/ans/agents/$AGENT_1" >/dev/null

# ----- 11. TL identity stream -----
header "11. Read the identity stream from the TL — NO polling: identity ops are seal-before-success (§5.6.1)"
assert_tl_identity_audit "$IDENTITY_ID" 2
ok "IDENTITY_VERIFIED + IDENTITY_LINKED were already sealed when the API calls returned"

header "11a. TL: GET /v1/identities/$IDENTITY_ID  (identity badge — latest sealed event + proof + status)"
curl_tl GET "/v1/identities/$IDENTITY_ID" >/dev/null

header "11b. TL: GET /v1/identities/$IDENTITY_ID/audit  (the WHO's full chain — standard audit envelope)"
AUDIT=$(curl_tl GET "/v1/identities/$IDENTITY_ID/audit")
# The multi-key proof sealed BOTH verification methods verbatim, and
# the batch link sealed ONE event naming both agents.
SEALED_KEY_COUNT=$(printf '%s' "$AUDIT" | \
  jq -r '[.records[].payload.producer.event | select(.keys)][0].keys | length')
LINK_ANSIDS=$(printf '%s' "$AUDIT" | \
  jq -r '[.records[].payload.producer.event | select(.eventType == "IDENTITY_LINKED")][0].ansIds | length')
[ "$SEALED_KEY_COUNT" = "2" ] || fail "sealed proof should carry 2 keys, got $SEALED_KEY_COUNT"
[ "$LINK_ANSIDS" = "2" ] || fail "sealed link event should carry 2 ansIds, got $LINK_ANSIDS"
ok "sealed: IDENTITY_VERIFIED.keys[2] (ES256 + EdDSA, verbatim) and IDENTITY_LINKED.ansIds[2] (one event)"

header "11c. TL: GET /v1/identities/$IDENTITY_ID/agents  (reverse join: both linked agents)"
AGENTS_VIEW=$(curl_tl GET "/v1/identities/$IDENTITY_ID/agents")
AGENTS_COUNT=$(printf '%s' "$AGENTS_VIEW" | jq -r '.agents | length')
[ "$AGENTS_COUNT" = "2" ] || fail "reverse join should list 2 agents, got $AGENTS_COUNT"

header "11d. TL: GET /v1/identities/$DK_ID  (did:key badge — the sealed Multikey verification method)"
assert_tl_identity_audit "$DK_ID" 2
DK_BADGE_VM=$(curl_tl GET "/v1/identities/$DK_ID/audit" | \
  jq -r '[.records[].payload.producer.event | select(.keys)][0].keys[0].verificationMethod')
DK_VM_TYPE=$(printf '%s' "$DK_BADGE_VM" | jq -r '.type // empty')
DK_VM_MB=$(printf '%s' "$DK_BADGE_VM" | jq -r '.publicKeyMultibase // empty')
[ "$DK_VM_TYPE" = "Multikey" ] || fail "did:key seal should be a Multikey method, got $DK_VM_TYPE"
[ "did:key:$DK_VM_MB" = "$DID_KEY" ] || fail "did:key seal's publicKeyMultibase must be the identifier's msid verbatim"
ok "did:key sealed verbatim: type=Multikey, publicKeyMultibase = the did:key msid itself"

# ----- 12-13. Agent-side computed views (both badges) -----
header "12. TL: GET /v1/agents/{both}  (agent-1 carries BOTH whos; agent-2 carries the did:web)"
BADGE_1=$(curl_tl GET "/v1/agents/$AGENT_1")
IDS_1=$(printf '%s' "$BADGE_1" | jq -r '.identities | length')
[ "$IDS_1" = "2" ] || fail "agent-1 badge should show 2 identities, got $IDS_1"
KEYS_1=$(printf '%s' "$BADGE_1" | jq -r '.identities[] | select(.kind == "did:web") | .keys | length')
[ "$KEYS_1" = "2" ] || fail "agent-1's did:web entry should quote 2 verbatim keys, got $KEYS_1"
KEYSLOG_1=$(printf '%s' "$BADGE_1" | jq -r '.identities[] | select(.kind == "did:web") | .keysLogId // empty')
[ -n "$KEYSLOG_1" ] || fail "agent-1's did:web entry is missing keysLogId (the seal the keys are quoted from)"
DK_ON_1=$(printf '%s' "$BADGE_1" | jq -r '.identities[] | select(.kind == "did:key") | .value // empty')
[ "$DK_ON_1" = "$DID_KEY" ] || fail "agent-1's did:key entry missing"
BADGE_2=$(curl_tl GET "/v1/agents/$AGENT_2")
WHO_2=$(printf '%s' "$BADGE_2" | jq -r '.identities[0].value // empty')
[ "$WHO_2" = "$DID_WEB" ] || fail "agent-2 badge missing the identity join"
# Capture the sealed verbatim key material so the rotation step can
# show it change (read from the latest PROOF event on the stream).
SEALED_X_BEFORE=$(printf '%s' "$AUDIT" | \
  jq -r '[.records[].payload.producer.event | select(.keys)][0].keys[0].verificationMethod.publicKeyJwk.x // empty')
[ -n "$SEALED_X_BEFORE" ] || fail "sealed proof event is missing the verbatim verification method"
ok "agent-1: did:web (keys[2] quoted verbatim + keysLogId) + did:key (Ed25519) side by side; agent-2: $WHO_2"

header "13. TL: GET /v1/agents/$AGENT_1/identities  +  /identities/history"
curl_tl GET "/v1/agents/$AGENT_1/identities" >/dev/null
curl_tl GET "/v1/agents/$AGENT_1/identities/history" >/dev/null

# ----- 14-16. Rotation — ONE event, no fan-out -----
header "14. PUT /v2/ans/identities/$IDENTITY_ID  (rotate — stage a re-proof under ONE new key)"
signproof keygen -out "$KEY_DIR/who-rotated.pem" >/dev/null
ROT_RESP=$(curl_json PUT "/v2/ans/identities/$IDENTITY_ID" "$(jq -n --arg v "$DID_WEB" '{value: $v}')")
ROT_INPUT=$(printf '%s' "$ROT_RESP" | jq -r '.challenges[0].signingInput // empty')
[ -n "$ROT_INPUT" ] || fail "rotate did not return a fresh challenge"
note "until the new proof lands, the previously sealed state (2 keys) stands"

header "15. POST /v2/ans/identities/$IDENTITY_ID/verify-control  (new key → seals ONE IDENTITY_UPDATED)"
ROT_PROOF=$(signproof sign -key "$KEY_DIR/who-rotated.pem" -kid "${DID_WEB}#key-1" -input "$ROT_INPUT")
curl_json POST "/v2/ans/identities/$IDENTITY_ID/verify-control" \
  "$(jq -n --arg p "$ROT_PROOF" '{signedProofs: [$p]}')" >/dev/null
assert_2xx "rotation verify-control"

header "16. TL: the rotation sealed ONE IDENTITY_UPDATED — proven set 2 keys → 1, key material changed"
assert_tl_identity_audit "$IDENTITY_ID" 3
AUDIT=$(curl_tl GET "/v1/identities/$IDENTITY_ID/audit")
SEALED_X_AFTER=$(printf '%s' "$AUDIT" | \
  jq -r '[.records[].payload.producer.event | select(.keys)][0].keys[0].verificationMethod.publicKeyJwk.x // empty')
SEALED_KEYS_AFTER=$(printf '%s' "$AUDIT" | \
  jq -r '[.records[].payload.producer.event | select(.keys)][0].keys | length')
[ -n "$SEALED_X_AFTER" ] && [ "$SEALED_X_AFTER" != "$SEALED_X_BEFORE" ] || \
  fail "rotation not sealed (before=$SEALED_X_BEFORE after=$SEALED_X_AFTER)"
[ "$SEALED_KEYS_AFTER" = "1" ] || fail "rotated proven set should be 1 key, got $SEALED_KEYS_AFTER"
# Both linked badges reflect it immediately (read-time join) — with
# 10,000 linked agents this would still be ONE sealed event.
KEYS_1_AFTER=$(curl_tl GET "/v1/agents/$AGENT_1" | \
  jq -r '.identities[] | select(.kind == "did:web") | .keys | length')
[ "$KEYS_1_AFTER" = "1" ] || fail "agent-1's did:web entry should now quote 1 key, got $KEYS_1_AFTER"
ok "sealed key material flipped (${SEALED_X_BEFORE:0:12}… → ${SEALED_X_AFTER:0:12}…), set 2→1 — ONE event, zero agent-stream writes"

# ----- 17. Identity receipt -----
header "17. TL: GET /v1/identities/$IDENTITY_ID/receipt  (SCITT COSE_Sign1 for the identity leaf)"
IDENTITY_RECEIPT="$DATA/identity-receipt.cbor"
receipt_status=$(curl_tl_binary GET "/v1/identities/$IDENTITY_ID/receipt" "$IDENTITY_RECEIPT")
if [ "$receipt_status" = "200" ]; then
  first_byte=$(od -An -tx1 -N1 "$IDENTITY_RECEIPT" | tr -d ' \n')
  ok "identity receipt saved to $IDENTITY_RECEIPT (first byte=0x${first_byte}, want 0xd2 for COSE_Sign1)"
elif [ "$receipt_status" = "503" ]; then
  warn "receipt 503 — checkpoint has not yet covered the leaf; retry in a few seconds"
else
  fail "unexpected identity receipt status $receipt_status"
fi

# ----- 18. Unlink ONE agent — the other stays linked -----
header "18. DELETE /v2/ans/identities/$IDENTITY_ID/links/$AGENT_1  (unlink the did:web from agent #1 only)"
curl_json DELETE "/v2/ans/identities/$IDENTITY_ID/links/$AGENT_1" >/dev/null
assert_2xx "unlink"
assert_tl_identity_audit "$IDENTITY_ID" 4
BADGE_1=$(curl_tl GET "/v1/agents/$AGENT_1")
REMAINING_1=$(printf '%s' "$BADGE_1" | jq -r '(.identities | length) // 0')
KIND_1=$(printf '%s' "$BADGE_1" | jq -r '.identities[0].kind // empty')
REMAINING_2=$(curl_tl GET "/v1/agents/$AGENT_2" | jq -r '(.identities | length) // 0')
[ "$REMAINING_1" = "1" ] && [ "$KIND_1" = "did:key" ] || \
  fail "agent-1 should keep exactly its did:key link (got $REMAINING_1 × $KIND_1)"
[ "$REMAINING_2" = "1" ] || fail "agent-2 badge lost its link — unlink must be per-pair"
ok "the did:web↔agent-1 pair ended; agent-1's did:key link and agent-2's did:web link are untouched"
curl_tl GET "/v1/agents/$AGENT_1/identities/history" >/dev/null

# ----- 18b. Link liveness gate — terminal agents are not linkable -----
header "18b. Liveness gate: linking to a REVOKED agent fails 422 AGENT_NOT_LINKABLE (nothing seals)"
AGENT_3=$(register_agent "dead-$(openssl rand -hex 3).example.com")
curl_json POST "/v2/ans/agents/$AGENT_3/revoke" \
  "$(jq -n '{reason: "CESSATION_OF_OPERATION", comments: "liveness-gate demo"}')" >/dev/null
assert_2xx "revoke agent-3"
GATE_RESP=$(curl_json POST "/v2/ans/identities/$DK_ID/links" \
  "$(jq -n --arg a "$AGENT_3" '{agentIds: [$a]}')" || true)
GATE_CODE=$(printf '%s' "$GATE_RESP" | jq -r '.code // empty')
[ "$GATE_CODE" = "AGENT_NOT_LINKABLE" ] || \
  fail "linking a revoked agent must fail AGENT_NOT_LINKABLE, got: $GATE_RESP"
# Nothing sealed: the did:key stream still has exactly its 2 events.
assert_tl_identity_audit "$DK_ID" 2
ok "terminal agent rejected all-or-nothing; the did:key stream sealed nothing"

# ----- 19-20. Revoke — the who dies, the whats survive -----
header "19. POST /v2/ans/identities/$IDENTITY_ID/revoke  (state change — an identity cannot be deleted)"
curl_json POST "/v2/ans/identities/$IDENTITY_ID/revoke" >/dev/null
assert_2xx "revoke"
assert_tl_identity_audit "$IDENTITY_ID" 5

header "20. TL: did:web REVOKED; agent-2's join shows it; agent-1's did:key stays VERIFIED"
ID_STATUS=$(curl_tl GET "/v1/identities/$IDENTITY_ID" | jq -r '.status')
[ "$ID_STATUS" = "REVOKED" ] || fail "identity badge status=$ID_STATUS, want REVOKED"
BADGE_2=$(curl_tl GET "/v1/agents/$AGENT_2")
WHO_STATUS_2=$(printf '%s' "$BADGE_2" | jq -r '.identities[0].identityStatus // empty')
AGENT_STATUS_2=$(printf '%s' "$BADGE_2" | jq -r '.status')
[ "$WHO_STATUS_2" = "REVOKED" ] || fail "agent-2's identities[] should show REVOKED, got $WHO_STATUS_2"
# Visibility ≠ attestation: the revoked entry stays on the badge —
# a verifier must SEE the who was revoked — but its keys[] are gone.
REVOKED_KEYS_2=$(printf '%s' "$BADGE_2" | jq -r '(.identities[0].keys | length) // 0')
[ "$REVOKED_KEYS_2" = "0" ] || fail "revoked identity must quote no keys, got $REVOKED_KEYS_2"
[ "$AGENT_STATUS_2" = "ACTIVE" ] || fail "agent-2 status=$AGENT_STATUS_2, want ACTIVE — identity ops must never touch the agent"
# Each identity has its own lifecycle: the did:key on agent-1 is
# unaffected by the did:web's revocation.
DK_STATUS_1=$(curl_tl GET "/v1/agents/$AGENT_1" | \
  jq -r '.identities[] | select(.kind == "did:key") | .identityStatus // empty')
[ "$DK_STATUS_1" = "VERIFIED" ] || fail "agent-1's did:key should stay VERIFIED, got $DK_STATUS_1"
ok "ONE IDENTITY_REVOKED propagated to agent-2's join at read time; agent-1's did:key untouched; agents ACTIVE"

# ----- summary -----
header "Identity lifecycle complete"
printf "  did:web      %s  (VERIFIED w/ 2 keys → rotated to 1 → REVOKED)\n" "$IDENTITY_ID" >&2
printf "  did:key      %s  (Ed25519 — VERIFIED, linked to agent-1 throughout)\n" "$DK_ID" >&2
printf "  agent-1      %s (carried BOTH whos; kept the did:key after the did:web unlink)\n" "$AGENT_1" >&2
printf "  agent-2      %s (did:web-linked throughout; saw rotation + revocation at read time)\n" "$AGENT_2" >&2
printf "  receipt      %s\n" "$IDENTITY_RECEIPT" >&2
printf "\n" >&2
printf "  sealed: did:web stream — IDENTITY_VERIFIED (multi-key), IDENTITY_LINKED (ansIds[2]),\n" >&2
printf "  IDENTITY_UPDATED, IDENTITY_UNLINKED, IDENTITY_REVOKED; did:key stream —\n" >&2
printf "  IDENTITY_VERIFIED (Multikey, verbatim), IDENTITY_LINKED.\n" >&2
