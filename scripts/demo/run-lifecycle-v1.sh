#!/usr/bin/env bash
# Walk a fresh agent through the full V1 RA lifecycle, printing every
# request + response pair in color. V1 counterpart to
# run-lifecycle.sh, using /v1/agents/* and the V1 TL ingest lane.
#
#   1. POST   /v1/agents/register                                (register)
#   2. GET    /v1/agents/{id}                                    (detail, PENDING_VALIDATION — challenges[] only, no dnsRecords yet)
#   3. POST   /v1/agents/{id}/verify-acme                        (→ PENDING_DNS; no V1 TL emit; issues identity + server certs)
#   4. GET    /v1/agents/{id}                                    (detail, PENDING_DNS — production dnsRecords with real TLSA fingerprint)
#   5. POST   /v1/agents/{id}/verify-dns                         (→ ACTIVE; emits V1 AGENT_REGISTERED)
#   6. GET    /v1/agents/{id}                                    (detail, now ACTIVE)
#   7. GET    /v1/agents/{id}/certificates/identity              (issued cert)
#   8. Wait for the outbox worker to push the one V1 event to the TL
#   9. GET    TL /v1/agents/{id}/audit                           (shape: schemaVersion=V1)
#  10. GET    TL /v1/agents/{id}                                 (badge: schemaVersion=V1)
#  11. POST   /v1/agents/{id}/revoke                             (emits V1 AGENT_REVOKED)
#
# Lifecycle invariants this script exercises:
#   - V1 emits NO TL leaf at register or verify-acme — only on
#     verify-dns (terminal AGENT_REGISTERED) and revoke (terminal
#     AGENT_REVOKED).
#   - Badge/audit responses carry `schemaVersion: "V1"` so SDK
#     parsers pick the V1 envelope shape.
#   - The TL's `/v1/internal/agents/event` ingest route receives the
#     V1 envelopes (not `/v2/...`) because the outbox worker routes
#     per-row by schema_version.
#
# Usage:
#   scripts/demo/run-lifecycle-v1.sh                            # random host, version 1.0.0
#   scripts/demo/run-lifecycle-v1.sh myagent.example.com        # specific host, 1.0.0
#   scripts/demo/run-lifecycle-v1.sh myagent.example.com 2.1.0  # specific host + version
#
# Env:
#   AGENT_HOST      override the host component
#   AGENT_VERSION   override the version component (default 1.0.0)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# ----- arg parsing (same shape as run-lifecycle.sh) -----
ARG1="${1:-}"
ARG2="${2:-}"
if [[ "$ARG1" == ans://* ]]; then
  rest="${ARG1#ans://}"
  if [[ "$rest" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)\.(.+)$ ]]; then
    ARG_VERSION="${BASH_REMATCH[1]}"
    ARG_HOST="${BASH_REMATCH[2]}"
  else
    fail "ANS name must be ans://vMAJOR.MINOR.PATCH.host; got $ARG1"
  fi
else
  ARG_HOST="$ARG1"
  ARG_VERSION="$ARG2"
fi

AGENT_VERSION="${AGENT_VERSION:-${ARG_VERSION:-1.0.0}}"
if [ -n "${AGENT_HOST:-}" ]; then
  :
elif [ -n "$ARG_HOST" ]; then
  AGENT_HOST="$ARG_HOST"
else
  # "v1demo-" prefix so V1 demo agents are distinguishable from V2
  # agents in shared outbox / log output.
  AGENT_HOST="v1demo-$(openssl rand -hex 4).example.com"
fi
ANS_NAME="ans://v${AGENT_VERSION}.${AGENT_HOST}"

header "V1 demo target"
printf "  ansName   %s\n" "$ANS_NAME" >&2
printf "  host      %s\n" "$AGENT_HOST" >&2
printf "  version   %s\n" "$AGENT_VERSION" >&2

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# ----- 0. Build a matching CSR -----
header "0. Generate identity CSR"
CSR_DIR="$DATA/csr"
rm -rf "$CSR_DIR"
mkdir -p "$CSR_DIR"
cat >"$CSR_DIR/openssl.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $ANS_NAME
[v3_req]
subjectAltName = URI:$ANS_NAME
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$CSR_DIR/key.pem" 2>/dev/null
openssl req -new -key "$CSR_DIR/key.pem" \
  -config "$CSR_DIR/openssl.cnf" \
  -out "$CSR_DIR/csr.pem" 2>/dev/null
CSR_PEM=$(cat "$CSR_DIR/csr.pem")
ok "CSR for $ANS_NAME written to $CSR_DIR/csr.pem"

# Server CSR — V1 register now exercises the serverCsrPEM path where
# the RA's configured server CA signs the TLS cert.
cat >"$CSR_DIR/server.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $AGENT_HOST
[v3_req]
subjectAltName = DNS:$AGENT_HOST
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$CSR_DIR/server.key" 2>/dev/null
openssl req -new -key "$CSR_DIR/server.key" \
  -config "$CSR_DIR/server.cnf" \
  -out "$CSR_DIR/server.csr" 2>/dev/null
SERVER_CSR_PEM=$(cat "$CSR_DIR/server.csr")

# ----- 1. V1 Register -----
#
# Note the different URL path: /v1/agents/register (byte-for-byte
# parity with the reference RA's path) vs the V2 shape
# /v2/ans/agents.
header "1. POST /v1/agents/register"
REG_REQ=$(jq -n \
  --arg host "$AGENT_HOST" \
  --arg version "$AGENT_VERSION" \
  --arg csr "$CSR_PEM" \
  --arg srvCsr "$SERVER_CSR_PEM" '
  {
    agentDisplayName: "v1-demo-agent",
    agentDescription: "V1 lane demo — same domain logic, different wire shape + TL lane",
    version:          $version,
    agentHost:        $host,
    endpoints: [{
      agentUrl:   ("https://" + $host + "/mcp"),
      protocol:   "MCP",
      transports: ["SSE"]
    }],
    identityCsrPEM: $csr,
    serverCsrPEM:   $srvCsr
  }')

REG_RESP=$(curl_json POST /v1/agents/register "$REG_REQ")
AGENT_ID=$(printf '%s' "$REG_RESP" | jq -r '.agentId // empty')
if [ -z "$AGENT_ID" ]; then
  fail "no agentId in V1 register response — see the RESP above"
fi
echo "$AGENT_ID" >"$DATA/last-agent-id-v1"
ok "V1 agentId=$AGENT_ID"

# ----- 2. V1 Detail (pending) -----
header "2. GET /v1/agents/$AGENT_ID  (expect PENDING_VALIDATION)"
curl_json GET "/v1/agents/$AGENT_ID" >/dev/null

# ----- 3. V1 verify-acme -----
#
# V1 invariant: this MUST NOT emit a TL leaf. The V1 enum has no
# intermediate DOMAIN_VALIDATION type — the reference records the
# transition in its domain-level lifecycle store only. The agent's
# state still advances to PENDING_DNS.
#
# Cert issuance happens here, NOT at register: the RA only signs the
# identity + server CSRs once the operator has proven domain control
# via the ACME DNS-01 challenge. This is also when production DNS
# records (TRUST/BADGE/DISCOVERY/TLSA) become computable.
header "3. POST /v1/agents/$AGENT_ID/verify-acme  (→ PENDING_DNS, no V1 TL emit; issues identity + server certs)"
curl_json POST "/v1/agents/$AGENT_ID/verify-acme" >/dev/null
assert_2xx "verify-acme"

# ----- 4. V1 Detail (pending DNS) -----
#
# Now that verify-acme has issued the server cert, the GET detail
# response surfaces the full production record set the operator must
# publish before verify-dns will succeed: DISCOVERY (TXT routing
# pointer), BADGE (TXT public discovery hint), and TLSA (cert
# binding, fingerprint pinned to the just-issued server leaf).
header "4. GET /v1/agents/$AGENT_ID  (PENDING_DNS — production dnsRecords now materialized)"
curl_json GET "/v1/agents/$AGENT_ID" >/dev/null

# ----- 5. V1 verify-dns -----
#
# V1 invariant: the FIRST TL leaf V1 agents ever receive is
# AGENT_REGISTERED, emitted exactly here. (V2 equivalent emits
# AGENT_ACTIVE.)
header "5. POST /v1/agents/$AGENT_ID/verify-dns  (→ ACTIVE; emits V1 AGENT_REGISTERED)"
if [ -n "${ANS_DNS_ZONE:-}" ] && [ -x "$BIN/ans-dns" ]; then
  note "installing agent records into $ANS_DNS_ZONE via ans-dns"
  "$BIN/ans-dns" install --zone "$ANS_DNS_ZONE" --api-key "$RA_API_KEY" "$RA_URL" "$AGENT_ID"
else
  note "noop DNS verifier accepts any operator DNS state; production plugs in a real verifier"
fi
curl_json POST "/v1/agents/$AGENT_ID/verify-dns" >/dev/null
assert_2xx "verify-dns"

# ----- 6. V1 Detail (active) -----
header "6. GET /v1/agents/$AGENT_ID  (now ACTIVE)"
curl_json GET "/v1/agents/$AGENT_ID" >/dev/null

# ----- 7. V1 identity certs -----
header "7. GET /v1/agents/$AGENT_ID/certificates/identity"
curl_json GET "/v1/agents/$AGENT_ID/certificates/identity" >/dev/null

# ----- 8. Wait for outbox worker -----
#
# V1 differs from V2 here: V2 writes 3 outbox rows across a register
# → verify-acme → verify-dns lifecycle. V1 writes ONE row — only the
# terminal AGENT_REGISTERED on verify-dns ACTIVE. This step proves
# the "V1 lifecycle emits exactly one leaf" invariant end-to-end.
header "8. Wait for outbox worker to push 1 V1 event to the TL"
poll_tl_audit "$AGENT_ID" 1 30
ok "TL received the single V1 AGENT_REGISTERED event"

# ----- 9. V1 audit (schemaVersion=V1) -----
#
# The TL's badge/audit responses are schema-agnostic — one endpoint
# family, one wrapper shape, with `schemaVersion` distinguishing V1
# vs V2 payloads. We verify below that our V1 agent produced a V1
# leaf (schemaVersion: "V1" in the audit + badge responses).
header "9. TL: GET /v1/agents/$AGENT_ID/audit  (expect schemaVersion=V1)"
AUDIT_JSON=$(curl_tl GET "/v1/agents/$AGENT_ID/audit")
audit_version=$(printf '%s' "$AUDIT_JSON" | jq -r '.records[0].schemaVersion // empty')
if [ "$audit_version" != "V1" ]; then
  fail "V1 audit response missing schemaVersion=V1 (got '$audit_version')"
fi
audit_event_type=$(printf '%s' "$AUDIT_JSON" | jq -r '.records[0].payload.producer.event.eventType // empty')
if [ "$audit_event_type" != "AGENT_REGISTERED" ]; then
  fail "V1 audit event_type should be AGENT_REGISTERED; got '$audit_event_type'"
fi
ok "audit confirms schemaVersion=V1, eventType=AGENT_REGISTERED"

# ----- 10. V1 badge -----
header "10. TL: GET /v1/agents/$AGENT_ID  (badge; expect schemaVersion=V1)"
BADGE_JSON=$(curl_tl GET "/v1/agents/$AGENT_ID")
badge_version=$(printf '%s' "$BADGE_JSON" | jq -r '.schemaVersion // empty')
badge_status=$(printf '%s' "$BADGE_JSON" | jq -r '.status // empty')
if [ "$badge_version" != "V1" ]; then
  fail "V1 badge response missing schemaVersion=V1 (got '$badge_version')"
fi
ok "badge confirms schemaVersion=V1, status=$badge_status"

# ----- 11. V1 revoke -----
#
# Emits the V1 AGENT_REVOKED terminal event. The TL should now have
# two V1 leaves for this agent: AGENT_REGISTERED (from verify-dns)
# and AGENT_REVOKED (from here).
header "11. POST /v1/agents/$AGENT_ID/revoke  (emits V1 AGENT_REVOKED)"
REV_REQ=$(jq -n '{reason: "CESSATION_OF_OPERATION", comments: "V1 demo teardown"}')
curl_json POST "/v1/agents/$AGENT_ID/revoke" "$REV_REQ" >/dev/null

# Wait for the second V1 event to land.
poll_tl_audit "$AGENT_ID" 2 30

# Confirm the audit now shows both events on the V1 schema.
AUDIT_JSON=$(curl_tl GET "/v1/agents/$AGENT_ID/audit")
event_types=$(printf '%s' "$AUDIT_JSON" | jq -r '[.records[].payload.producer.event.eventType] | sort | join(",")')
expected="AGENT_REGISTERED,AGENT_REVOKED"
if [ "$event_types" != "$expected" ]; then
  fail "V1 audit eventTypes='$event_types'; expected '$expected'"
fi
ok "audit now shows both V1 terminal events (AGENT_REGISTERED + AGENT_REVOKED)"

# ----- summary -----
header "V1 Lifecycle complete"
printf "  agentId     %s\n" "$AGENT_ID" >&2
printf "  ansName     %s\n" "$ANS_NAME" >&2
printf "  saved to    %s\n" "$DATA/last-agent-id-v1" >&2
printf "\n" >&2
printf "  V1 contract verified end-to-end:\n" >&2
printf "    - %s\n" "no TL emit at register (V1 has no intermediate enum value)" >&2
printf "    - %s\n" "no TL emit at verify-acme (same reason)" >&2
printf "    - %s\n" "AGENT_REGISTERED emitted ONCE at verify-dns ACTIVE" >&2
printf "    - %s\n" "AGENT_REVOKED emitted at revoke" >&2
printf "    - %s\n" "badge + audit responses stamp schemaVersion=V1" >&2
printf "    - %s\n" "outbox routed V1 events to /v1/internal/agents/event" >&2
