#!/usr/bin/env bash
# Revoke the last-registered demo agent (or an agent you name).
#
# Usage:
#   scripts/demo/revoke.sh                           # revoke last from run-lifecycle.sh
#   scripts/demo/revoke.sh <agentId>                 # revoke a specific id
#   REASON=SUPERSEDED scripts/demo/revoke.sh         # override reason
#
# Default REASON is KEY_COMPROMISE. Full enum:
#   KEY_COMPROMISE | CESSATION_OF_OPERATION | AFFILIATION_CHANGED
#   SUPERSEDED     | CERTIFICATE_HOLD       | PRIVILEGE_WITHDRAWN
#   AA_COMPROMISE

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

REASON="${REASON:-KEY_COMPROMISE}"
AGENT_ID="${1:-}"

if [ -z "$AGENT_ID" ]; then
  if [ -f "$DATA/last-agent-id" ]; then
    AGENT_ID=$(cat "$DATA/last-agent-id")
  else
    fail "no agentId given and $DATA/last-agent-id not found — pass one as the first argument"
  fi
fi

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

header "POST /v2/ans/agents/$AGENT_ID/revoke  (reason=$REASON)"
BODY=$(jq -n --arg r "$REASON" '{ reason: $r, comments: "demo revoke" }')
curl_json POST "/v2/ans/agents/$AGENT_ID/revoke" "$BODY" >/dev/null

header "GET /v2/ans/agents/$AGENT_ID  (expect REVOKED)"
curl_json GET "/v2/ans/agents/$AGENT_ID" >/dev/null

# The outbox worker picks up the AGENT_REVOCATION event and POSTs it
# to the TL. Wait for it to show up on the audit endpoint before we
# declare success — otherwise a fast-following `stop.sh --clean` could
# race ahead of delivery.
header "Wait for AGENT_REVOKED to reach the TL"
poll_tl_audit "$AGENT_ID" 2 30
ok "TL shows 2 events (active, revocation)"

header "TL: GET /v1/agents/$AGENT_ID/audit"
curl_tl GET "/v1/agents/$AGENT_ID/audit" >/dev/null

header "TL: GET /v1/agents/$AGENT_ID (badge should read REVOKED)"
curl_tl GET "/v1/agents/$AGENT_ID" >/dev/null

ok "revocation complete"
