#!/usr/bin/env bash
# Drive an agent from PENDING_DNS to ACTIVE by POSTing verify-dns —
# the last registration step. This is the piece that finishes a
# registration started with `register.sh --register-only` and advanced
# past validation with `acme-verify.sh`.
#
# EXECUTE this script; do NOT `source` it. Like every demo script it
# runs `set -euo pipefail`, which would leak into and kill your
# interactive shell if sourced.
#
# With the default stack (dns.type: noop) verify-dns accepts any DNS
# state, so this just flips the agent to ACTIVE — nothing to publish.
# With dns.type: lookup it queries real public DNS; if the required
# records aren't live the response lists what's missing and you re-run
# after publishing them.
#
# Usage:
#   scripts/demo/verify-dns.sh                 # V2, agent from data/demo/last-agent-id
#   scripts/demo/verify-dns.sh --v1            # V1 lane
#   scripts/demo/verify-dns.sh --agent <uuid>  # explicit agent
#
# Exits 0 once the agent is ACTIVE; non-zero if required records are
# missing (lookup DNS) or the agent isn't in a verifiable state.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

LANE="v2"
AGENT_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --v1) LANE="v1"; shift ;;
    --v2) LANE="v2"; shift ;;
    --agent) AGENT_ARG="$2"; shift 2 ;;
    --help|-h) grep '^#' "$0" | sed 's/^# \?//' >&2; exit 0 ;;
    *) fail "unknown arg: $1" ;;
  esac
done

if [ "$LANE" = "v1" ]; then
  AGENT_BASE="/v1/agents"
  LAST_AGENT_FILE="$DATA/last-agent-id-v1"
else
  AGENT_BASE="/v2/ans/agents"
  LAST_AGENT_FILE="$DATA/last-agent-id"
fi

AGENT="${AGENT_ID:-}"
[ -z "$AGENT" ] && [ -n "$AGENT_ARG" ] && AGENT="$AGENT_ARG"
[ -z "$AGENT" ] && [ -f "$LAST_AGENT_FILE" ] && AGENT=$(cat "$LAST_AGENT_FILE")
[ -n "$AGENT" ] || fail "no agentId given and $LAST_AGENT_FILE not found — register first"

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# ----- 1. Check current state -----
header "GET $AGENT_BASE/$AGENT"
DETAIL=$(curl_json GET "$AGENT_BASE/$AGENT")
STATUS=$(printf '%s' "$DETAIL" | jq -r '.agentStatus // .status // empty')
case "$STATUS" in
  ACTIVE) ok "agent is already ACTIVE — nothing to do"; exit 0 ;;
  PENDING_DNS) : ;;
  PENDING_VALIDATION)
    fail "agent is still PENDING_VALIDATION — run scripts/demo/acme-verify.sh first to get past domain validation, then re-run this"
    ;;
  *) fail "agent status is '$STATUS' — verify-dns only applies to PENDING_DNS agents" ;;
esac

# ----- 2. verify-dns -----
header "POST $AGENT_BASE/$AGENT/verify-dns"
RESP=$(curl_json POST "$AGENT_BASE/$AGENT/verify-dns")
# RFC 7807 problem documents carry `code`; the success body does not.
ERR_CODE=$(printf '%s' "$RESP" | jq -r '.code // empty')
if [ -n "$ERR_CODE" ]; then
  ERR_DETAIL=$(printf '%s' "$RESP" | jq -r '.detail // empty')
  fail "verify-dns failed ($ERR_CODE): $ERR_DETAIL"
fi
RSTATUS=$(printf '%s' "$RESP" | jq -r '.status // empty')
if [ "$RSTATUS" = "ERROR" ]; then
  # 422 DnsVerificationError — required records aren't live (lookup DNS).
  warn "required DNS records are not yet satisfied — publish these and re-run:"
  printf '%s' "$RESP" | jq -r '
    (.missingRecords[]?   | "  MISSING    \(.type) \(.name) = \(.value)"),
    (.incorrectRecords[]? | "  INCORRECT  \(.type) \(.name) (expected \(.value))")' >&2
  fail "verify-dns reported missing/incorrect records"
fi

# ----- 3. Confirm ACTIVE -----
FINAL=$(curl_json GET "$AGENT_BASE/$AGENT")
FSTATUS=$(printf '%s' "$FINAL" | jq -r '.agentStatus // .status // empty')
if [ "$FSTATUS" != "ACTIVE" ]; then
  fail "expected ACTIVE after verify-dns, got '$FSTATUS'"
fi
ok "agent is ACTIVE — registration complete"
printf "  agentId %s\n" "$AGENT" >&2
printf "  lane    %s\n" "$LANE" >&2
note "next: renew its server cert with scripts/demo/renewal.sh --$LANE --csr (add --skip-verify-acme + renewal-acme-verify.sh for the async ACME path)"
