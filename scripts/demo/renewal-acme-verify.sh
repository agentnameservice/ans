#!/usr/bin/env bash
# Drive the renewal verify-acme loop for an agent with a pending
# server-cert renewal, and fetch the provider-renewed certificate once
# the order completes. This is the renewal-lane counterpart to
# acme-verify.sh — it handles the asynchronous ACME path that
# renewal.sh (single-shot, synchronous-only) does not.
#
# Pairs with `start.sh --with-acme`. First submit a CSR renewal and
# stop before verification:
#   scripts/demo/renewal.sh --v2 --csr --skip-verify-acme
# Then run this script. It:
#
#   1. reads the pending renewal and shows the provider's challenge
#      artifacts to publish (DNS-01 TXT / HTTP-01) — unless the
#      provider reused a recent authorization, in which case there's
#      nothing to publish and issuance proceeds directly,
#   2. POSTs renewal verify-acme — the RA answers the provider and
#      finalizes the order,
#   3. re-POSTs while the provider reports the order still issuing
#      (status ISSUING_CERTIFICATE), and
#   4. prints the new leaf's TLSA record and certificate details once
#      the renewal reaches COMPLETED.
#
# Usage:
#   scripts/demo/renewal-acme-verify.sh                 # V2, agent from data/demo/last-agent-id
#   scripts/demo/renewal-acme-verify.sh --v1            # V1 lane
#   scripts/demo/renewal-acme-verify.sh --agent <uuid>  # explicit agent
#   RENEWAL_VERIFY_ATTEMPTS=40 scripts/demo/renewal-acme-verify.sh   # longer re-drive loop
#
# Exits 0 once the renewal is COMPLETED; non-zero if the challenge
# isn't live yet or the provider failed the order.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# ----- arg parsing -----
LANE="v2"
AGENT_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --v1) LANE="v1"; shift ;;
    --v2) LANE="v2"; shift ;;
    --agent) AGENT_ARG="$2"; shift 2 ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//' >&2
      exit 0
      ;;
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

# Resolve agent id (env > flag > file).
AGENT="${AGENT_ID:-}"
if [ -z "$AGENT" ] && [ -n "$AGENT_ARG" ]; then
  AGENT="$AGENT_ARG"
fi
if [ -z "$AGENT" ] && [ -f "$LAST_AGENT_FILE" ]; then
  AGENT=$(cat "$LAST_AGENT_FILE")
fi
[ -n "$AGENT" ] || fail "no agentId given and $LAST_AGENT_FILE not found — submit a renewal first"

ATTEMPTS="${RENEWAL_VERIFY_ATTEMPTS:-24}"
SLEEP_SECONDS=5
RENEWAL_BASE="$AGENT_BASE/$AGENT/certificates/server/renewal"

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh --with-acme first"
fi

# ----- 1. Read the pending renewal + show what to publish -----
header "GET $RENEWAL_BASE"
RENEWAL=$(curl_json GET "$RENEWAL_BASE")
RCODE=$(printf '%s' "$RENEWAL" | jq -r '.code // empty')
if [ -n "$RCODE" ]; then
  fail "no readable renewal ($RCODE) — submit one first: scripts/demo/renewal.sh --$LANE --csr --skip-verify-acme"
fi
RSTATUS=$(printf '%s' "$RENEWAL" | jq -r '.status // empty')
case "$RSTATUS" in
  COMPLETED) ok "renewal already COMPLETED — nothing to drive"; exit 0 ;;
  FAILED)
    REASON=$(printf '%s' "$RENEWAL" | jq -r '.failureReason // "unknown"')
    fail "renewal already FAILED: $REASON — submit a fresh renewal"
    ;;
  PENDING_VALIDATION|ISSUING_CERTIFICATE) : ;;
  *) fail "unexpected renewal status '$RSTATUS' — expected PENDING_VALIDATION or ISSUING_CERTIFICATE" ;;
esac

TXT_NAME=$(printf '%s' "$RENEWAL" | jq -r '.challenges.dns01.dnsRecord.name // empty')
TXT_VALUE=$(printf '%s' "$RENEWAL" | jq -r '.challenges.dns01.dnsRecord.value // empty')
HTTP_PATH=$(printf '%s' "$RENEWAL" | jq -r '.challenges.http01.httpPath // empty')
HTTP_KEYAUTH=$(printf '%s' "$RENEWAL" | jq -r '.challenges.http01.keyAuthorization // .challenges.http01.token // empty')
if [ -n "$TXT_NAME" ] || [ -n "$HTTP_PATH" ]; then
  header "Challenge to publish (one of)"
  [ -n "$TXT_NAME" ] && printf "  TXT  %s = %s\n" "$TXT_NAME" "$TXT_VALUE" >&2
  [ -n "$HTTP_PATH" ] && printf "  HTTP http://<fqdn>%s → %s\n" "$HTTP_PATH" "$HTTP_KEYAUTH" >&2
  # Local dig pre-check is advisory: your resolver may lag the
  # provider's, and the RA does its own authoritative check anyway.
  if [ -n "$TXT_NAME" ] && command -v dig >/dev/null 2>&1; then
    SEEN=$(dig +short TXT "$TXT_NAME" 2>/dev/null | tr -d '"' || true)
    if printf '%s' "$SEEN" | grep -qF "$TXT_VALUE"; then
      ok "TXT record is visible to the local resolver"
    else
      note "TXT record not visible to the local resolver yet (propagation can take a minute)"
    fi
  fi
else
  note "renewal carries no challenges — the provider reused a recent authorization; issuance proceeds directly"
fi

# ----- 2/3. verify-acme, re-driving while the order is issuing -----
i=1
while :; do
  header "POST $RENEWAL_BASE/verify-acme  (attempt $i)"
  RESP=$(curl_json POST "$RENEWAL_BASE/verify-acme")
  # Error responses are RFC 7807 problem documents carrying `code`;
  # the success RenewalVerificationResponse never has one.
  ERR_CODE=$(printf '%s' "$RESP" | jq -r '.code // empty')
  if [ -n "$ERR_CODE" ]; then
    ERR_DETAIL=$(printf '%s' "$RESP" | jq -r '.detail // empty')
    fail "renewal verify-acme failed ($ERR_CODE): $ERR_DETAIL"
  fi
  STATUS=$(printf '%s' "$RESP" | jq -r '.status // empty')
  if [ "$STATUS" != "ISSUING_CERTIFICATE" ]; then
    break
  fi
  if [ "$i" -ge "$ATTEMPTS" ]; then
    fail "order still issuing after $ATTEMPTS attempts — re-run this script to keep driving it"
  fi
  note "provider is still validating/issuing — retrying in ${SLEEP_SECONDS}s"
  sleep "$SLEEP_SECONDS"
  i=$((i + 1))
done

if [ "$STATUS" != "COMPLETED" ]; then
  fail "unexpected post-verify renewal status: $STATUS"
fi
ok "renewal COMPLETED — provider issued the renewed certificate"

# ----- 4. Surface the new leaf's TLSA record + certificate -----
TLSA_NAME=$(printf '%s' "$RESP" | jq -r '.tlsaDnsRecord.name // empty')
TLSA_VALUE=$(printf '%s' "$RESP" | jq -r '.tlsaDnsRecord.value // empty')
if [ -n "$TLSA_NAME" ]; then
  header "Updated TLSA record to publish"
  printf "  TLSA %s = %s\n" "$TLSA_NAME" "$TLSA_VALUE" >&2
fi

header "GET $AGENT_BASE/$AGENT/certificates/server"
CERTS=$(curl_json GET "$AGENT_BASE/$AGENT/certificates/server")
LEAF=$(printf '%s' "$CERTS" | jq -r '.[0].certificatePEM // empty')
if [ -n "$LEAF" ]; then
  header "Renewed certificate"
  printf '%s' "$LEAF" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /' >&2
fi
ok "renewal complete — publish the updated TLSA record to finish the rollover"
