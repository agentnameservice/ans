#!/usr/bin/env bash
# Drive the ACME verify-acme loop for a registered V2 agent and fetch
# the provider-issued server certificate once the order completes.
#
# Pairs with `start.sh --with-acme`: after registering with
#   scripts/demo/register.sh --v2 --register-only agent.yourdomain.com
# the pending response relays the provider's challenges. Publish ONE
# of them on the domain you control (usually the DNS-01 TXT record),
# then run this script. It:
#
#   1. shows the outstanding challenge artifacts (and dig-checks the
#      TXT record locally when `dig` is available),
#   2. POSTs verify-acme — the RA re-checks the artifact, answers the
#      provider, and finalizes the order,
#   3. re-POSTs while the provider reports the order still issuing
#      (phase CERTIFICATE_ISSUANCE), and
#   4. prints the issued certificate's subject/issuer/validity once
#      the agent reaches PENDING_DNS.
#
# Usage:
#   scripts/demo/acme-verify.sh             # agent from data/demo/last-agent-id
#   scripts/demo/acme-verify.sh <agentId>   # explicit agent
#   ACME_VERIFY_ATTEMPTS=40 scripts/demo/acme-verify.sh   # longer re-drive loop
#
# Exits 0 once the certificate is issued; non-zero if the challenge
# isn't live yet or the provider failed the order.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

AGENT="${1:-}"
if [ -z "$AGENT" ] && [ -f "$DATA/last-agent-id" ]; then
  AGENT=$(cat "$DATA/last-agent-id")
fi
[ -n "$AGENT" ] || fail "no agentId given and $DATA/last-agent-id not found — register first"

ATTEMPTS="${ACME_VERIFY_ATTEMPTS:-24}"
SLEEP_SECONDS=5
AGENT_BASE="/v2/ans/agents"

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh --with-acme first"
fi

# ----- 1. Show outstanding challenges (pre-validation only) -----
header "GET $AGENT_BASE/$AGENT"
DETAIL=$(curl_json GET "$AGENT_BASE/$AGENT")
STATUS=$(printf '%s' "$DETAIL" | jq -r '.agentStatus // empty')

if [ "$STATUS" = "PENDING_VALIDATION" ]; then
  CHALLENGES=$(printf '%s' "$DETAIL" | jq -c '.registrationPending.challenges // []')
  TXT_NAME=$(printf '%s' "$CHALLENGES" | jq -r '.[] | select(.type=="DNS_01") | .dnsRecord.name // empty')
  TXT_VALUE=$(printf '%s' "$CHALLENGES" | jq -r '.[] | select(.type=="DNS_01") | .dnsRecord.value // empty')
  if [ -n "$TXT_NAME" ]; then
    header "Challenge to publish (one of)"
    printf "  TXT  %s = %s\n" "$TXT_NAME" "$TXT_VALUE" >&2
    HTTP_PATH=$(printf '%s' "$CHALLENGES" | jq -r '.[] | select(.type=="HTTP_01") | .httpPath // empty')
    KEYAUTH=$(printf '%s' "$CHALLENGES" | jq -r '.[] | select(.type=="HTTP_01") | .keyAuthorization // .token // empty')
    if [ -n "$HTTP_PATH" ]; then
      printf "  HTTP http://<fqdn>%s → %s\n" "$HTTP_PATH" "$KEYAUTH" >&2
    fi
    # Local dig pre-check is advisory: your resolver may lag the
    # provider's, and the RA does its own authoritative check anyway.
    if command -v dig >/dev/null 2>&1; then
      SEEN=$(dig +short TXT "$TXT_NAME" 2>/dev/null | tr -d '"' || true)
      if printf '%s' "$SEEN" | grep -qF "$TXT_VALUE"; then
        ok "TXT record is visible to the local resolver"
      else
        note "TXT record not visible to the local resolver yet (propagation can take a minute)"
      fi
    fi
  fi
fi

# ----- 2/3. verify-acme, re-driving while the order is issuing -----
i=1
while :; do
  header "POST $AGENT_BASE/$AGENT/verify-acme  (attempt $i)"
  RESP=$(curl_json POST "$AGENT_BASE/$AGENT/verify-acme")
  # Error responses are RFC 7807 problem documents carrying `code` —
  # the success AgentStatus body never has one. (curl_json runs in a
  # command substitution, so its LAST_HTTP_STATUS isn't visible here.)
  ERR_CODE=$(printf '%s' "$RESP" | jq -r '.code // empty')
  if [ -n "$ERR_CODE" ]; then
    ERR_DETAIL=$(printf '%s' "$RESP" | jq -r '.detail // empty')
    fail "verify-acme failed ($ERR_CODE): $ERR_DETAIL"
  fi
  PHASE=$(printf '%s' "$RESP" | jq -r '.phase // empty')
  STATUS=$(printf '%s' "$RESP" | jq -r '.status // empty')
  if [ "$PHASE" != "CERTIFICATE_ISSUANCE" ]; then
    break
  fi
  if [ "$i" -ge "$ATTEMPTS" ]; then
    fail "order still issuing after $ATTEMPTS attempts — re-run this script to keep driving it"
  fi
  note "provider is still validating/issuing — retrying in ${SLEEP_SECONDS}s"
  sleep "$SLEEP_SECONDS"
  i=$((i + 1))
done

if [ "$STATUS" != "PENDING_DNS" ] && [ "$STATUS" != "ACTIVE" ]; then
  fail "unexpected post-verify state: status=$STATUS phase=$PHASE"
fi
ok "domain validated, order complete (status=$STATUS)"

# ----- 4. Fetch the provider-issued server certificate -----
header "GET $AGENT_BASE/$AGENT/certificates/server"
CERTS=$(curl_json GET "$AGENT_BASE/$AGENT/certificates/server")
LEAF=$(printf '%s' "$CERTS" | jq -r '.[0].certificatePEM // empty')
[ -n "$LEAF" ] || fail "no server certificate returned"

header "Issued certificate"
printf '%s' "$LEAF" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/  /' >&2
ok "server certificate issued — publish the production DNS records and POST verify-dns to reach ACTIVE"
