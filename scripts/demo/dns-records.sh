#!/usr/bin/env bash
# Print the DNS records an agent's operator must publish, and
# optionally verify them through the RA's configured DNS verifier.
#
# This is the operator-facing companion to register.sh --register-only:
# after registering with a real domain, run this to see exactly what to
# create at your DNS provider, publish the records, then re-run with
# --verify to drive POST verify-dns (the RA queries its configured DNS
# server — real public DNS such as 1.1.1.1 when start.sh was launched
# with ANS_DNS_TYPE=lookup ANS_DNS_SERVER=1.1.1.1:53).
#
# What it prints depends on where the agent is in the flow:
#   PENDING_VALIDATION  the domain-control challenge artifacts (publish
#                       ONE: the DNS-01 TXT record, or the HTTP-01
#                       resource), then run scripts/demo/acme-verify.sh
#   PENDING_CERTS       nothing to publish — certificate issuance is in
#                       flight (or failed); shows the next step
#   PENDING_DNS         the production record set (SVCB / TXT / TLSA /
#                       HTTPS per the registration's discoveryProfiles),
#                       plus copy-pasteable dig commands to spot-check
#   ACTIVE              nothing pending — records were already verified
#
# EXECUTE this script; do NOT `source` it (set -euo pipefail would leak
# into your interactive shell).
#
# Usage:
#   scripts/demo/dns-records.sh                             # agent from data/demo/last-agent-id
#   scripts/demo/dns-records.sh <agent-uuid>                # explicit agent
#   scripts/demo/dns-records.sh agent.example.com           # resolve by host (V2 list)
#   scripts/demo/dns-records.sh ans://v1.0.0.agent.example.com
#   scripts/demo/dns-records.sh --verify [...]              # also POST verify-dns (PENDING_DNS only)
#   scripts/demo/dns-records.sh --json [...]                # raw JSON records on stdout
#   scripts/demo/dns-records.sh --v1 [...]                  # V1 lane (uuid / last-agent-id-v1 only)
#
# Name resolution (host / ans:// forms) uses the V2 list endpoint's
# agentHost filter and therefore only sees agents owned by the demo API
# key; the V1 lane has no list route, so --v1 takes a UUID (or the
# last-agent-id-v1 file).
#
# Env:
#   AGENT_ID         overrides every other agent selector
#   ANS_DNS_SERVER   DNS server for the printed dig hints
#                    (default: value persisted by start.sh, else 1.1.1.1:53)
#
# Exits 0 when records were printed (and, with --verify, verification
# passed); non-zero on missing/incorrect records or unresolvable agent.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

LANE="v2"
VERIFY=0
JSON_OUT=0
AGENT_ARG=""
POSITIONAL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --v1) LANE="v1"; shift ;;
    --v2) LANE="v2"; shift ;;
    --agent) AGENT_ARG="$2"; shift 2 ;;
    --verify) VERIFY=1; shift ;;
    --json) JSON_OUT=1; shift ;;
    --help|-h) grep '^#' "$0" | sed 's/^# \?//' >&2; exit 0 ;;
    -*) fail "unknown arg: $1" ;;
    *) POSITIONAL="$1"; shift ;;
  esac
done

if [ "$LANE" = "v1" ]; then
  AGENT_BASE="/v1/agents"
  LAST_AGENT_FILE="$DATA/last-agent-id-v1"
else
  AGENT_BASE="/v2/ans/agents"
  LAST_AGENT_FILE="$DATA/last-agent-id"
fi

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# ----- resolve the agent id -----
#
# Precedence: AGENT_ID env > --agent > positional > last-agent-id file.
# A positional that isn't a UUID is treated as an ANS name / host and
# resolved through the V2 list endpoint's agentHost filter.
is_uuid() {
  [[ "$1" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

resolve_by_name() {
  local input="$1" host ver=""
  if [[ "$input" == ans://* ]]; then
    local rest="${input#ans://}"
    if [[ "$rest" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)\.(.+)$ ]]; then
      ver="${BASH_REMATCH[1]}"
      host="${BASH_REMATCH[2]}"
    else
      fail "ANS name must be ans://vMAJOR.MINOR.PATCH.host; got $input"
    fi
  else
    host="$input"
  fi
  [ "$LANE" = "v2" ] || fail "name resolution needs the V2 list endpoint; pass a UUID with --v1"

  note "resolving $input via GET $AGENT_BASE?agentHost=$host&status=ALL"
  local list matches count
  list=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" \
    "$RA_URL$AGENT_BASE?agentHost=$host&status=ALL")
  matches=$(printf '%s' "$list" | jq -c --arg v "$ver" \
    '[.items[]? | select($v == "" or .version == $v)]')
  count=$(printf '%s' "$matches" | jq 'length')
  case "$count" in
    0) fail "no registration found for host '$host'${ver:+ version $ver} (owned by this API key)" ;;
    1) printf '%s' "$matches" | jq -r '.[0].agentId' ;;
    *)
      warn "host '$host' has $count registrations — disambiguate with the full ans:// name or a UUID:"
      printf '%s' "$matches" | jq -r '.[] | "  \(.ansName)  \(.status)  \(.agentId)"' >&2
      exit 1
      ;;
  esac
}

AGENT="${AGENT_ID:-}"
[ -z "$AGENT" ] && [ -n "$AGENT_ARG" ] && AGENT="$AGENT_ARG"
if [ -z "$AGENT" ] && [ -n "$POSITIONAL" ]; then
  if is_uuid "$POSITIONAL"; then
    AGENT="$POSITIONAL"
  else
    AGENT=$(resolve_by_name "$POSITIONAL")
  fi
fi
[ -z "$AGENT" ] && [ -f "$LAST_AGENT_FILE" ] && AGENT=$(cat "$LAST_AGENT_FILE")
[ -n "$AGENT" ] || fail "no agent given and $LAST_AGENT_FILE not found — register first"

# ----- fetch detail -----
header "GET $AGENT_BASE/$AGENT"
DETAIL=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" "$RA_URL$AGENT_BASE/$AGENT")
ERR_CODE=$(printf '%s' "$DETAIL" | jq -r '.code // empty')
[ -z "$ERR_CODE" ] || fail "GET failed ($ERR_CODE): $(printf '%s' "$DETAIL" | jq -r '.detail // empty')"

STATUS=$(printf '%s' "$DETAIL" | jq -r '.agentStatus // .status // empty')
ANS_NAME=$(printf '%s' "$DETAIL" | jq -r '.ansName // empty')
AGENT_HOST=$(printf '%s' "$DETAIL" | jq -r '.agentHost // empty')
FLOW=$(printf '%s' "$DETAIL" | jq -r '.registrationPending.status // empty')
printf "  ansName  %s\n  status   %s%s\n" "$ANS_NAME" "$STATUS" \
  "${FLOW:+ (flow: $FLOW)}" >&2

# The dig hints target the same server the RA's lookup verifier uses
# when start.sh persisted it; otherwise default to Cloudflare.
DIG_TARGET="${ANS_DNS_SERVER:-1.1.1.1:53}"
DIG_HOST="${DIG_TARGET%:*}"
DIG_PORT="${DIG_TARGET##*:}"
DIG_ARGS="@$DIG_HOST"
[ "$DIG_PORT" != "$DIG_HOST" ] && [ "$DIG_PORT" != "53" ] && DIG_ARGS="@$DIG_HOST -p $DIG_PORT"
if [ -n "${ANS_DNS_TYPE:-}" ]; then
  note "RA DNS verifier: $ANS_DNS_TYPE${ANS_DNS_SERVER:+ via $ANS_DNS_SERVER}"
else
  note "RA DNS verifier mode unknown (start.sh default is noop — lookup mode: ANS_DNS_TYPE=lookup ANS_DNS_SERVER=1.1.1.1:53 scripts/demo/start.sh)"
fi

# print_records JSON_ARRAY — one block per record, stdout.
print_records() {
  local records="$1"
  printf '%s' "$records" | jq -r '
    to_entries[] |
    "record \(.key + 1)  [\(if .value.required then "REQUIRED" else "optional" end)]  purpose=\(.value.purpose)\n" +
    "  type   \(.value.type)\n" +
    "  name   \(.value.name)\n" +
    "  value  \(.value.value)\n" +
    "  ttl    \(.value.ttl)\n"'
}

case "$FLOW" in
  PENDING_VALIDATION)
    CHALLENGES=$(printf '%s' "$DETAIL" | jq -c '.registrationPending.challenges // []')
    if [ "$JSON_OUT" = "1" ]; then
      printf '%s\n' "$CHALLENGES" | jq .
      exit 0
    fi
    header "Domain-control challenge — publish ONE of these"
    printf '%s' "$CHALLENGES" | jq -r --arg host "$AGENT_HOST" '
      .[] |
      if .type == "DNS_01" and .dnsRecord != null then
        "DNS-01   \(.dnsRecord.type) record\n  name   \(.dnsRecord.name)\n  value  \(.dnsRecord.value)\n"
      elif .type == "HTTP_01" then
        "HTTP-01  serve at  http://\($host)\(.httpPath // "/.well-known/acme-challenge/\(.token)")\n  body   \(.keyAuthorization // .token)\n"
      else
        "\(.type)  token=\(.token)"
      end'
    if [ "$LANE" = "v2" ]; then
      note "then: scripts/demo/acme-verify.sh   (issues certs → PENDING_DNS; re-run this script for the production records)"
    else
      note "then: curl -X POST $RA_URL$AGENT_BASE/$AGENT/verify-acme   (→ PENDING_DNS; re-run this script for the production records)"
    fi
    [ "$VERIFY" = "1" ] && fail "--verify applies to PENDING_DNS agents; this one still needs verify-acme"
    exit 0
    ;;
  PENDING_CERTS)
    header "Certificate issuance in flight — nothing to publish yet"
    printf '%s' "$DETAIL" | jq -r '.registrationPending.nextSteps[]? | "  \(.action): \(.description)"' >&2
    [ "$VERIFY" = "1" ] && fail "--verify applies to PENDING_DNS agents; certificate order is still open"
    exit 0
    ;;
  PENDING_DNS)
    RECORDS=$(printf '%s' "$DETAIL" | jq -c '.registrationPending.dnsRecords // []')
    COUNT=$(printf '%s' "$RECORDS" | jq 'length')
    if [ "$JSON_OUT" = "1" ]; then
      printf '%s\n' "$RECORDS" | jq .
    else
      header "DNS records to publish ($COUNT)"
      print_records "$RECORDS"
      header "Spot-check with dig"
      # SVCB/HTTPS use RFC 3597 generic qtype syntax (TYPE64/TYPE65):
      # stock macOS dig (BIND 9.10) doesn't know the SVCB/HTTPS
      # mnemonics and would silently query type A instead. Newer dig
      # (BIND 9.16+) accepts both forms.
      printf '%s' "$RECORDS" | jq -r '.[] | "\(.name) \(.type)"' | sort -u | while read -r name typ; do
        case "$typ" in
          SVCB)  typ="TYPE64" ;;
          HTTPS) typ="TYPE65" ;;
        esac
        printf 'dig %s %s %s +short\n' "$DIG_ARGS" "$name" "$typ"
      done
      note "TYPE64 = SVCB, TYPE65 = HTTPS (dig >= 9.16 also accepts the mnemonics)"
    fi
    ;;
  *)
    case "$STATUS" in
      ACTIVE)
        ok "agent is ACTIVE — its DNS records were already verified; nothing pending"
        ;;
      *)
        note "agent status is '$STATUS' — no pending DNS records to publish"
        ;;
    esac
    [ "$VERIFY" = "1" ] && fail "--verify applies to PENDING_DNS agents; status is '$STATUS'"
    exit 0
    ;;
esac

# ----- optional verification through the RA -----
[ "$VERIFY" = "1" ] || exit 0

header "POST $AGENT_BASE/$AGENT/verify-dns  (RA queries its configured DNS server)"
RESP=$(curl_json POST "$AGENT_BASE/$AGENT/verify-dns")
ERR_CODE=$(printf '%s' "$RESP" | jq -r '.code // empty')
if [ -n "$ERR_CODE" ]; then
  fail "verify-dns failed ($ERR_CODE): $(printf '%s' "$RESP" | jq -r '.detail // empty')"
fi
RSTATUS=$(printf '%s' "$RESP" | jq -r '.status // empty')
if [ "$RSTATUS" = "ERROR" ]; then
  warn "required records are not yet live — publish/fix these and re-run:"
  # missingRecords is a flat dnsRecord list; incorrectRecords nests the
  # expected record under .record with the live value in .found.
  printf '%s' "$RESP" | jq -r '
    (.missingRecords[]?   | "  MISSING    \(.type) \(.name) = \(.value)"),
    (.incorrectRecords[]? | "  INCORRECT  \(.record.type) \(.record.name) (expected \(.expected); live \(.found))")' >&2
  fail "verify-dns reported missing/incorrect records"
fi

FINAL=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" "$RA_URL$AGENT_BASE/$AGENT")
FSTATUS=$(printf '%s' "$FINAL" | jq -r '.agentStatus // .status // empty')
[ "$FSTATUS" = "ACTIVE" ] || fail "expected ACTIVE after verify-dns, got '$FSTATUS'"
ok "all required DNS records verified — agent is ACTIVE"
