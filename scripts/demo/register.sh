#!/usr/bin/env bash
# Register a fresh agent and drive it to ACTIVE on the chosen lane.
# Focused building block for end-to-end testing — stops at ACTIVE, no
# audit/receipt flow (see run-lifecycle{,-v1}.sh for the full demo).
#
# Writes the new agentId to:
#   data/demo/last-agent-id-v1    (for --v1)
#   data/demo/last-agent-id       (for --v2)
# so downstream scripts (renewal.sh, revoke.sh) can pick it up
# without arguments.
#
# Usage:
#   scripts/demo/register.sh --v1                            # random host, V1 lane
#   scripts/demo/register.sh --v2                            # random host, V2 lane
#   scripts/demo/register.sh --v1 myagent.example.com        # specific host
#   scripts/demo/register.sh --v2 myagent.example.com 2.1.0  # specific host + version
#   scripts/demo/register.sh --v1 --register-only            # stop after POST /register (don't activate)
#
# Env:
#   ANS_DISCOVERY_PROFILES  comma-separated discoveryProfiles for the
#                           V2 register request, e.g. "ANS_TXT" or
#                           "ANS_DNSAID,ANS_TXT". Omitted → the server
#                           default (ANS_DNSAID: SVCB rows per RFC
#                           9460). V1 is always pinned to ANS_TXT.
#
# Exits 0 on success; agentId is echoed on the FINAL line of stdout so
# callers can `AGENT_ID=$(register.sh --v1)` if they want.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# ----- arg parsing -----
LANE=""
REGISTER_ONLY=0
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --v1) LANE="v1"; shift ;;
    --v2) LANE="v2"; shift ;;
    --register-only) REGISTER_ONLY=1; shift ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//' >&2
      exit 0
      ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
if [ -z "$LANE" ]; then
  fail "must specify --v1 or --v2"
fi

ARG_HOST="${ARGS[0]:-}"
ARG_VERSION="${ARGS[1]:-}"
AGENT_VERSION="${AGENT_VERSION:-${ARG_VERSION:-1.0.0}}"
if [ -n "${AGENT_HOST:-}" ]; then
  :  # env wins
elif [ -n "$ARG_HOST" ]; then
  AGENT_HOST="$ARG_HOST"
else
  AGENT_HOST="${LANE}demo-$(openssl rand -hex 4).example.com"
fi
ANS_NAME="ans://v${AGENT_VERSION}.${AGENT_HOST}"

header "Register on lane $LANE"
printf "  ansName   %s\n" "$ANS_NAME" >&2
printf "  host      %s\n" "$AGENT_HOST" >&2
printf "  version   %s\n" "$AGENT_VERSION" >&2

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# ----- Generate identity CSR (URI SAN = ANS name) -----
CSR_DIR="$DATA/csr"
rm -rf "$CSR_DIR"
mkdir -p "$CSR_DIR"
cat >"$CSR_DIR/identity.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $ANS_NAME
[v3_req]
subjectAltName = URI:$ANS_NAME
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$CSR_DIR/identity.key" 2>/dev/null
openssl req -new -key "$CSR_DIR/identity.key" \
  -config "$CSR_DIR/identity.cnf" \
  -out "$CSR_DIR/identity.csr" 2>/dev/null
IDENTITY_CSR_PEM=$(cat "$CSR_DIR/identity.csr")

# ----- Generate server CSR (DNS SAN = agent FQDN) -----
#
# The RA opens a certificate order via its configured
# ServerCertificateIssuer port and finalizes it at verify-acme. The
# demo wires the in-process self-signed CA by default, or Let's
# Encrypt with start.sh --with-acme.
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

# ----- POST register (lane-specific URL + last-agent-id filename) -----
if [ "$LANE" = "v1" ]; then
  REGISTER_PATH="/v1/agents/register"
  AGENT_BASE="/v1/agents"
  LAST_AGENT_FILE="$DATA/last-agent-id-v1"
else
  REGISTER_PATH="/v2/ans/agents"
  AGENT_BASE="/v2/ans/agents"
  LAST_AGENT_FILE="$DATA/last-agent-id"
fi

# Host-derived display text. Searchability does not require this — the
# Finder indexes the publisher host itself, so "translator" finds
# translator.example.com whatever the display name says. This is
# presentation: search results and lifecycle output should show a name
# recognizably tied to what the user registered, not a fixed
# "demo-agent" string. Truncated to stay inside the RA's field limits
# (displayName 64, description 150) for long-but-legal DNS labels.
HOST_LABEL="${AGENT_HOST%%.*}"
HOST_LABEL="${HOST_LABEL:0:40}"
DISPLAY_NAME="$HOST_LABEL $LANE demo agent"
DESCRIPTION="Demo agent for $AGENT_HOST, registered by scripts/demo/register.sh on the $LANE lane."
DESCRIPTION="${DESCRIPTION:0:150}"

header "POST $REGISTER_PATH"
# metaDataUrl sits at /.well-known/ so the ANS_DNSAID profile's SVCB
# rows carry the capability locator (key65400) and well-known suffix
# (key65409) SvcParams — the representative shape for real-DNS SVCB
# testing. discoveryProfiles is only attached when the caller set
# ANS_DISCOVERY_PROFILES (V2 lane; V1 ignores the field server-side).
REG_REQ=$(jq -n \
  --arg host "$AGENT_HOST" \
  --arg version "$AGENT_VERSION" \
  --arg idCsr "$IDENTITY_CSR_PEM" \
  --arg srvCsr "$SERVER_CSR_PEM" \
  --arg display "$DISPLAY_NAME" \
  --arg desc "$DESCRIPTION" \
  --arg profiles "${ANS_DISCOVERY_PROFILES:-}" '
  {
    agentDisplayName: $display,
    agentDescription: $desc,
    version:          $version,
    agentHost:        $host,
    endpoints: [{
      agentUrl:    ("https://" + $host + "/mcp"),
      metaDataUrl: ("https://" + $host + "/.well-known/mcp/server-card.json"),
      protocol:    "MCP",
      transports:  ["SSE"]
    }],
    identityCsrPEM: $idCsr,
    serverCsrPEM:   $srvCsr
  }
  | if $profiles != "" then . + {discoveryProfiles: ($profiles | split(","))} else . end')
REG_RESP=$(curl_json POST "$REGISTER_PATH" "$REG_REQ")
AGENT_ID=$(printf '%s' "$REG_RESP" | jq -r '.agentId // empty')
if [ -z "$AGENT_ID" ]; then
  fail "no agentId in register response"
fi
echo "$AGENT_ID" >"$LAST_AGENT_FILE"
ok "agentId=$AGENT_ID (saved to $LAST_AGENT_FILE)"

if [ "$REGISTER_ONLY" = "1" ]; then
  header "--register-only: stopping before activation"
  # Surface the domain-control challenge artifacts the owner must
  # publish before verify-acme. With the self-signed issuer the noop
  # DNS verifier accepts anything; with --with-acme these are the
  # provider's real challenges and one of them must actually be live
  # (scripts/demo/acme-verify.sh drives the rest of that flow).
  TXT_NAME=$(printf '%s' "$REG_RESP" | jq -r '.challenges[]? | select(.type=="DNS_01") | .dnsRecord.name // empty')
  TXT_VALUE=$(printf '%s' "$REG_RESP" | jq -r '.challenges[]? | select(.type=="DNS_01") | .dnsRecord.value // empty')
  if [ -n "$TXT_NAME" ]; then
    note "to validate domain control, publish: TXT $TXT_NAME = $TXT_VALUE"
  fi
  note "record helper: scripts/demo/dns-records.sh prints every record to publish at each stage (and --verify drives verify-dns)"
  printf "%s\n" "$AGENT_ID"
  exit 0
fi

# ----- Drive to ACTIVE (verify-acme → verify-dns) -----
#
# V1 skips the intermediate DOMAIN_VALIDATION TL emit but still
# advances the state machine; V2 emits DOMAIN_VALIDATION at this
# step. The RA's response shape is identical on both lanes.
header "POST $AGENT_BASE/$AGENT_ID/verify-acme  (→ PENDING_DNS)"
curl_json POST "$AGENT_BASE/$AGENT_ID/verify-acme" >/dev/null

header "POST $AGENT_BASE/$AGENT_ID/verify-dns  (→ ACTIVE)"
note "noop DNS verifier accepts any operator DNS state; production plugs in a real verifier"
curl_json POST "$AGENT_BASE/$AGENT_ID/verify-dns" >/dev/null

# ----- Confirm ACTIVE -----
header "GET $AGENT_BASE/$AGENT_ID  (expect agentStatus=ACTIVE)"
DETAIL=$(curl_json GET "$AGENT_BASE/$AGENT_ID")
status=$(printf '%s' "$DETAIL" | jq -r '.agentStatus // .status // empty')
if [ "$status" != "ACTIVE" ]; then
  fail "agent did not reach ACTIVE; got '$status'"
fi
ok "agent is ACTIVE on lane $LANE"

# Echo agentId on the last line so shell callers can capture it:
#   AGENT=$(scripts/demo/register.sh --v1)
printf "%s\n" "$AGENT_ID"
