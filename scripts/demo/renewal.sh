#!/usr/bin/env bash
# Exercise the server-cert renewal flow end-to-end on the chosen lane.
# Requires an ACTIVE agent (run scripts/demo/register.sh first).
#
# Flow:
#   1. POST   .../certificates/server/renewal         (BYOC submit → 202 PENDING_VALIDATION)
#   2. GET    .../certificates/server/renewal         (status)
#   3. POST   .../certificates/server/renewal/verify-acme  (BYOC → sync 200 COMPLETED)
#   4. GET    .../certificates/server/renewal         (final status)
#
# ans is BYOC-only — we generate a self-signed server cert for the
# agent's FQDN. The RA validator skips chain verification in the
# demo stack (cmd/ans-ra/main.go uses WithSkipChainVerify), so the
# self-signed cert is accepted.
#
# Usage:
#   scripts/demo/renewal.sh --v1                             # BYOC, pick agent from last-agent-id-v1
#   scripts/demo/renewal.sh --v2                             # BYOC, pick agent from last-agent-id
#   scripts/demo/renewal.sh --v1 --csr                       # CSR path (RA's server CA signs)
#   scripts/demo/renewal.sh --v1 --agent <uuid>              # explicit agent
#   scripts/demo/renewal.sh --v1 --skip-verify-acme          # submit only, stop before verify
#   scripts/demo/renewal.sh --v2 --cancel                    # DELETE instead of submit
#
# Env:
#   AGENT_ID   override the agent id (takes precedence over --agent)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# ----- arg parsing -----
LANE=""
AGENT_ARG=""
SKIP_VERIFY=0
CANCEL=0
PATH_MODE="byoc"   # byoc | csr
while [ $# -gt 0 ]; do
  case "$1" in
    --v1) LANE="v1"; shift ;;
    --v2) LANE="v2"; shift ;;
    --agent) AGENT_ARG="$2"; shift 2 ;;
    --skip-verify-acme) SKIP_VERIFY=1; shift ;;
    --cancel) CANCEL=1; shift ;;
    --csr) PATH_MODE="csr"; shift ;;
    --byoc) PATH_MODE="byoc"; shift ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//' >&2
      exit 0
      ;;
    *) fail "unknown arg: $1" ;;
  esac
done
if [ -z "$LANE" ]; then
  fail "must specify --v1 or --v2"
fi

# ----- Resolve lane-specific paths -----
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
if [ -z "$AGENT" ]; then
  if [ ! -f "$LAST_AGENT_FILE" ]; then
    fail "no agent id — pass --agent <uuid> or run register.sh --$LANE first (expected $LAST_AGENT_FILE)"
  fi
  AGENT=$(cat "$LAST_AGENT_FILE")
fi

header "Renewal on lane $LANE"
printf "  agentId   %s\n" "$AGENT" >&2

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# ----- Cancel path (short-circuit) -----
if [ "$CANCEL" = "1" ]; then
  header "DELETE $AGENT_BASE/$AGENT/certificates/server/renewal"
  # Use raw curl so we can inspect the 204 (no body) cleanly.
  status=$(curl -sS -X DELETE \
    -H "Authorization: Bearer $RA_API_KEY" \
    -o /dev/null -w "%{http_code}" \
    "${RA_URL}${AGENT_BASE}/${AGENT}/certificates/server/renewal")
  if [ "$status" = "204" ]; then
    ok "renewal cancelled (204 No Content)"
  elif [ "$status" = "404" ]; then
    warn "no renewal found for agent — 404 is the expected response when there's nothing to cancel"
  elif [ "$status" = "422" ]; then
    # Reference semantics (CertificateRenewalOperationsHandler
    # line 246): DELETE on a COMPLETED renewal returns 422. It's a
    # benign "too late to cancel" not a failure — the renewal
    # already did its job.
    warn "renewal already COMPLETED — 422 is the expected response when there's nothing left to cancel"
  else
    fail "unexpected status $status on DELETE renewal"
  fi
  exit 0
fi

# ----- 0. Look up the agent's FQDN so the self-signed cert matches -----
#
# The server cert validator requires a DNS SAN matching the agent's
# FQDN (derived from ANS name minus the version label). We read the
# agent detail to get the exact string rather than reconstructing it
# locally.
header "GET $AGENT_BASE/$AGENT  (look up agentHost for cert SAN)"
DETAIL=$(curl_json GET "$AGENT_BASE/$AGENT")
AGENT_FQDN=$(printf '%s' "$DETAIL" | jq -r '.agentHost // empty')
if [ -z "$AGENT_FQDN" ]; then
  fail "could not resolve agent FQDN from $AGENT_BASE/$AGENT"
fi
agent_status=$(printf '%s' "$DETAIL" | jq -r '.agentStatus // .status // empty')
if [ "$agent_status" != "ACTIVE" ]; then
  fail "agent must be ACTIVE to renew; current status: $agent_status"
fi
ok "agentFqdn=$AGENT_FQDN"

# ----- 1. Prepare the credential (CSR or BYOC cert) -----
CERT_DIR="$DATA/cert-renewal"
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
cat >"$CERT_DIR/openssl.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $AGENT_FQDN
[v3_req]
subjectAltName = DNS:$AGENT_FQDN
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/key.pem" 2>/dev/null

if [ "$PATH_MODE" = "csr" ]; then
  # CSR path: produce a PEM CSR with DNS SAN matching the agent FQDN.
  # The RA's configured ServerCertificateAuthority signs it.
  openssl req -new -key "$CERT_DIR/key.pem" \
    -config "$CERT_DIR/openssl.cnf" \
    -out "$CERT_DIR/csr.pem" 2>/dev/null
  CRED_PEM=$(cat "$CERT_DIR/csr.pem")
  CRED_FIELD="serverCsrPEM"
  ok "server CSR generated (DNS SAN = $AGENT_FQDN)"
else
  # BYOC path: self-signed cert (validator has chain verify off
  # in the demo; production requires a real CA).
  openssl req -new -x509 -key "$CERT_DIR/key.pem" \
    -config "$CERT_DIR/openssl.cnf" \
    -extensions v3_req \
    -days 90 \
    -out "$CERT_DIR/cert.pem" 2>/dev/null
  CRED_PEM=$(cat "$CERT_DIR/cert.pem")
  CRED_FIELD="serverCertificatePEM"
  ok "self-signed server cert generated (90-day validity)"
fi

# ----- 1b. Clean up any stale PENDING renewal -----
#
# A previous run may have left a PENDING_VALIDATION renewal behind
# (e.g. if the script was killed before verify-acme). The service
# refuses to submit a new renewal while one is pending (409
# PENDING_RENEWAL_EXISTS), so we DELETE any existing one first to
# keep the script re-runnable.
stale_status=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $RA_API_KEY" \
  -X GET "${RA_URL}${AGENT_BASE}/${AGENT}/certificates/server/renewal")
if [ "$stale_status" = "200" ]; then
  warn "pending renewal exists from a previous run — cancelling before retry"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $RA_API_KEY" \
    -o /dev/null \
    "${RA_URL}${AGENT_BASE}/${AGENT}/certificates/server/renewal"
fi

# ----- 2. POST renewal -----
header "POST $AGENT_BASE/$AGENT/certificates/server/renewal ($PATH_MODE path)"
RENEWAL_REQ=$(jq -n --arg field "$CRED_FIELD" --arg pem "$CRED_PEM" '{($field): $pem}')
RENEWAL_RESP=$(curl_json POST "$AGENT_BASE/$AGENT/certificates/server/renewal" "$RENEWAL_REQ")
renewal_status=$(printf '%s' "$RENEWAL_RESP" | jq -r '.status // empty')
renewal_type=$(printf '%s' "$RENEWAL_RESP" | jq -r '.renewalType // empty')
# Renewal-type enum (domain.RenewalType constants in internal/domain/status.go):
#   - serverCertificatePEM → SERVER_BYOC
#   - serverCsrPEM         → SERVER_CSR
if [ "$PATH_MODE" = "csr" ]; then
  expected_type="SERVER_CSR"
else
  expected_type="SERVER_BYOC"
fi
if [ "$renewal_type" != "$expected_type" ]; then
  fail "renewalType: got '$renewal_type', want $expected_type"
fi
if [ "$renewal_status" != "PENDING_VALIDATION" ]; then
  fail "status: got '$renewal_status', want PENDING_VALIDATION"
fi
ok "renewal accepted (renewalType=$expected_type, status=PENDING_VALIDATION)"

# Verify the next-step endpoint points at the correct lane.
next_endpoint=$(printf '%s' "$RENEWAL_RESP" | jq -r '.nextStep.endpoint // empty')
if [[ "$LANE" = "v1" && "$next_endpoint" != /v1/* ]]; then
  fail "V1 nextStep.endpoint must target /v1/, got '$next_endpoint'"
fi
if [[ "$LANE" = "v2" && "$next_endpoint" != /v2/* ]]; then
  fail "V2 nextStep.endpoint must target /v2/, got '$next_endpoint'"
fi
ok "nextStep.endpoint targets the matching lane: $next_endpoint"

# ----- 3. GET status (PENDING_VALIDATION) -----
header "GET $AGENT_BASE/$AGENT/certificates/server/renewal  (expect PENDING_VALIDATION)"
STATUS_RESP=$(curl_json GET "$AGENT_BASE/$AGENT/certificates/server/renewal")
status=$(printf '%s' "$STATUS_RESP" | jq -r '.status // empty')
if [ "$status" != "PENDING_VALIDATION" ]; then
  fail "status: got '$status', want PENDING_VALIDATION"
fi

if [ "$SKIP_VERIFY" = "1" ]; then
  header "--skip-verify-acme: stopping before ACME verification"
  exit 0
fi

# ----- 4. POST verify-acme (BYOC → sync COMPLETED) -----
header "POST $AGENT_BASE/$AGENT/certificates/server/renewal/verify-acme"
# BYOC verification completes synchronously → 200 + COMPLETED.
# CSR-based renewals (not supported on this lane) would be 202 +
# ISSUING_CERTIFICATE.
VERIFY_RESP=$(curl_json POST "$AGENT_BASE/$AGENT/certificates/server/renewal/verify-acme")
final_status=$(printf '%s' "$VERIFY_RESP" | jq -r '.status // empty')
if [ "$final_status" != "COMPLETED" ]; then
  fail "verify-acme status: got '$final_status', want COMPLETED"
fi
ok "renewal COMPLETED synchronously (BYOC)"

# ----- 5. Confirm final state via GET -----
header "GET $AGENT_BASE/$AGENT/certificates/server/renewal  (expect COMPLETED)"
FINAL=$(curl_json GET "$AGENT_BASE/$AGENT/certificates/server/renewal")
final_state=$(printf '%s' "$FINAL" | jq -r '.status // empty')
if [ "$final_state" != "COMPLETED" ]; then
  fail "final status: got '$final_state', want COMPLETED"
fi

header "Renewal complete"
printf "  agentId     %s\n" "$AGENT" >&2
printf "  lane        %s\n" "$LANE" >&2
printf "  path        %s\n" "$PATH_MODE" >&2
printf "  artefact    %s\n" "$CERT_DIR/" >&2
printf "  renewalType %s\n" "$expected_type" >&2
printf "  final       COMPLETED\n" >&2
