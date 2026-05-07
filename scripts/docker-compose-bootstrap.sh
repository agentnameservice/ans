#!/usr/bin/env bash
# Bootstrap the TL's producerKeys trust list with the RA's signer
# public key after `docker compose up`. The TL ships with
# `producerKeys: []` (see config/tl-docker.yaml) and rejects events
# until at least one producer is trusted; this script registers the
# RA's signer via the TL admin API.
#
# Idempotent — safe to re-run. A 409 Conflict on the second run is
# treated as success.
#
# Usage:
#   docker compose up --build -d
#   ./scripts/docker-compose-bootstrap.sh    # or: make docker-compose-bootstrap

set -euo pipefail

RA_CONTAINER="${RA_CONTAINER:-ans-ra}"
TL_URL="${TL_URL:-http://localhost:18081}"
RA_URL="${RA_URL:-http://localhost:18080}"
TL_ADMIN_KEY="${TL_ADMIN_KEY:-tl-internal-key}"
RA_KEY_ID="${RA_KEY_ID:-ans-ra-signer}"
RA_ID="${RA_ID:-ans-ra-local}"

# Color helpers — match the demo scripts' style without sourcing
# common.sh (which makes assumptions about $ROOT layout).
if [ -t 2 ]; then
  C_GREEN=$(printf '\033[32m'); C_RED=$(printf '\033[31m')
  C_DIM=$(printf '\033[2m'); C_RESET=$(printf '\033[0m')
else
  C_GREEN=""; C_RED=""; C_DIM=""; C_RESET=""
fi

note()  { printf "${C_DIM}%s${C_RESET}\n" "$1" >&2; }
ok()    { printf "${C_GREEN}✔${C_RESET} %s\n" "$1" >&2; }
fail()  { printf "${C_RED}✘${C_RESET} %s\n" "$1" >&2; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }
require_cmd docker
require_cmd curl
require_cmd jq

# 1. Wait for both containers to be ready. The healthchecks in
#    docker-compose.yaml mean `docker compose up -d` returns before
#    the services accept traffic; we poll /v2/admin/ready directly.
wait_ready() {
  local url="$1" timeout="${2:-30}" i=0
  while [ "$i" -lt "$timeout" ]; do
    if curl -sSf "$url" >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  fail "timed out waiting for $url (${timeout}s)"
}

note "waiting for RA at $RA_URL/v2/admin/ready ..."
wait_ready "$RA_URL/v2/admin/ready"
note "waiting for TL at $TL_URL/v2/admin/ready ..."
wait_ready "$TL_URL/v2/admin/ready"

# 2. Pull the RA signer's PEM out of the running RA container.
#    The path matches keys.file.path in config/ra-docker.yaml.
note "reading RA signer pubkey from container '$RA_CONTAINER' ..."
PEM=$(docker exec "$RA_CONTAINER" cat "/var/lib/ans-ra/keys/${RA_KEY_ID}.pub") \
  || fail "could not read pubkey from $RA_CONTAINER (is the container running?)"
[ -n "$PEM" ] || fail "pubkey at /var/lib/ans-ra/keys/${RA_KEY_ID}.pub is empty"

# 3. POST to /internal/v1/producer-keys. JSON shape matches the
#    reference TL swagger §1371 (snake_case fields).
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
# 10-year expiry. BSD `date -v` (macOS) and GNU `date -d` differ;
# try BSD first and fall back to GNU.
EXPIRES=$(date -u -v+10y +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
       || date -u -d "+10 years" +"%Y-%m-%dT%H:%M:%SZ")

# jq -Rs handles the multi-line PEM → JSON-escaped string conversion.
PEM_JSON=$(printf '%s' "$PEM" | jq -Rs .)

BODY=$(cat <<EOF
{
  "key_id": "$RA_KEY_ID",
  "public_key_pem": $PEM_JSON,
  "algorithm": "ES256",
  "ra_id": "$RA_ID",
  "valid_from": "$NOW",
  "expires_at": "$EXPIRES"
}
EOF
)

note "POST $TL_URL/internal/v1/producer-keys (key_id=$RA_KEY_ID, ra_id=$RA_ID)"
RESP_FILE=$(mktemp)
trap 'rm -f "$RESP_FILE"' EXIT

STATUS=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' \
  -X POST "$TL_URL/internal/v1/producer-keys" \
  -H "Authorization: Bearer $TL_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data "$BODY")

case "$STATUS" in
  200|201)
    ok "TL now trusts RA signer (key_id=$RA_KEY_ID, ra_id=$RA_ID)"
    ;;
  409)
    ok "TL already trusts RA signer — bootstrap is idempotent"
    ;;
  *)
    cat "$RESP_FILE" >&2
    fail "bootstrap failed: HTTP $STATUS"
    ;;
esac
