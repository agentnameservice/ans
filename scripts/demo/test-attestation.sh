#!/usr/bin/env bash
# Integration test for GET /v2/ans/agents/{agentId}/attestation.
#
# Registers a fresh agent on the V2 lane, polls for the registration
# event to land in the TL (so the receipt is available), fetches the
# bundled attestation, and runs `ans-verify attest` to verify the
# outer signature (RA producer key) AND the embedded SCITT receipt
# (TL root key) AND the leaf-hash cross-check.
#
# Prerequisites: scripts/demo/start.sh has been run.
#
# Usage:
#   scripts/demo/test-attestation.sh                  # auto-pick host
#   scripts/demo/test-attestation.sh my.example.com   # specific host

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOST="${1:-attest-it-$(openssl rand -hex 4).example.com}"

# ----- preflight -----
header "Preflight"
if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra is not reachable at $RA_URL — run scripts/demo/start.sh first"
fi
if [ ! -x "$ROOT/bin/ans-verify" ]; then
  fail "ans-verify not found at $ROOT/bin/ans-verify — run scripts/demo/start.sh to build"
fi
RA_PUBKEY="$ROOT/data/demo/ra/keys/ans-ra-signer.pub"
if [ ! -f "$RA_PUBKEY" ]; then
  fail "RA producer pubkey not found at $RA_PUBKEY — has ans-ra started successfully?"
fi
ok "RA + verifier binary + producer pubkey present"

# ----- register -----
header "Register agent on V2 lane"
AGENT_ID=$("$SCRIPT_DIR/register.sh" --v2 "$HOST" 2>&1 | tail -1)
if ! [[ "$AGENT_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  fail "registration did not return a UUID: $AGENT_ID"
fi
ok "agent registered: $AGENT_ID"

# ----- wait for TL receipt to be available -----
header "Wait for TL receipt"
deadline=$(($(date +%s) + 30))
while [ "$(date +%s)" -lt "$deadline" ]; do
  status=$(curl -sS -o /dev/null -w "%{http_code}" \
    "$TL_URL/v1/agents/$AGENT_ID/receipt") || true
  if [ "$status" = "200" ]; then
    ok "receipt available (HTTP 200)"
    break
  fi
  sleep 1
done
if [ "$status" != "200" ]; then
  fail "TL receipt did not become available within 30s (last status: $status)"
fi

# ----- fetch attestation + inspect HTTP shape -----
header "Fetch attestation"
ATTEST_FILE=$(mktemp -t ans-attest.XXXXXX)
trap 'rm -f "$ATTEST_FILE"' EXIT
http_summary=$(curl -sS -o "$ATTEST_FILE" \
  -w "HTTP=%{http_code} CT=%{content_type} CC=%header{cache-control} LEN=%{size_download}" \
  "$RA_URL/v2/ans/agents/$AGENT_ID/attestation")
echo "  $http_summary"
case "$http_summary" in
  *"HTTP=200"*"CT=application/cose"*"CC=public, max-age=3600"*)
    ok "HTTP shape matches spec (200, application/cose, max-age=3600)"
    ;;
  *) fail "HTTP shape mismatch: $http_summary" ;;
esac
# Sanity: CBOR tag-18 marker is the first byte.
first_byte=$(xxd -p -l 1 "$ATTEST_FILE")
if [ "$first_byte" != "d2" ]; then
  fail "first byte $first_byte, want d2 (CBOR tag 18)"
fi
ok "CBOR tag 18 marker present"

# ----- verify offline with ans-verify -----
header "Verify attestation with ans-verify"
"$ROOT/bin/ans-verify" attest \
  -ra-url "$RA_URL" \
  -tl-url "$TL_URL" \
  -ra-pubkey "$RA_PUBKEY" \
  "$AGENT_ID"

ok "attestation verified end-to-end"
