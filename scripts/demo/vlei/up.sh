#!/usr/bin/env bash
#
# Bring up the vLEI ecosystem (witnesses + schema server + KERIA +
# vlei-verifier + signify Deno runner) and wait for the verifier to come green
# and the signify container to finish pre-caching its deps. The whole stack —
# including the SignifyTS runner — lives in this one compose file; no second
# repo is required.
#
# Usage:
#   scripts/demo/vlei/up.sh
#
# Env overrides:
#   COMPOSE       docker compose command (default: "docker compose")
#   VERIFIER_URL  verifier base URL to health-check (default: http://localhost:7676)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DATA="${DATA:-$(cd "$SCRIPT_DIR/../../.." && pwd)/data/demo/vlei}"
# shellcheck source=../common.sh
. "$SCRIPT_DIR/../common.sh"

COMPOSE="${COMPOSE:-docker compose}"
VERIFIER_URL="${VERIFIER_URL:-http://localhost:7676}"

require_cmd docker
require_cmd curl

header "vLEI ecosystem — up"
note "compose file: $SCRIPT_DIR/docker-compose.yml"

# shellcheck disable=SC2086  # COMPOSE may be a multi-word command
$COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" up -d --build

note "waiting for vlei-verifier /health at $VERIFIER_URL …"
for _ in $(seq 1 60); do
  if curl -fsS "$VERIFIER_URL/health" >/dev/null 2>&1; then
    ok "vlei-verifier healthy at $VERIFIER_URL"
    break
  fi
  sleep 2
done

if ! curl -fsS "$VERIFIER_URL/health" >/dev/null 2>&1; then
  fail "vlei-verifier did not become healthy — check '$COMPOSE -f $SCRIPT_DIR/docker-compose.yml logs'"
fi

# The signify container pre-caches its npm deps at start and touches /tmp/ready
# when done; probe that marker so the first `deno run` exec is fast. exec needs
# the container running (it is — it idles on tail), and returns non-zero until
# the marker exists.
note "waiting for the signify container to finish caching deps …"
signify_ready() {
  # shellcheck disable=SC2086  # COMPOSE may be a multi-word command
  $COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" exec -T signify test -f /tmp/ready >/dev/null 2>&1
}
for _ in $(seq 1 60); do
  if signify_ready; then
    ok "signify container ready"
    break
  fi
  sleep 2
done

if ! signify_ready; then
  fail "signify container did not become ready — check '$COMPOSE -f $SCRIPT_DIR/docker-compose.yml logs signify'"
fi

header "Next steps"
note "Run the whole flow with one command:  $SCRIPT_DIR/run-vlei.sh"
note "  (requires ans-ra running with vlei.base-url=$VERIFIER_URL)"
note "Or step by step:"
note "  1. $SCRIPT_DIR/build-chain.sh         — build the chain + present + export (headless)"
note "  2. $SCRIPT_DIR/verify-control-demo.sh — RA-mediated present + verify-control"
