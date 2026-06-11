#!/usr/bin/env bash
#
# One-command vLEI verify-control demo.
#
# Chains the whole self-contained flow:
#   1. up.sh                — bring up the stack (witnesses, vlei-server, KERIA,
#                             vlei-verifier, signify Deno runner) on one network.
#   2. build-chain.sh       — run build-chain.ts headless: build the synthetic
#                             vLEI trust chain, issue the ECR to the holder AID,
#                             present it, register the local GLEIF root of trust,
#                             and export ecr-presentation.json + tier1-outputs.json.
#   3. verify-control-demo.sh (AUTO_SIGN=1) — RA-mediated register +
#                             verify-control on /v2/ans/identities, signing the
#                             served signingInput in-container with the holder
#                             (role) AID, then linking the verified lei identity
#                             to the agent. No manual paste.
#
# The RA is NOT started here — it owns its own lifecycle (config + agent
# registration). This script requires it already running with an agent
# registered; it checks both up front and points you at the right script if not.
#
# Usage:
#   AGENT_ID=$(scripts/demo/register.sh --v2)
#   scripts/demo/vlei/run-vlei.sh [--down]
#
# Required env:
#   AGENT_ID   a registered ans agent id (e.g. from scripts/demo/register.sh
#
# Flags:
#   --down     tear the stack down (down.sh) after a successful run.
#
# Env overrides:
#   COMPOSE    docker compose command (default: "docker compose")
#   RA_URL     ans-ra base URL (default: http://localhost:18080)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
. "$SCRIPT_DIR/../common.sh"

TEARDOWN=0
for arg in "$@"; do
  case "$arg" in
    --down) TEARDOWN=1 ;;
    *) fail "unknown argument: $arg (supported: --down)" ;;
  esac
done

OUT_DIR="$SCRIPT_DIR/signify/out"

# AGENT_ID: from env
[ -n "${AGENT_ID:-}" ] || fail "set AGENT_ID — register an agent first (scripts/demo/register.sh)"

header "vLEI verify-control demo — full run"
note "agent: $AGENT_ID   RA: $RA_URL"

# Fail fast if the RA isn't reachable, before standing the stack up.
if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first (and ensure the vlei: block in config/ra-local.yaml is enabled)"
fi
ok "ans-ra ready at $RA_URL"

# 1. stack up
"$SCRIPT_DIR/up.sh"

# 2. build the chain (headless): build chain, present, register root, export artifacts
"$SCRIPT_DIR/build-chain.sh"

# 3. RA-mediated register + verify-control, auto-signing the signingInput
#    in-container. DATA points the verify script at build-chain.ts's exported
#    artifacts so it finds both ecr-presentation.json and tier1-outputs.json there.
AGENT_ID="$AGENT_ID" DATA="$OUT_DIR" AUTO_SIGN=1 "$SCRIPT_DIR/verify-control-demo.sh"

if [ "$TEARDOWN" = "1" ]; then
  "$SCRIPT_DIR/down.sh"
fi

header "All done"
note "vLEI control proven end-to-end with no manual steps."
