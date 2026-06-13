#!/usr/bin/env bash
#
# One-command vLEI verify-control demo — fully standalone.
#
# Bootstraps everything the flow needs and chains it end-to-end with no manual steps:
#   0. ensure ans-ra      — start ans-ra (+ ans-tl) in the real vlei
#                           "verifier" mode if it isn't already running that
#                           way. The demo presents real CESR, which only the
#                           verifier backend accepts; the plain start.sh
#                           default is "noop" (base64url JSON), so a noop RA is
#                           restarted into verifier mode here.
#   0b. ensure an agent   — register one (register.sh --v2) if none exists, to
#                           link the verified lei identity to.
#   1. up.sh              — bring up the stack (witnesses, vlei-server, KERIA,
#                           vlei-verifier, signify Deno runner) on one network.
#   2. build-chain.sh     — run build-chain.ts headless: build the synthetic
#                           vLEI trust chain, issue the ECR to the holder AID,
#                           present it, register the local GLEIF root of trust,
#                           and export ecr-presentation.json + holder-state.json.
#   3. verify-control-demo.sh (AUTO_SIGN=1) — RA-mediated register +
#                           verify-control on /v2/ans/identities, signing the
#                           served signingInput in-container with the holder
#                           (role) AID, then linking the verified lei identity
#                           to the agent. No manual paste.
#
# Usage:
#   scripts/demo/vlei/run-vlei.sh [--down]
#
# Flags:
#   --down     tear the stack down after a successful run — both the docker
#              ecosystem (down.sh) and the ans-ra/ans-tl/ans-dns daemons
#              (stop.sh) this run may have started.
#
# Env overrides:
#   AGENT_ID           reuse this already-registered agent instead of
#                      registering a fresh one (default: the id saved by a
#                      prior register.sh --v2, else a freshly registered one).
#   COMPOSE            docker compose command (default: "docker compose")
#   RA_URL             ans-ra base URL (default: http://localhost:18080)
#   VLEI_VERIFIER_URL  the vlei-verifier the RA points at in verifier mode
#                      (default: http://localhost:7676 — the port up.sh exposes)

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
VLEI_VERIFIER_URL="${VLEI_VERIFIER_URL:-http://localhost:7676}"

header "vLEI verify-control demo — full run"

# 0. Ensure ans-ra is up AND wired to the real vlei-verifier. This demo
#    presents real CESR, which only the "verifier" backend accepts; the plain
#    start.sh default is "noop" (base64url JSON). Three cases:
#      * RA not running       → fresh start in verifier mode.
#      * RA running, noop mode → restart in verifier mode, preserving data
#        (start.sh --keep keeps data/demo: agent id, SQLite store, signer keys;
#        the TL still trusts the unchanged RA pubkey).
#      * RA running, verifier  → leave it.
#    The running RA's mode is read from its startup log; start.sh truncates
#    ra.log per launch, so the grep reflects the live process.
if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  note "ans-ra not running — starting ans-ra + ans-tl in vlei verifier mode"
  ANS_VLEI_TYPE=verifier ANS_VLEI_BASE_URL="$VLEI_VERIFIER_URL" \
    "$SCRIPT_DIR/../start.sh"
elif grep -Eq 'vleiVerifier=("?)verifier' "$DATA/ra.log" 2>/dev/null; then
  ok "ans-ra already in vlei verifier mode"
else
  note "ans-ra is in noop vlei mode — restarting in verifier mode (data preserved via --keep)"
  "$SCRIPT_DIR/../stop.sh"
  ANS_VLEI_TYPE=verifier ANS_VLEI_BASE_URL="$VLEI_VERIFIER_URL" \
    "$SCRIPT_DIR/../start.sh" --keep
fi
ok "ans-ra ready at $RA_URL in vlei verifier mode"

# 0b. Ensure an agent is registered to link the verified lei identity to.
#     Reuse AGENT_ID (env) or the id a prior register.sh --v2 saved; otherwise
#     register a fresh one now (the RA is up, so registration can run).
if [ -z "${AGENT_ID:-}" ] && [ -f "$DATA/last-agent-id" ]; then
  AGENT_ID=$(cat "$DATA/last-agent-id")
fi
if [ -z "${AGENT_ID:-}" ]; then
  note "no agent registered — registering one (register.sh --v2)"
  "$SCRIPT_DIR/../register.sh" --v2 >&2
  AGENT_ID=$(cat "$DATA/last-agent-id")
fi
[ -n "${AGENT_ID:-}" ] || fail "agent registration did not produce an id"
note "agent: $AGENT_ID   RA: $RA_URL"

# 1. stack up
"$SCRIPT_DIR/up.sh"

# 2. build the chain (headless): build chain, present, register root, export artifacts
"$SCRIPT_DIR/build-chain.sh"

# 3. RA-mediated register + verify-control, auto-signing the signingInput
#    in-container. DATA points the verify script at build-chain.ts's exported
#    artifacts so it finds both ecr-presentation.json and holder-state.json there.
AGENT_ID="$AGENT_ID" DATA="$OUT_DIR" AUTO_SIGN=1 "$SCRIPT_DIR/verify-control-demo.sh"

if [ "$TEARDOWN" = "1" ]; then
  "$SCRIPT_DIR/down.sh"
  # Also stop the ans-ra/ans-tl/ans-dns daemons this run may have started in
  # step 0 — down.sh only tears down the docker stack, not the local daemons.
  "$SCRIPT_DIR/../stop.sh"
fi

header "All done"
note "vLEI control proven end-to-end with no manual steps."
