#!/usr/bin/env bash
#
# Build the vLEI trust chain headless, inside the signify (Deno) container.
#
# Runs build-chain.ts: the trust-chain build, ECR issuance, IPEX present, local
# root-of-trust registration, and the holder-state export. No notebook/kernel —
# it is plain SignifyTS run by Deno.
#
# On success build-chain.ts has written, into the bind-mounted out dir
# (host: scripts/demo/vlei/signify/out/):
#   - ecr-presentation.json  {cesr, lei, aid}     consumed by verify-control-demo.sh
#   - holder-state.json      {roleBran, ...}      consumed by the nonce signer
#
# Usage:
#   scripts/demo/vlei/build-chain.sh
#
# Env overrides:
#   COMPOSE   docker compose command (default: "docker compose")
#   SCRIPT    build script path inside the container (default: scripts_ts/build-chain.ts)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../common.sh
. "$SCRIPT_DIR/../common.sh"

COMPOSE="${COMPOSE:-docker compose}"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
SCRIPT="${SCRIPT:-scripts_ts/build-chain.ts}"
OUT_DIR="$SCRIPT_DIR/signify/out"

require_cmd docker

header "Building the vLEI trust chain headless — $SCRIPT"

# Run the build script in the signify container. -A grants the file/net
# permissions the SignifyTS flow needs; the container is on the stack network so
# keria / vlei-server / witness-demo / vlei-verifier resolve by service name.
# shellcheck disable=SC2086  # COMPOSE may be a multi-word command
$COMPOSE -f "$COMPOSE_FILE" exec -T signify deno run -A "$SCRIPT"

ok "build script executed"

# Assert the exported artifacts landed on the host via the bind mount.
for f in ecr-presentation.json holder-state.json; do
  if [ ! -s "$OUT_DIR/$f" ]; then
    fail "expected $OUT_DIR/$f to exist and be non-empty after the run — check the output above"
  fi
  ok "wrote $f"
done

header "Chain build complete"
note "ecr-presentation.json + holder-state.json are in $OUT_DIR"
note "next: $SCRIPT_DIR/verify-control-demo.sh  (or run-vlei.sh for the full flow)"
