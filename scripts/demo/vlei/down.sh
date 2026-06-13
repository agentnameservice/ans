#!/usr/bin/env bash
#
# Tear down the vLEI ecosystem.
#
# Usage:
#   scripts/demo/vlei/down.sh          # stop + remove containers
#   KEEP_VOLUMES=1 scripts/demo/vlei/down.sh   # keep named volumes
#
# Env overrides:
#   COMPOSE   docker compose command (default: "docker compose")

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DATA="${DATA:-$(cd "$SCRIPT_DIR/../../.." && pwd)/data/demo/vlei}"
# shellcheck source=../common.sh
. "$SCRIPT_DIR/../common.sh"

COMPOSE="${COMPOSE:-docker compose}"

require_cmd docker

header "vLEI ecosystem — down"

DOWN_ARGS=(down --remove-orphans)
if [ "${KEEP_VOLUMES:-0}" != "1" ]; then
  DOWN_ARGS+=(--volumes)
fi

# shellcheck disable=SC2086  # COMPOSE may be a multi-word command
$COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" "${DOWN_ARGS[@]}"
ok "stack stopped"
