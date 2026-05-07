#!/usr/bin/env bash
# Shut down the demo daemons. By default, preserves data/demo/ so
# you can inspect logs + sqlite; pass --clean to wipe it.
#
# Usage:
#   scripts/demo/stop.sh            # kill daemons, keep data
#   scripts/demo/stop.sh --clean    # kill daemons, rm -rf data/demo

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

CLEAN=0
case "${1:-}" in
  --clean) CLEAN=1 ;;
  "") ;;
  *) fail "unknown arg: $1 (try --clean)" ;;
esac

# stop_one NAME PIDFILE
stop_one() {
  local name="$1" pidfile="$2"
  if [ ! -f "$pidfile" ]; then
    note "$name: no pidfile at $pidfile"
    return 0
  fi
  local pid
  pid=$(cat "$pidfile")
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    note "$name: pid $pid not running"
    rm -f "$pidfile"
    return 0
  fi
  # Polite SIGTERM, wait up to 5s, then SIGKILL.
  kill "$pid" 2>/dev/null || true
  local i=0
  while [ $i -lt 5 ] && kill -0 "$pid" 2>/dev/null; do
    sleep 1
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    warn "$name pid $pid did not exit on SIGTERM; sending SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile"
  ok "$name stopped (pid $pid)"
}

header "Stop daemons"
stop_one ans-ra "$DATA/ra.pid"
stop_one ans-tl "$DATA/tl.pid"
stop_one ans-dns "$DATA/ans-dns.pid"

if [ "$CLEAN" -eq 1 ]; then
  header "Clean data"
  rm -rf "$DATA"
  ok "removed $DATA"
else
  note "data preserved at $DATA (pass --clean to wipe)"
fi
