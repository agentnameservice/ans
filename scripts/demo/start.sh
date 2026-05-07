#!/usr/bin/env bash
# Build ans-ra + ans-tl and start them both against a demo data dir.
#
# The two binaries need a small bootstrap: the RA auto-generates its
# signer key on first run, and the TL needs that pubkey in its
# `producerKeys[]` trust list before it will accept events. This
# script starts the RA first, waits for readiness (which materializes
# the pubkey file), then composes a demo-tl.yaml with that pubkey
# inlined and starts the TL against it.
#
# Usage:
#   scripts/demo/start.sh            # wipe data/demo, fresh start
#   scripts/demo/start.sh --keep     # reuse existing data/demo
#
# Prerequisites: go, curl, jq, openssl (openssl only needed by
# run-lifecycle.sh, but checked here for early-failure UX).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# ----- args -----
KEEP_DATA=0
WITH_DNS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP_DATA=1; shift ;;
    --with-dns)
      # Start the bundled `ans-dns` authoritative server on
      # 127.0.0.1:15353 and flip the RA to "lookup" mode pointed at
      # it. Lets run-lifecycle.sh drive verify-dns end-to-end
      # without noop-ing.
      WITH_DNS=1
      export ANS_DNS_TYPE=lookup
      export ANS_DNS_SERVER="127.0.0.1:15353"
      shift
      ;;
    -h|--help)
      sed -n '2,17p' "$0"
      exit 0
      ;;
    *) fail "unknown arg: $1" ;;
  esac
done

# ----- preflight -----
header "Preflight"
for cmd in go curl jq openssl; do
  require_cmd "$cmd"
done
ok "all required tools present"

# ----- build -----
header "Build"
cd "$ROOT"
make build >&2
ok "binaries in $ROOT/bin"

# ----- data dir -----
header "Data dir"
mkdir -p "$DATA"
if [ "$KEEP_DATA" -eq 0 ]; then
  # Clean everything except the .log files from a prior run — keep
  # those around in case the user was inspecting them.
  rm -rf \
    "$DATA/ra" "$DATA/tl" \
    "$DATA/demo-ra.yaml" "$DATA/demo-tl.yaml" \
    "$DATA/last-agent-id" "$DATA/csr"
  # pid files (if the daemons were still running, stop.sh handles them;
  # here we just remove the stale files).
  rm -f "$DATA"/*.pid
  ok "cleared $DATA (kept log files)"
else
  note "keeping existing data under $DATA"
fi

# Refuse to start if the ports already have something on them.
for url in "$RA_URL/v2/admin/health" "$TL_URL/v2/admin/health"; do
  if curl -sSf "$url" >/dev/null 2>&1; then
    fail "something is already running at $url (run scripts/demo/stop.sh first)"
  fi
done

# ----- RA config -----
header "Compose RA config"
cat >"$DATA/demo-ra.yaml" <<YAML
server:
  host: "127.0.0.1"
  port: 18080

auth:
  type: static
  static:
    api-key: "$RA_API_KEY"
    # ANS SDKs send 'Authorization: sso-key <apiKey>:<apiSecret>'.
    # Configuring this secret enables that format alongside the
    # simple Bearer format the demo curl scripts use.
    api-secret: "$RA_API_SECRET"

ca:
  type: self
  self:
    org: "ANS Demo CA"
    validity-days: 365
    data-dir: "$DATA/ra/ca"
  # Server CA: optional. When present, enables the serverCsrPEM
  # registration/renewal path where the RA signs TLS server certs
  # with this separate private CA. When absent, only BYOC works.
  # Keep it configured in the demo so both paths are exercised.
  server:
    org: "ANS Demo Server CA"
    validity-days: 365
    data-dir: "$DATA/ra/server-ca"

dns:
  # Flip to "lookup" + set DNS_SERVER to point at ans-dns for
  # end-to-end verify-dns testing:
  #   ANS_DNS_TYPE=lookup ANS_DNS_SERVER=127.0.0.1:15353 scripts/demo/start.sh
  type: ${ANS_DNS_TYPE:-noop}
  server: "${ANS_DNS_SERVER:-}"

keys:
  type: file
  file:
    path: "$DATA/ra/keys"

store:
  type: sqlite
  sqlite:
    path: "$DATA/ra/ans.db"

tl-client:
  base-url: "$TL_URL"
  api-key: "tl-internal-key"
  timeout: 10s

signer:
  keyId: "ans-ra-signer"
  raId: "ans-ra-local"

log:
  level: info
  format: text
YAML
ok "wrote $DATA/demo-ra.yaml"

# ----- start ans-dns (optional, --with-dns) -----
if [ "$WITH_DNS" -eq 1 ]; then
  header "Start ans-dns"
  ANS_DNS_ZONE="$DATA/ans-dns.zone.json"
  # Start fresh: empty zone; the lifecycle script installs records
  # just before verify-dns via `ans-dns install`.
  printf '{"records":{}}\n' >"$ANS_DNS_ZONE"
  "$ROOT/bin/ans-dns" serve --addr 127.0.0.1:15353 --zone "$ANS_DNS_ZONE" --dnssec \
    >"$DATA/ans-dns.log" 2>&1 &
  DNS_PID=$!
  echo "$DNS_PID" >"$DATA/ans-dns.pid"
  # Persist the zone path so run-lifecycle.sh (a separate process)
  # picks it up via common.sh's env-file sourcing.
  echo "ANS_DNS_ZONE=$ANS_DNS_ZONE" >"$DATA/env"
  note "logs → $DATA/ans-dns.log (zone=$ANS_DNS_ZONE, addr=127.0.0.1:15353)"
  sleep 1
  ok "ans-dns ready (pid $DNS_PID)"
fi

# ----- start RA -----
header "Start ans-ra"
"$ROOT/bin/ans-ra" --config "$DATA/demo-ra.yaml" >"$DATA/ra.log" 2>&1 &
RA_PID=$!
echo "$RA_PID" >"$DATA/ra.pid"
note "logs → $DATA/ra.log"
wait_ready "$RA_URL/v2/admin/ready"
ok "ans-ra ready (pid $RA_PID) at $RA_URL"

RA_PUB="$DATA/ra/keys/ans-ra-signer.pub"
if [ ! -f "$RA_PUB" ]; then
  fail "expected RA pubkey at $RA_PUB but it wasn't written"
fi

# ----- compose TL config with the RA pubkey trusted -----
header "Compose TL config (with RA pubkey in producerKeys)"
{
  cat <<YAML
server:
  host: "127.0.0.1"
  port: 18081

auth:
  type: static
  static:
    api-key: "tl-internal-key"
  public-read: true

keys:
  type: file
  file:
    path: "$DATA/tl/keys"

store:
  type: sqlite
  sqlite:
    path: "$DATA/tl/tl.db"

merkle:
  origin: "ans-demo"
  tile-storage:
    type: filesystem
    filesystem:
      path: "$DATA/tl/tiles"
  checkpoint-interval: 2s

attestation:
  keyId: "ans-tl-attestation"

producerKeys:
  - raId: "ans-ra-local"
    keyId: "ans-ra-signer"
    algorithm: "ES256"
    publicKeyPem: |
YAML
  # Inline the PEM indented to match the YAML block scalar — 6 spaces
  # so it sits under `publicKeyPem: |` in the producerKeys list entry.
  sed 's/^/      /' "$RA_PUB"
  cat <<'YAML'

log:
  level: info
  format: text
YAML
} >"$DATA/demo-tl.yaml"
ok "wrote $DATA/demo-tl.yaml (RA signer trusted)"

# ----- start TL -----
header "Start ans-tl"
mkdir -p "$DATA/tl/tiles" "$DATA/tl/keys"
"$ROOT/bin/ans-tl" --config "$DATA/demo-tl.yaml" >"$DATA/tl.log" 2>&1 &
TL_PID=$!
echo "$TL_PID" >"$DATA/tl.pid"
note "logs → $DATA/tl.log"
wait_ready "$TL_URL/v2/admin/ready"
ok "ans-tl ready (pid $TL_PID) at $TL_URL"

# ----- summary -----
header "Ready"
printf "  %s ans-ra   %s   (pid %s, log %s)\n" "${C_GREEN}✔${C_RESET}" "$RA_URL" "$RA_PID" "$DATA/ra.log" >&2
printf "  %s ans-tl   %s   (pid %s, log %s)\n" "${C_GREEN}✔${C_RESET}" "$TL_URL" "$TL_PID" "$DATA/tl.log" >&2
printf "\n" >&2
printf "  next: %s\n" "scripts/demo/run-lifecycle.sh" >&2
printf "  stop: %s\n" "scripts/demo/stop.sh          (or --clean to wipe data)" >&2
