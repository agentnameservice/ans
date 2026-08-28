#!/usr/bin/env bash
# Compose a capability descriptor from an existing AgentEndpoint.metaDataUrl,
# and verify the integrity pin that makes it trustworthy.
#
# ANS discovers and verifies agents by name; the Protocol enum is deliberately
# transport-only (A2A / MCP / HTTP-API). This demo shows that a discovered agent
# can also advertise *how to transact with it* using only fields that ship
# today — no new enum member, discovery profile, or wire change.
#
# The mechanism is protocol-neutral: metaDataUrl locates a richer descriptor for
# an endpoint, and nothing constrains what that descriptor advertises. This demo
# uses an A2A agent-card carrying x402 payment tooling as its worked example,
# but the same composition carries any capability descriptor.
#
# What it does:
#
#   1. hashes the committed fixture card and checks it against the metaDataHash
#      pin quoted in README.md (offline, deterministic — this is the assertion),
#   2. derives the DNS-AID `cap-sha256` SvcParam (base64url of the raw digest)
#      and asserts it against testdata/expected-svcb.txt — the SVCB row this
#      registration actually produced when run against ans-ra, captured verbatim
#      from scripts/demo/dns-records.sh,
#   3. prints the registration body this composition produces, and
#   4. with --live URL, applies the same composition to YOUR descriptor:
#      fetches it, computes its pin and cap-sha256, and prints the registration
#      body you would POST for it.
#
# Step 2 is the load-bearing one: the expected row is recorded output from the
# reference implementation, not a value re-derived by this script. If the emit
# path in internal/adapter/discovery/ans/dnsaid.go changes shape, this fails
# instead of quietly agreeing with itself.
#
# The fixture is a neutral card for agent.example.com — nothing serves it; it
# exists so the offline assertion stays deterministic forever. Your own,
# necessarily different, descriptor is what --live is for.
#
# EXECUTE this script; do NOT `source` it (set -euo pipefail would leak into
# your interactive shell).
#
# Usage:
#   scripts/demo/capability-descriptors/verify.sh
#       # offline, fixture only
#   scripts/demo/capability-descriptors/verify.sh --live https://agent.your.tld/.well-known/agent-card.json
#       # additionally compose a registration for your live descriptor
#
# No running ANS stack is required — this demo asserts over a committed
# fixture and therefore does not source scripts/demo/common.sh.
#
# Exits 0 when the fixture matches its pin; non-zero on a pin mismatch, a
# missing dependency, or an unreachable --live descriptor.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FIXTURE="$SCRIPT_DIR/testdata/agent-card.json"
EXPECTED_SVCB="$SCRIPT_DIR/testdata/expected-svcb.txt"
# The neutral host the committed fixture is pinned to. Nothing is served
# there — the fixture keeps the offline assertion deterministic; --live is
# how you run the composition against a real descriptor.
AGENT_HOST="agent.example.com"
METADATA_URL="https://$AGENT_HOST/.well-known/agent-card.json"
AGENT_URL="https://$AGENT_HOST/a2a/v1"

# The pin this demo asserts. Keep in sync with README.md §"The integrity pin".
PINNED_SHA256="d8386a152720b0b9e1dd05a6456a812d864d6b85aca2a5a4d1decffc50d8ad88"

LIVE_URL=""
if [ "${1:-}" = "--live" ]; then
  LIVE_URL="${2:-}"
  [ -n "$LIVE_URL" ] || {
    printf 'FAIL: --live takes the descriptor URL as an argument, e.g.\n' >&2
    printf '  %s --live https://agent.your.tld/.well-known/agent-card.json\n' "$0" >&2
    exit 1
  }
fi

fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
header() { printf '\n\033[1m%s\033[0m\n' "$*"; }
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

# sha256 of a file, hex digest only. sha256sum on Linux; stock macOS ships
# shasum (Perl) but not coreutils sha256sum.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  fail "missing required command: sha256sum (or shasum)"
fi

require_cmd base64
require_cmd xxd
[ -f "$FIXTURE" ] || fail "fixture not found: $FIXTURE"

# dnsaid.go publishes key65401 (cap-sha256) as base64url of the RAW digest
# bytes, not of the hex text. Decode the hex, then base64url-encode unpadded.
cap_sha256_from_hex() {
  printf '%s' "$1" \
    | xxd -r -p \
    | base64 \
    | tr '+/' '-_' \
    | tr -d '=\n'
}

# ---------------------------------------------------------------------------
header "1. Fixture digest vs the pin"

FIXTURE_SHA="$(sha256_file "$FIXTURE")"
printf '  fixture : %s\n' "${FIXTURE#"$SCRIPT_DIR/"}"
printf '  sha256  : %s\n' "$FIXTURE_SHA"
printf '  pinned  : %s\n' "$PINNED_SHA256"

if [ "$FIXTURE_SHA" != "$PINNED_SHA256" ]; then
  fail "fixture digest does not match the pin in README.md.
      The committed card and the documented metaDataHash have diverged —
      update both together, or the worked example teaches a wrong value."
fi
printf '  -> match\n'

# ---------------------------------------------------------------------------
header "2. Derived cap-sha256 vs the row ans-ra actually emitted"

CAP_SHA256="$(cap_sha256_from_hex "$FIXTURE_SHA")"
printf '  derived key65401 : %s\n' "$CAP_SHA256"

[ -f "$EXPECTED_SVCB" ] || fail "missing recorded SVCB row: $EXPECTED_SVCB"
EMITTED_ROW="$(tr -d '\r\n' < "$EXPECTED_SVCB")"
EMITTED_CAP="$(
  printf '%s' "$EMITTED_ROW" \
    | tr ' ' '\n' \
    | sed -n 's/^key65401=//p'
)"
printf '  emitted key65401 : %s\n' "${EMITTED_CAP:-(not found)}"

if [ "$CAP_SHA256" != "$EMITTED_CAP" ]; then
  fail "derived cap-sha256 does not match the recorded ans-ra output.
      Either the fixture card changed without the row being re-recorded, or
      the emit path in internal/adapter/discovery/ans/dnsaid.go changed shape.
      Re-record with: scripts/demo/dns-records.sh --json"
fi
printf '  -> match\n\n'

printf '  Full SVCB row emitted by ans-ra for this registration:\n'
printf '    %s\n' "$EMITTED_ROW"

# ---------------------------------------------------------------------------
header "3. Registration body this composition produces"

cat <<JSON
  {
    "agentHost": "$AGENT_HOST",
    "discoveryProfiles": ["ANS_DNSAID"],
    "endpoints": [
      {
        "protocol": "A2A",
        "agentUrl": "$AGENT_URL",
        "metaDataUrl": "$METADATA_URL",
        "metaDataHash": "SHA256:$PINNED_SHA256",
        "transports": ["JSON_RPC"]
      }
    ]
  }
JSON
printf '\n  Note: metaDataUrl host == agentHost, as the emit-side URL policy\n'
printf '  requires (internal/catalog/generate.go). An off-host descriptor is\n'
printf '  catalog-ineligible and is published without an integrity pin.\n'

# ---------------------------------------------------------------------------
header "4. What the descriptor advertises"

if command -v jq >/dev/null 2>&1; then
  printf '  skills: '
  jq -r '[.skills[]?.id] | join(", ")' "$FIXTURE" 2>/dev/null || printf '(none parsed)\n'
else
  printf '  (install jq to list the descriptor skills)\n'
fi
printf '\n  The descriptor — not ANS — carries the capability. ANS'"'"'s role ends at\n'
printf '  verified discovery of an integrity-pinned locator.\n'

# ---------------------------------------------------------------------------
if [ -n "$LIVE_URL" ]; then
  header "5. Your descriptor (--live)"
  require_cmd curl

  case "$LIVE_URL" in
    https://*) : ;;
    *) fail "--live URL must be https (the same policy the RA enforces on metaDataUrl)" ;;
  esac
  LIVE_HOST="${LIVE_URL#https://}"
  LIVE_HOST="${LIVE_HOST%%/*}"

  LIVE_TMP="$(mktemp)"
  trap 'rm -f "$LIVE_TMP"' EXIT

  curl -sSf "$LIVE_URL" -o "$LIVE_TMP" 2>/dev/null \
    || fail "descriptor unreachable at $LIVE_URL"

  LIVE_SHA="$(sha256_file "$LIVE_TMP")"
  LIVE_CAP="$(cap_sha256_from_hex "$LIVE_SHA")"
  printf '  descriptor       : %s\n' "$LIVE_URL"
  printf '  sha256 pin       : %s\n' "$LIVE_SHA"
  printf '  cap-sha256 (raw) : %s\n' "$LIVE_CAP"
  printf '\n  Registration body for this descriptor:\n'
  cat <<JSON
  {
    "agentHost": "$LIVE_HOST",
    "discoveryProfiles": ["ANS_DNSAID"],
    "endpoints": [
      {
        "protocol": "A2A",
        "agentUrl": "https://$LIVE_HOST/a2a/v1",
        "metaDataUrl": "$LIVE_URL",
        "metaDataHash": "SHA256:$LIVE_SHA"
      }
    ]
  }
JSON
  printf '\n  The pin binds the registration to the exact bytes fetched above.\n'
  printf '  When the descriptor changes, re-verify and re-register — metaDataHash\n'
  printf '  detects change; it is not a liveness check.\n'
fi

header "OK"
printf 'Fixture matches its pin. The composition above needs no ANS code change.\n\n'
