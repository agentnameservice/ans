#!/usr/bin/env bash
# Compose a payable agent endpoint from an existing AgentEndpoint.metaDataUrl,
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
#   4. with --live, fetches the real descriptor and reports whether it still
#      matches the fixture.
#
# Step 2 is the load-bearing one: the expected row is recorded output from the
# reference implementation, not a value re-derived by this script. If the emit
# path in internal/adapter/discovery/ans/dnsaid.go changes shape, this fails
# instead of quietly agreeing with itself.
#
# On --live mismatch the demo does NOT fail: a changed descriptor is either
# drift or a legitimate new version, and from the digest alone you cannot tell
# which. That ambiguity is the reason the pin is checked against a committed
# fixture rather than against whatever the network returns today.
#
# EXECUTE this script; do NOT `source` it (set -euo pipefail would leak into
# your interactive shell).
#
# Usage:
#   scripts/demo/payable-endpoints/verify.sh           # offline, fixture only
#   scripts/demo/payable-endpoints/verify.sh --live    # also compare live descriptor
#
# No running ANS stack is required — this demo asserts over a committed
# fixture and therefore does not source scripts/demo/common.sh.
#
# Exits 0 when the fixture matches its pin; non-zero on a pin mismatch or a
# missing dependency.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FIXTURE="$SCRIPT_DIR/testdata/agent-card.json"
EXPECTED_SVCB="$SCRIPT_DIR/testdata/expected-svcb.txt"
AGENT_HOST="api.dnsofmoney.com"
METADATA_URL="https://$AGENT_HOST/.well-known/agent-card.json"
AGENT_URL="https://$AGENT_HOST/a2a/v1"

# The pin this demo asserts. Keep in sync with README.md §"The integrity pin".
PINNED_SHA256="23133f65cc200a06f79009d3b43e65dd743fb7d0a914109274a6c5b5a9c0d41b"

LIVE=0
[ "${1:-}" = "--live" ] && LIVE=1

fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
header() { printf '\n\033[1m%s\033[0m\n' "$*"; }
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_cmd sha256sum
require_cmd base64
[ -f "$FIXTURE" ] || fail "fixture not found: $FIXTURE"

# ---------------------------------------------------------------------------
header "1. Fixture digest vs the pin"

FIXTURE_SHA="$(sha256sum "$FIXTURE" | cut -d' ' -f1)"
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

# dnsaid.go publishes key65401 (cap-sha256) as base64url of the RAW digest
# bytes, not of the hex text. Decode the hex, then base64url-encode unpadded.
CAP_SHA256="$(
  printf '%s' "$FIXTURE_SHA" \
    | xxd -r -p \
    | base64 \
    | tr '+/' '-_' \
    | tr -d '=\n'
)"
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
if [ "$LIVE" -eq 1 ]; then
  header "5. Live descriptor comparison (--live)"
  require_cmd curl

  LIVE_TMP="$(mktemp)"
  trap 'rm -f "$LIVE_TMP"' EXIT

  if ! curl -sSf "$METADATA_URL" -o "$LIVE_TMP" 2>/dev/null; then
    printf '  live descriptor unreachable at %s\n' "$METADATA_URL"
    printf '  (network-dependent; the fixture assertion above still stands)\n'
  else
    LIVE_SHA="$(sha256sum "$LIVE_TMP" | cut -d' ' -f1)"
    printf '  live sha256 : %s\n' "$LIVE_SHA"
    if [ "$LIVE_SHA" = "$FIXTURE_SHA" ]; then
      printf '  -> identical to the fixture\n'
    else
      printf '  -> DIFFERS from the fixture\n\n'
      printf '  The live descriptor has changed since this fixture was committed.\n'
      printf '  From the digest alone you cannot distinguish a legitimate new\n'
      printf '  version from unintended drift — which is exactly why the pin is\n'
      printf '  asserted against the fixture. Not a failure of this demo.\n'
    fi
  fi
fi

header "OK"
printf 'Fixture matches its pin. The composition above needs no ANS code change.\n\n'
