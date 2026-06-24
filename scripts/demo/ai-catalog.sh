#!/usr/bin/env bash
# Produce and validate the host-complete AI Catalog document — the literal
# ai-catalog.json an Agent-Host Provider (AHP) republishes verbatim at
# https://{agentHost}/.well-known/ai-catalog.json (IMPL §4).
#
# catalog.sh exercises the per-agent catalog-ENTRY (one building block,
# served as application/json). THIS script exercises the per-host
# DOCUMENT, whose defining property is that it is HOST-COMPLETE: it carries
# one CatalogEntry for EVERY catalog-eligible agent on the host — and
# nothing else. To prove that, it builds a single host with a deliberately
# mixed population (all same owner — one host belongs to one owner):
#
#   v1.0.0  MCP  + metaDataUrl    eligible, ACTIVE    -> IN the document
#   v2.0.0  A2A  + metaDataUrl    eligible, ACTIVE    -> IN the document
#   v3.0.0  HTTP-API (no card)    ACTIVE, ineligible  -> ABSENT (no artifact type)
#   v4.0.0  MCP  + metaDataUrl    eligible, PENDING   -> ABSENT (not sealed in the TL)
#   + an eligible ACTIVE agent on a DIFFERENT host    -> ABSENT (host scope)
#
# The resulting document must therefore list EXACTLY the two ACTIVE
# eligible versions, carry specVersion "1.0" + a host object, sort
# deterministically (identifier then version) for a stable ETag, and be
# byte-identical no matter which of the host's agentIds is used to fetch it
# (the route is an agent-scoped alias for the whole host). It is saved to
# data/demo/ai-catalog.json so you can open the actual file an AHP serves.
#
# NOTE (serving model): IMPL §6 models the catalog routes as PUBLIC and
# unauthenticated (every field is already TL- or DNS-visible). This RA
# deployment owner-scopes them (ReadOwnership), so the fetch below carries
# the owner's bearer token. A public deployment would drop that header; the
# document assertions are otherwise identical. ANS never serves the
# /.well-known path itself — it generates the bytes; the AHP publishes them.
#
# Usage:
#   scripts/demo/start.sh        # bring up ans-ra + ans-tl first
#   scripts/demo/ai-catalog.sh   # then run this
#
# Prerequisites: curl, jq, openssl (same as the other demo scripts).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

require_cmd curl
require_cmd jq
require_cmd openssl

if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# reg_eligible HOST VERSION PROTOCOL — register an agent whose single
# endpoint declares a metaDataUrl card (catalog-eligible). Sets
# REG_AGENT_ID. PROTOCOL is MCP or A2A.
reg_eligible() {
  local host="$1" ver="$2" proto="$3" ans="ans://v$2.$1" path meta
  case "$proto" in
    MCP) path="/mcp"; meta="https://$host/.well-known/mcp/server-card.json" ;;
    A2A) path="/a2a"; meta="https://$host/.well-known/agent-card.json" ;;
    *)   fail "reg_eligible: unsupported protocol $proto" ;;
  esac
  gen_csrs "$host" "$ans"
  local body
  body=$(jq -n --arg host "$host" --arg ver "$ver" --arg url "https://$host$path" \
    --arg meta "$meta" --arg proto "$proto" --arg idc "$IDENTITY_CSR_PEM" --arg sc "$SERVER_CSR_PEM" '{
    agentDisplayName: ("Catalog " + $proto + " v" + $ver),
    version: $ver,
    agentHost: $host,
    endpoints: [{ agentUrl: $url, metaDataUrl: $meta, protocol: $proto }],
    identityCsrPEM: $idc,
    serverCsrPEM: $sc
  }')
  cat_req POST /v2/ans/agents "$body"
  assert_status 202 "register $proto v$ver on $host"
  REG_AGENT_ID=$(printf '%s' "$CAT_BODY" | jq -r '.agentId // empty')
  [ -n "$REG_AGENT_ID" ] || fail "no agentId for $proto v$ver on $host"
}

# reg_ineligible HOST VERSION — register an HTTP-API agent (no catalog
# artifact type, no metaDataUrl): activates fine, but is never catalogued.
# Sets REG_AGENT_ID.
reg_ineligible() {
  local host="$1" ver="$2" ans="ans://v$2.$1"
  gen_csrs "$host" "$ans"
  local body
  body=$(jq -n --arg host "$host" --arg ver "$ver" --arg idc "$IDENTITY_CSR_PEM" --arg sc "$SERVER_CSR_PEM" '{
    agentDisplayName: ("Catalog HTTP v" + $ver),
    version: $ver,
    agentHost: $host,
    endpoints: [{ agentUrl: ("https://" + $host + "/api"), protocol: "HTTP_API" }],
    identityCsrPEM: $idc,
    serverCsrPEM: $sc
  }')
  cat_req POST /v2/ans/agents "$body"
  assert_status 202 "register HTTP-API v$ver on $host"
  REG_AGENT_ID=$(printf '%s' "$CAT_BODY" | jq -r '.agentId // empty')
  [ -n "$REG_AGENT_ID" ] || fail "no agentId for HTTP-API v$ver on $host"
}

RAND="$(openssl rand -hex 4)"
HOST="catalog-host-$RAND.example.com"
LABEL="${HOST%%.*}"
URN="urn:air:$HOST:agents:$LABEL"
OTHER="catalog-other-$RAND.example.com"

# ──────────────────────────────────────────────────────────────────
# 1. Build a mixed agent population on ONE host
# ──────────────────────────────────────────────────────────────────
header "1. Build a mixed agent population on a single host: $HOST"

reg_eligible "$HOST" "1.0.0" MCP; A1="$REG_AGENT_ID"; cat_activate "$A1"
reg_eligible "$HOST" "2.0.0" A2A; A2="$REG_AGENT_ID"; cat_activate "$A2"
reg_ineligible "$HOST" "3.0.0";  A3="$REG_AGENT_ID"; cat_activate "$A3"
reg_eligible "$HOST" "4.0.0" MCP; A4="$REG_AGENT_ID"   # left PENDING on purpose
ok "v1.0.0 (MCP) + v2.0.0 (A2A): ACTIVE & eligible"
ok "v3.0.0 (HTTP-API): ACTIVE but ineligible; v4.0.0 (MCP): eligible but PENDING"

header "1b. An eligible ACTIVE agent on a DIFFERENT host (must NOT leak in)"
reg_eligible "$OTHER" "1.0.0" MCP; AX="$REG_AGENT_ID"; cat_activate "$AX"

# ──────────────────────────────────────────────────────────────────
# 2. Fetch the host-complete ai-catalog.json and validate its shape
# ──────────────────────────────────────────────────────────────────
header "2. GET /v2/ans/agents/$A1/ai-catalog  → save the ai-catalog.json"
AICAT="$DATA/ai-catalog.json"
cat_doc "$A1" "$AICAT"
[ "$CAT_DOC_STATUS" = "200" ] || fail "ai-catalog GET: expected 200, got $CAT_DOC_STATUS"
pretty_json <"$AICAT" >&2

[ "$CAT_DOC_CTYPE" = "application/ai-catalog+json" ] \
  || fail "Content-Type: got '$CAT_DOC_CTYPE', want application/ai-catalog+json"
ok "served as application/ai-catalog+json"
[ -n "$CAT_DOC_ETAG" ] || fail "no ETag header on the document"
ETAG1="$CAT_DOC_ETAG"
ok "strong ETag present: $ETAG1"

DOC=$(cat "$AICAT")
cassert "specVersion is \"1.0\""                                  "$DOC" '.specVersion == "1.0"'
cassert "host object: identifier == displayName == agentHost"     "$DOC" ".host.identifier == \"$HOST\" and .host.displayName == \"$HOST\""
cassert "entries serializes as an array (never null)"             "$DOC" '(.entries | type) == "array"'
cassert "host-complete: EXACTLY the 2 ACTIVE eligible versions"   "$DOC" '(.entries | length) == 2'
cassert "both entries carry the host's version-spanning URN"      "$DOC" "[.entries[].identifier] == [\"$URN\", \"$URN\"]"
cassert "sorted (identifier, version): v1.0.0 before v2.0.0"      "$DOC" '[.entries[].version] == ["1.0.0", "2.0.0"]'
cassert "v1.0.0 entry is the MCP server card"                     "$DOC" '.entries[0].mediaType == "application/mcp-server-card+json"'
cassert "v2.0.0 entry is the A2A agent card"                      "$DOC" '.entries[1].mediaType == "application/a2a-agent-card+json"'
cassert "every entry is anchored on this agentHost"               "$DOC" "all(.entries[]; .metadata.agentHost == \"$HOST\")"
cassert "ineligible v3.0.0 (HTTP-API) is absent"                  "$DOC" '([.entries[].version] | index("3.0.0")) == null'
cassert "pending v4.0.0 is absent (not sealed in the TL)"         "$DOC" '([.entries[].version] | index("4.0.0")) == null'
cassert "a different host's agent never leaks in"                 "$DOC" "all(.entries[]; .metadata.agentHost != \"$OTHER\")"

# ──────────────────────────────────────────────────────────────────
# 3. Agent-scoped alias: any agentId on the host returns the WHOLE host
# ──────────────────────────────────────────────────────────────────
header "3. Host-complete alias: fetch via v2.0.0's agentId → same document"
AICAT_VIA_A2="$DATA/ai-catalog.via-a2.json"
cat_doc "$A2" "$AICAT_VIA_A2"
[ "$CAT_DOC_STATUS" = "200" ] || fail "ai-catalog via A2: expected 200, got $CAT_DOC_STATUS"
if diff -q "$AICAT" "$AICAT_VIA_A2" >/dev/null; then
  ok "byte-identical whether fetched via v1.0.0's or v2.0.0's agentId"
else
  fail "document differs by which agentId fetched it — not host-complete"
fi
[ "$CAT_DOC_ETAG" = "$ETAG1" ] || fail "ETag differs by agentId ($CAT_DOC_ETAG vs $ETAG1)"
ok "identical ETag across agentIds: $ETAG1"

# ──────────────────────────────────────────────────────────────────
# 4. Deterministic bytes + cheap AHP poll (ETag / 304)
# ──────────────────────────────────────────────────────────────────
header "4. Re-derivation is deterministic; conditional GET returns 304"
cat_doc "$A1" "$DATA/ai-catalog.refetch.json"
[ "$CAT_DOC_ETAG" = "$ETAG1" ] || fail "ETag not stable across re-derivation ($CAT_DOC_ETAG vs $ETAG1)"
ok "ETag stable across re-derivation (deterministic JCS-sorted bytes)"
cat_doc_inm "$A1" "$ETAG1"
[ "$CAT_DOC_STATUS" = "304" ] || fail "If-None-Match did not yield 304 (got $CAT_DOC_STATUS)"
ok "If-None-Match returned 304 Not Modified (AHP polls cheaply)"

# ----- summary -----
header "ai-catalog.json ready"
printf "  host        %s\n" "$HOST" >&2
printf "  entries     %s (v1.0.0 MCP, v2.0.0 A2A — host-complete)\n" "$(jq '.entries | length' "$AICAT")" >&2
printf "  ETag        %s\n" "$ETAG1" >&2
printf "  saved to    %s\n" "$AICAT" >&2
printf "\n" >&2
printf "  An Agent-Host Provider republishes this file verbatim at:\n" >&2
printf "    https://%s/.well-known/ai-catalog.json\n" "$HOST" >&2
