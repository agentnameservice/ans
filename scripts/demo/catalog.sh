#!/usr/bin/env bash
# Walk the AI Catalog generation scenarios end-to-end against a running
# RA. Every byte is derived from the registration aggregate. A catalog
# entry is published only AFTER the agent is ACTIVE — its SCITT-receipt
# attestation and TL badge link to Transparency-Log records that exist only
# once the agent is sealed at activation — so each agent is driven to ACTIVE
# before its catalog-entry is fetched.
#
#   1. Eligible single-protocol (MCP + metaDataUrl), activated
#        → GET .../catalog-entry returns the bare entry (200), with the
#          urn:ai lineage handle, the ANS-Registration SCITT-receipt
#          attestation, and {ansName,agentHost,badgeUrl} metadata.
#   2. Eligible multi-protocol (A2A + MCP, both with metaDataUrl), activated
#        → one nested outer entry (mediaType application/ai-catalog+json)
#          whose inline data holds one lean child per protocol.
#   3. Ineligible (HTTP-API endpoint, no catalog artifact type), activated
#        → GET .../catalog-entry returns 422 NOT_CATALOG_ELIGIBLE.
#   Plus: the registration 202 carries NO catalog data (it lives behind the
#   catalog routes), and a pending agent has no catalog entry.
#
# Usage:
#   scripts/demo/start.sh            # bring up ans-ra + ans-tl first
#   scripts/demo/catalog.sh          # then run this
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

# Catalog helpers (cat_req, assert_status, cassert, cat_activate, gen_csrs)
# live in common.sh — shared with ai-catalog.sh.

RAND="$(openssl rand -hex 4)"

# ──────────────────────────────────────────────────────────────────
# Scenario 1 — eligible single-protocol (MCP)
# ──────────────────────────────────────────────────────────────────
header "1. Eligible single-protocol agent (MCP + metaDataUrl)"
H1="catalog-single-$RAND.example.com"
ANS1="ans://v1.0.0.$H1"
URN1="urn:ai:$H1:agents:${H1%%.*}"
META1="https://$H1/.well-known/mcp/server-card.json"
gen_csrs "$H1" "$ANS1"
REQ1=$(jq -n --arg host "$H1" --arg meta "$META1" --arg idc "$IDENTITY_CSR_PEM" --arg sc "$SERVER_CSR_PEM" '{
  agentDisplayName: "Catalog Single",
  agentDescription: "single-protocol catalog demo",
  version: "1.0.0",
  agentHost: $host,
  endpoints: [{ agentUrl: ("https://" + $host + "/mcp"), metaDataUrl: $meta, protocol: "MCP", transports: ["SSE"] }],
  identityCsrPEM: $idc,
  serverCsrPEM: $sc
}')
header "1a. POST /v2/ans/agents  (eligible single-protocol)"
cat_req POST /v2/ans/agents "$REQ1"
assert_status 202 "register single"
A1=$(printf '%s' "$CAT_BODY" | jq -r '.agentId // empty')
[ -n "$A1" ] || fail "no agentId for single-protocol agent"
# The registration path is UNCHANGED: the 202 carries no catalog data
# (no catalogEntry/catalogEntryReason, no catalog links). The catalog is
# derived from existing data and lives behind its own routes (1b below).
cassert "registration 202 carries no catalog data" "$CAT_BODY" \
  '(has("catalogEntry")|not) and (has("catalogEntryReason")|not) and ([.links[]?.rel] | (index("catalog-entry")==null) and (index("ai-catalog")==null))'

cat_activate "$A1"

header "1b. GET /v2/ans/agents/$A1/catalog-entry"
cat_req GET "/v2/ans/agents/$A1/catalog-entry"
assert_status 200 "catalog-entry single"
E1="$CAT_BODY"
cassert "identifier is the urn:ai lineage handle (leftmost DNS label)" "$E1" ".identifier == \"$URN1\""
cassert "mediaType is the card type for MCP"                          "$E1" '.mediaType == "application/mcp-server-card+json"'
cassert "exactly one of url|data (single -> url)"                     "$E1" '(.url|type=="string") and (has("data")|not)'
cassert "url is the declared metaDataUrl"                             "$E1" ".url == \"$META1\""
cassert "publisher is DNS-anchored on the agentHost"                  "$E1" ".publisher.identifier == \"$H1\" and .publisher.identityType == \"dns\""
cassert "metadata = {ansName, agentHost, badgeUrl}, no logId"         "$E1" \
  ".metadata.ansName == \"$ANS1\" and .metadata.agentHost == \"$H1\" and .metadata.badgeUrl == \"$TL_PUBLIC_URL/v1/agents/$A1\" and (.metadata|has(\"logId\")|not)"
cassert "trustManifest.identity equals the entry identifier"          "$E1" '.trustManifest.identity == .identifier'
cassert "ANS-Registration SCITT-receipt attestation (no digest)"      "$E1" \
  ".trustManifest.attestations[0].type == \"ANS-Registration\" and .trustManifest.attestations[0].mediaType == \"application/scitt-receipt+cose\" and .trustManifest.attestations[0].uri == \"$TL_PUBLIC_URL/v1/agents/$A1/receipt\" and (.trustManifest.attestations[0]|has(\"digest\")|not)"

# ──────────────────────────────────────────────────────────────────
# Scenario 2 — eligible multi-protocol (A2A + MCP) → nested entry
# ──────────────────────────────────────────────────────────────────
header "2. Eligible multi-protocol agent (A2A + MCP) -> nested entry"
H2="catalog-multi-$RAND.example.com"
ANS2="ans://v1.0.0.$H2"
URN2="urn:ai:$H2:agents:${H2%%.*}"
gen_csrs "$H2" "$ANS2"
REQ2=$(jq -n --arg host "$H2" --arg idc "$IDENTITY_CSR_PEM" --arg sc "$SERVER_CSR_PEM" '{
  agentDisplayName: "Catalog Multi",
  version: "1.0.0",
  agentHost: $host,
  endpoints: [
    { agentUrl: ("https://" + $host + "/a2a"), metaDataUrl: ("https://" + $host + "/.well-known/agent-card.json"), protocol: "A2A" },
    { agentUrl: ("https://" + $host + "/mcp"), metaDataUrl: ("https://" + $host + "/.well-known/mcp/server-card.json"), protocol: "MCP" }
  ],
  identityCsrPEM: $idc,
  serverCsrPEM: $sc
}')
header "2a. POST /v2/ans/agents  (eligible multi-protocol)"
cat_req POST /v2/ans/agents "$REQ2"
assert_status 202 "register multi"
A2=$(printf '%s' "$CAT_BODY" | jq -r '.agentId // empty')
[ -n "$A2" ] || fail "no agentId for multi-protocol agent"

cat_activate "$A2"

header "2b. GET /v2/ans/agents/$A2/catalog-entry"
cat_req GET "/v2/ans/agents/$A2/catalog-entry"
assert_status 200 "catalog-entry multi"
E2="$CAT_BODY"
cassert "outer entry is a nested catalog (mediaType ai-catalog+json)" "$E2" '.mediaType == "application/ai-catalog+json"'
cassert "outer entry uses data, not url"                             "$E2" '(has("url")|not) and (.data|type=="object")'
cassert "nested catalog is specVersion 1.0 with two children"        "$E2" '.data.specVersion == "1.0" and (.data.entries|length == 2)'
cassert "first child is the A2A leaf (id :a2a)"                      "$E2" \
  '.data.entries[0].identifier == (.identifier + ":a2a") and .data.entries[0].mediaType == "application/a2a-agent-card+json" and (.data.entries[0].url|type=="string")'
cassert "second child is the MCP leaf (id :mcp)"                     "$E2" \
  '.data.entries[1].identifier == (.identifier + ":mcp") and .data.entries[1].mediaType == "application/mcp-server-card+json"'
cassert "the trust manifest sits on the OUTER entry"                "$E2" ".trustManifest.identity == \"$URN2\""
cassert "children stay lean (no nested trust manifest)"             "$E2" '(.data.entries[0]|has("trustManifest")|not)'

# ──────────────────────────────────────────────────────────────────
# Scenario 3 — ineligible (HTTP-API, no catalog artifact type)
# ──────────────────────────────────────────────────────────────────
header "3. Ineligible agent (HTTP-API endpoint -> no catalog artifact)"
H3="catalog-none-$RAND.example.com"
ANS3="ans://v1.0.0.$H3"
gen_csrs "$H3" "$ANS3"
REQ3=$(jq -n --arg host "$H3" --arg idc "$IDENTITY_CSR_PEM" --arg sc "$SERVER_CSR_PEM" '{
  agentDisplayName: "Catalog None",
  version: "1.0.0",
  agentHost: $host,
  endpoints: [{ agentUrl: ("https://" + $host + "/api"), protocol: "HTTP_API" }],
  identityCsrPEM: $idc,
  serverCsrPEM: $sc
}')
header "3a. POST /v2/ans/agents  (ineligible)"
cat_req POST /v2/ans/agents "$REQ3"
assert_status 202 "register ineligible"
A3=$(printf '%s' "$CAT_BODY" | jq -r '.agentId // empty')
[ -n "$A3" ] || fail "no agentId for ineligible agent"

cat_activate "$A3"

header "3b. GET /v2/ans/agents/$A3/catalog-entry  (expect 422 — ACTIVE but HTTP-API only)"
cat_req GET "/v2/ans/agents/$A3/catalog-entry"
assert_status 422 "catalog-entry ineligible"
cassert "RFC 7807 problem carries code NOT_CATALOG_ELIGIBLE" "$CAT_BODY" '.code == "NOT_CATALOG_ELIGIBLE" and .status == 422'
ok "ineligible registration correctly produces no catalog entry"

# ----- summary -----
header "AI Catalog scenarios complete"
printf "  single (MCP)        %s  -> %s\n" "$A1" "$URN1" >&2
printf "  multi  (A2A+MCP)    %s  -> %s (nested)\n" "$A2" "$URN2" >&2
printf "  ineligible (HTTP)   %s  -> 422 NOT_CATALOG_ELIGIBLE\n" "$A3" >&2
