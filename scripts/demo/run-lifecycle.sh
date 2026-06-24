#!/usr/bin/env bash
# Walk a fresh agent through the full RA lifecycle, printing every
# request + response pair in color.
#
#   1. POST   /v2/ans/agents                                    (register)
#   2. GET    /v2/ans/agents/{id}                               (detail, PENDING_VALIDATION — challenges[] only, no dnsRecords yet)
#   3. POST   /v2/ans/agents/{id}/verify-acme                   (→ PENDING_DNS — issues identity + server certs)
#   4. GET    /v2/ans/agents/{id}                               (detail, PENDING_DNS — production dnsRecords with real TLSA fingerprint)
#   5. POST   /v2/ans/agents/{id}/verify-dns                    (→ ACTIVE)
#   6. GET    /v2/ans/agents/{id}                               (detail, now ACTIVE)
#   7. GET    /v2/ans/agents?status=ALL                         (list mine)
#   8. GET    /v2/ans/agents/{id}/certificates/identity         (issued cert)
#   9. Confirm the inline-sealed AGENT_REGISTERED leaf is durable in the TL
#  10. GET    TL /v1/agents/{id}/audit                          (history)
#  11. GET    TL /v1/agents/{id}                                (badge)
#  12. GET    TL /root-keys                                     (verifier PEMs)
#  13. GET    TL /v1/agents/{id}/receipt                        (SCITT COSE)
#  14. go test ./internal/tl/receipt -run TestSmokeVerifyDemoReceipt  (offline verify)
#  15. GET    TL /internal/v1/producer-keys/ra/{raId}           (admin CRUD)
#  16. POST   /v2/ans/identities                                (register the WHO — a did:web verified identity)
#  17. POST   /v2/ans/identities/{id}/verify-control            (control proof → VERIFIED, seals IDENTITY_VERIFIED)
#  18. POST   /v2/ans/identities/{id}/links                     (link the agent — ONE IDENTITY_LINKED on the identity stream)
#  19. GET    TL /v1/agents/{id}                                (badge now carries the computed identities[] join)
#
# Step 16-19 show the verified-identity surface in the standard
# lifecycle; scripts/demo/identity-lifecycle.sh exercises EVERY
# identity operation (re-add, did:key, rotation, unlink, revoke,
# receipts, history views).
#
# Usage:
#   scripts/demo/run-lifecycle.sh                            # random host, version 1.0.0
#   scripts/demo/run-lifecycle.sh myagent.example.com        # specific host, 1.0.0
#   scripts/demo/run-lifecycle.sh myagent.example.com 2.1.0  # specific host + version
#   scripts/demo/run-lifecycle.sh ans://v1.0.0.foo.example.com
#
# Env (take precedence over positional args):
#   AGENT_HOST      override the host component
#   AGENT_VERSION   override the version component (default 1.0.0)
#
# Each invocation with no args generates a random host so the demo
# can be re-run back-to-back without colliding with an ACTIVE agent
# from a previous run. Passing an explicit host/name is useful for
# targeted repros — registration will 409 if the (host, version)
# pair already exists.
#
# The resulting agentId is written to data/demo/last-agent-id so
# revoke.sh can pick it up without arguments.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# ----- arg parsing -----
#
# Positional forms:
#   $1 = <ans-name>   (starts with "ans://") → parse out host + version
#   $1 = <host>, $2 = <version optional>
#
# Env vars win if set (per POSIX convention for config overrides).
ARG1="${1:-}"
ARG2="${2:-}"
if [[ "$ARG1" == ans://* ]]; then
  # Strip prefix: ans://v1.0.0.agent.example.com → v1.0.0.agent.example.com
  rest="${ARG1#ans://}"
  # Strip leading 'v' then split "1.0.0.agent.example.com" at the first
  # occurrence of ".<letter>" (the version ends at the first non-digit
  # label). Easiest robust match: three dot-separated numeric segments.
  if [[ "$rest" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)\.(.+)$ ]]; then
    ARG_VERSION="${BASH_REMATCH[1]}"
    ARG_HOST="${BASH_REMATCH[2]}"
  else
    fail "ANS name must be ans://vMAJOR.MINOR.PATCH.host; got $ARG1"
  fi
else
  ARG_HOST="$ARG1"
  ARG_VERSION="$ARG2"
fi

AGENT_VERSION="${AGENT_VERSION:-${ARG_VERSION:-1.0.0}}"
if [ -n "${AGENT_HOST:-}" ]; then
  :  # env var wins
elif [ -n "$ARG_HOST" ]; then
  AGENT_HOST="$ARG_HOST"
else
  # Random 8-hex suffix gives 2^32 possible hosts per run — plenty
  # for back-to-back demo invocations. openssl is already a script
  # prerequisite (for CSR gen) and avoids the `tr | head` pipeline
  # whose SIGPIPE on `tr` gets propagated by `set -o pipefail`.
  AGENT_HOST="demo-$(openssl rand -hex 4).example.com"
fi
ANS_NAME="ans://v${AGENT_VERSION}.${AGENT_HOST}"

header "Demo target"
printf "  ansName   %s\n" "$ANS_NAME" >&2
printf "  host      %s\n" "$AGENT_HOST" >&2
printf "  version   %s\n" "$AGENT_VERSION" >&2

# Quick sanity check — the RA has to be up.
if ! curl -sSf "$RA_URL/v2/admin/ready" >/dev/null 2>&1; then
  fail "ans-ra isn't reachable at $RA_URL — run scripts/demo/start.sh first"
fi

# ----- 0. Build a matching CSR -----
#
# The RA's X509Validator refuses any CSR whose URI SAN does not match
# the agent's ANS name, so we generate a fresh EC P-256 key + CSR
# pair here. The private key is discarded after the demo run — for a
# real agent it's what the agent uses to authenticate its mTLS
# connections, so don't copy this pattern to production.
header "0. Generate identity CSR"
CSR_DIR="$DATA/csr"
rm -rf "$CSR_DIR"
mkdir -p "$CSR_DIR"
cat >"$CSR_DIR/openssl.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $ANS_NAME
[v3_req]
subjectAltName = URI:$ANS_NAME
CNF

openssl ecparam -name prime256v1 -genkey -noout -out "$CSR_DIR/key.pem" 2>/dev/null
openssl req -new -key "$CSR_DIR/key.pem" \
  -config "$CSR_DIR/openssl.cnf" \
  -out "$CSR_DIR/csr.pem" 2>/dev/null
CSR_PEM=$(cat "$CSR_DIR/csr.pem")
ok "CSR for $ANS_NAME written to $CSR_DIR/csr.pem"

# Server CSR (DNS SAN = agent FQDN) — exercises the serverCsrPEM
# registration path so the RA's server CA signs the TLS cert.
cat >"$CSR_DIR/server.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $AGENT_HOST
[v3_req]
subjectAltName = DNS:$AGENT_HOST
CNF
openssl ecparam -name prime256v1 -genkey -noout -out "$CSR_DIR/server.key" 2>/dev/null
openssl req -new -key "$CSR_DIR/server.key" \
  -config "$CSR_DIR/server.cnf" \
  -out "$CSR_DIR/server.csr" 2>/dev/null
SERVER_CSR_PEM=$(cat "$CSR_DIR/server.csr")

# ----- 1. Register -----
header "1. POST /v2/ans/agents"
REG_REQ=$(jq -n \
  --arg host "$AGENT_HOST" \
  --arg version "$AGENT_VERSION" \
  --arg csr "$CSR_PEM" \
  --arg srvCsr "$SERVER_CSR_PEM" '
  {
    agentDisplayName: "demo-agent",
    agentDescription: "A demo agent",
    version:          $version,
    agentHost:        $host,
    endpoints: [{
      agentUrl:    ("https://" + $host + "/mcp"),
      metaDataUrl: ("https://" + $host + "/.well-known/mcp/server-card.json"),
      protocol:    "MCP",
      transports:  ["SSE"]
    }],
    identityCsrPEM: $csr,
    serverCsrPEM:   $srvCsr
  }')

REG_RESP=$(curl_json POST /v2/ans/agents "$REG_REQ")
AGENT_ID=$(printf '%s' "$REG_RESP" | jq -r '.agentId // empty')
if [ -z "$AGENT_ID" ]; then
  fail "no agentId in register response — see the RESP above"
fi
echo "$AGENT_ID" >"$DATA/last-agent-id"
ok "agentId=$AGENT_ID"

# ----- 2. Detail (pending) -----
header "2. GET /v2/ans/agents/$AGENT_ID  (expect PENDING_VALIDATION)"
curl_json GET "/v2/ans/agents/$AGENT_ID" >/dev/null

# ----- 3. verify-acme -----
#
# Cert issuance happens here, NOT at register: the RA only signs the
# identity + server CSRs once the operator has proven domain control
# via the ACME DNS-01 challenge. This is also when production DNS
# records (TRUST/BADGE/DISCOVERY/TLSA) become computable — TLSA's
# value is `3 1 1 SHA-256(server-cert-SPKI)`, so it can't exist before
# the server cert does.
header "3. POST /v2/ans/agents/$AGENT_ID/verify-acme  (→ PENDING_DNS, issues identity + server certs)"
curl_json POST "/v2/ans/agents/$AGENT_ID/verify-acme" >/dev/null
assert_2xx "verify-acme"

# ----- 4. Detail (pending DNS) -----
#
# Now that verify-acme has issued the server cert, the GET detail
# response surfaces the full production record set the operator must
# publish before verify-dns will succeed: DISCOVERY (TXT routing
# pointer), BADGE (TXT public discovery hint), and TLSA (cert
# binding, fingerprint pinned to the just-issued server leaf).
# Calling out this step explicitly so a demo viewer can see exactly
# which records to publish — production agents' SDKs do the same
# read between verify-acme and verify-dns.
header "4. GET /v2/ans/agents/$AGENT_ID  (PENDING_DNS — production dnsRecords now materialized)"
curl_json GET "/v2/ans/agents/$AGENT_ID" >/dev/null

# ----- 5. verify-dns -----
header "5. POST /v2/ans/agents/$AGENT_ID/verify-dns  (→ ACTIVE)"
# When ans-dns is bundled with this demo (see scripts/demo/start.sh
# --with-dns), install the agent's DNS records into the local
# authoritative server before calling verify-dns so the lookup
# succeeds against real wire-format responses. Falls through to
# noop behavior when ANS_DNS_ZONE is unset.
if [ -n "${ANS_DNS_ZONE:-}" ] && [ -x "$BIN/ans-dns" ]; then
  note "installing agent records into $ANS_DNS_ZONE via ans-dns"
  "$BIN/ans-dns" install --zone "$ANS_DNS_ZONE" --api-key "$RA_API_KEY" "$RA_URL" "$AGENT_ID"
else
  note "noop DNS verifier accepts any operator DNS state; production plugs in a real verifier"
fi
curl_json POST "/v2/ans/agents/$AGENT_ID/verify-dns" >/dev/null
assert_2xx "verify-dns"

# ----- 6. Detail (active) -----
header "6. GET /v2/ans/agents/$AGENT_ID  (now ACTIVE)"
curl_json GET "/v2/ans/agents/$AGENT_ID" >/dev/null

# ----- 7. List -----
header "7. GET /v2/ans/agents?status=ALL  (list mine)"
curl_json GET "/v2/ans/agents?status=ALL" >/dev/null

# ----- 8. Identity certs -----
header "8. GET /v2/ans/agents/$AGENT_ID/certificates/identity"
curl_json GET "/v2/ans/agents/$AGENT_ID/certificates/identity" >/dev/null

# ----- 9. Confirm the inline-sealed AGENT_REGISTERED leaf -----
#
# The single terminal AGENT_REGISTERED event is sealed INLINE at the
# verify-dns ACTIVE transition (seal-before-success): verify-dns only
# returned ACTIVE above because the TL already acknowledged the seal,
# so — unlike revocation, which still rides the outbox worker — the
# leaf is durable in the log by the time we get here. This poll is a
# confirmation, not a wait: it should succeed on the first try (the
# audit materialized view may lag the seal by a beat, so we still poll
# to keep the demo deterministic rather than racing the projection).
header "9. Confirm the inline-sealed AGENT_REGISTERED leaf is durable in the TL"
poll_tl_audit "$AGENT_ID" 1 30
ok "TL has the AGENT_REGISTERED leaf (sealed inline at activation)"

# ----- 10. TL audit -----
header "10. TL: GET /v1/agents/$AGENT_ID/audit"
curl_tl GET "/v1/agents/$AGENT_ID/audit" >/dev/null

# ----- 11. TL badge -----
header "11. TL: GET /v1/agents/$AGENT_ID (badge)"
curl_tl GET "/v1/agents/$AGENT_ID" >/dev/null

# ----- 12. TL root keys -----
#
# Sumdb-note verification lines for every active TL verifier — one
# line per key, format `<origin>+<keyhash-hex>+<base64-DER>`. A
# verifier fetches this once at session start and caches it;
# rotation adds a new line while the old one stays trusted.
header "12. TL: GET /root-keys  (verifier keys, sumdb-note format)"
ROOT_KEYS_FILE="$DATA/root-keys.txt"
curl_tl_text GET "/root-keys" >"$ROOT_KEYS_FILE"
assert_2xx "GET /root-keys"
key_count=$(grep -cv '^[[:space:]]*$' "$ROOT_KEYS_FILE" || true)
ok "root-keys saved to $ROOT_KEYS_FILE ($key_count verification line(s))"

# ----- 13. TL receipt -----
#
# SCITT COSE_Sign1 receipt — binary CBOR, tag 18, ES256 signature
# over the event's canonical bytes. The response is NOT JSON; we
# save it to disk so a verifier (internal/tl/receipt/verify.go)
# can round-trip it against root-keys.txt.
header "13. TL: GET /v1/agents/$AGENT_ID/receipt  (SCITT COSE_Sign1)"
RECEIPT_FILE="$DATA/receipt.cbor"
receipt_status=$(curl_tl_binary GET "/v1/agents/$AGENT_ID/receipt" "$RECEIPT_FILE")
if [ "$receipt_status" = "200" ]; then
  receipt_bytes=$(wc -c <"$RECEIPT_FILE" | tr -d ' ')
  # First byte should be 0xd2 (CBOR tag 18 = COSE_Sign1) — a quick
  # sanity check that we got bytes, not accidentally JSON. `od`
  # avoids requiring `xxd` which isn't always installed.
  first_byte=$(od -An -tx1 -N1 "$RECEIPT_FILE" | tr -d ' \n')
  ok "receipt saved to $RECEIPT_FILE (${receipt_bytes} bytes, first byte=0x${first_byte}, want 0xd2 for COSE_Sign1 tag 18)"
  # Close the loop — run the ans-verify CLI. Fetches root-keys,
  # decodes the CBOR, extracts the inclusion proof, walks the path
  # to the stored root hash, and ECDSA-verifies the signature with
  # KID-direct key lookup. Also cross-checks the receipt's leaf hash
  # against the badge's merkleProof. If this passes, any third-party
  # verifier talking only HTTP to the TL can cryptographically prove
  # inclusion — matching the reference ans-verify binary byte-for-byte
  # in flow and format.
  header "14. Offline verify (bin/ans-verify)"
  if "$ROOT/bin/ans-verify" -url "$TL_URL" -agent "$AGENT_ID" >&2; then
    ok "ans-verify passed"
  else
    fail "ans-verify FAILED — receipt bytes or root-keys are wrong"
  fi
elif [ "$receipt_status" = "503" ]; then
  warn "receipt 503 — checkpoint has not yet covered the leaf; retry in a few seconds"
else
  fail "unexpected receipt status $receipt_status; see $RECEIPT_FILE"
fi

# ----- 15. Admin producer-keys API -----
#
# Stage 4 moved the producer-key trust store from YAML-only to
# SQLite with admin CRUD. The YAML producerKeys[] section still works
# as a bootstrap path (keys are upserted into tl_producer_keys at
# startup), but runtime rotation now flows through the admin API.
# This step confirms:
#   (a) the admin auth works (we're hitting /v2/admin/* with the
#       static API key, which maps to IsAdmin=true);
#   (b) the bootstrapped RA signer is actually in SQLite;
#   (c) the list response is the shape admin tooling will consume.
header "15. TL: GET /internal/v1/producer-keys/ra/ans-ra-local  (admin)"
curl_tl GET "/internal/v1/producer-keys/ra/ans-ra-local" >/dev/null

# ----- 16-19. Verified identity (the WHO behind this agent) -----
#
# The agent registration above is the "what": one FQDN, its
# endpoints, its certificates. The verified identity is the "who"
# behind it — proven through a challenge-bound key proof, sealed on
# its own TL stream, and linked to the agent. Rotating or revoking
# the identity later is ONE sealed event regardless of how many
# agents are linked; every linked badge reflects it at read time.
header "16. POST /v2/ans/identities  (register the WHO — did:web)"
require_cmd go
IDENTITY_DID="did:web:who-$(openssl rand -hex 4).example.com"
IDENTITY_KEY="$DATA/identity-who.pem"
(cd "$ROOT" && go run ./scripts/demo/signproof keygen -out "$IDENTITY_KEY") >/dev/null
ID_REG=$(curl_json POST /v2/ans/identities "$(jq -n --arg v "$IDENTITY_DID" '{value: $v}')")
IDENTITY_ID=$(printf '%s' "$ID_REG" | jq -r '.identityId // empty')
ID_INPUT=$(printf '%s' "$ID_REG" | jq -r '.challenges[0].signingInput // empty')
[ -n "$IDENTITY_ID" ] && [ -n "$ID_INPUT" ] || fail "identity register failed"
echo "$IDENTITY_ID" >"$DATA/last-identity-id"
ok "identityId=$IDENTITY_ID (PENDING_CONTROL — challenge issued)"

header "17. POST /v2/ans/identities/$IDENTITY_ID/verify-control  (→ VERIFIED)"
ID_PROOF=$(cd "$ROOT" && go run ./scripts/demo/signproof sign \
  -key "$IDENTITY_KEY" -kid "${IDENTITY_DID}#key-1" -input "$ID_INPUT")
curl_json POST "/v2/ans/identities/$IDENTITY_ID/verify-control" \
  "$(jq -n --arg p "$ID_PROOF" '{signedProofs: [$p]}')" >/dev/null
assert_2xx "identity verify-control"
ok "control proven — IDENTITY_VERIFIED seals on the identity's own TL stream"

header "18. POST /v2/ans/identities/$IDENTITY_ID/links  (link this agent — one call, one sealed event)"
curl_json POST "/v2/ans/identities/$IDENTITY_ID/links" \
  "$(jq -n --arg a "$AGENT_ID" '{agentIds: [$a]}')" >/dev/null
assert_2xx "identity link"

header "19. TL: GET /v1/agents/$AGENT_ID  (badge — computed identities[] join)"
# No polling: identity ops are seal-before-success — the seals are
# already in the log the moment the link call returned.
assert_tl_identity_audit "$IDENTITY_ID" 2
BADGE_WITH_WHO=$(curl_tl GET "/v1/agents/$AGENT_ID")
WHO_VALUE=$(printf '%s' "$BADGE_WITH_WHO" | jq -r '.identities[0].value // empty')
[ "$WHO_VALUE" = "$IDENTITY_DID" ] || fail "badge identities[] join missing (got: $WHO_VALUE)"
ok "one hop answers \"who is behind this agent\": $WHO_VALUE (VERIFIED)"

# ----- 20. AI Catalog entry -----
#
# The catalog entry is a derived, owner-scoped view of how this agent
# appears to an external AI Catalog / ARD registry. Its trust manifest
# points at the SAME SCITT receipt the demo fetched at step 13 — proving
# the catalog references a real, resolvable inclusion proof, not a
# fabricated URL. badgeUrl + the attestation URI use the RA's configured
# public TL base ($TL_PUBLIC_URL); in this demo that is the same host:port
# as the TL, https scheme.
header "20. GET /v2/ans/agents/$AGENT_ID/catalog-entry  (AI Catalog record)"
# curl_json runs in a command-substitution subshell, so its
# LAST_HTTP_STATUS does not reach this shell — the strict jq shape
# assertion below is the guard: a 422/error body has no matching
# .identifier and fails it.
CAT_ENTRY=$(curl_json GET "/v2/ans/agents/$AGENT_ID/catalog-entry")
want_urn="urn:air:${AGENT_HOST}:agents:${AGENT_HOST%%.*}"
want_receipt="${TL_PUBLIC_URL}/v1/agents/${AGENT_ID}/receipt"
want_badge="${TL_PUBLIC_URL}/v1/agents/${AGENT_ID}"
printf '%s' "$CAT_ENTRY" | jq -e \
  --arg urn "$want_urn" --arg rcpt "$want_receipt" --arg badge "$want_badge" '
    .identifier == $urn
    and .mediaType == "application/mcp-server-card+json"
    and (.url | type) == "string"
    and (has("data") | not)
    and .trustManifest.identity == $urn
    and .trustManifest.attestations[0].type == "ANS-Registration"
    and .trustManifest.attestations[0].mediaType == "application/scitt-receipt+cose"
    and .trustManifest.attestations[0].uri == $rcpt
    and .metadata.agentHost == "'"$AGENT_HOST"'"
    and .metadata.badgeUrl == $badge
  ' >/dev/null || fail "catalog entry shape/URLs did not match expectations"
ok "catalog entry well-formed; attestation URI = $want_receipt"
# The catalog advertises the receipt at the path the demo already fetched
# live over http at step 13 (same agentId, same path; https public base).
ok "that receipt path is live on the TL (step 13 retrieved its COSE bytes → $RECEIPT_FILE)"

# ----- 21. Host-complete AI Catalog document -----
#
# The per-host document is what the AHP publishes verbatim at
# /.well-known/ai-catalog.json. It lists every ACTIVE catalog-eligible
# agent on the host (this one). It is served as application/ai-catalog+json
# with a strong ETag; a conditional re-fetch returns 304, so AHPs poll
# cheaply. Uses curl directly (not curl_json) to read response headers.
header "21. GET /v2/ans/agents/$AGENT_ID/ai-catalog  (host-complete AI Catalog document)"
AICAT_HDR="$DATA/ai-catalog.hdr"
AICAT_BODY="$DATA/ai-catalog.json"
printf "${C_DIM}→ GET %s/v2/ans/agents/%s/ai-catalog${C_RESET}\n" "$RA_URL" "$AGENT_ID" >&2
aicat_status=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" \
  -D "$AICAT_HDR" -o "$AICAT_BODY" -w '%{http_code}' \
  "$RA_URL/v2/ans/agents/$AGENT_ID/ai-catalog")
[ "$aicat_status" = "200" ] || fail "ai-catalog: expected 200, got $aicat_status"
pretty_json <"$AICAT_BODY" >&2
grep -iq '^content-type:[[:space:]]*application/ai-catalog+json' "$AICAT_HDR" \
  || fail "ai-catalog: Content-Type is not application/ai-catalog+json"
ETAG=$(grep -i '^etag:' "$AICAT_HDR" | sed -E 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*//' | tr -d '\r')
[ -n "$ETAG" ] || fail "ai-catalog: no ETag header"
jq -e --arg urn "$want_urn" --arg host "$AGENT_HOST" '
  .specVersion == "1.0"
  and .host.identifier == $host
  and .host.displayName == $host
  and ((.entries | map(.identifier) | index($urn)) != null)
' "$AICAT_BODY" >/dev/null || fail "ai-catalog: document shape wrong or this agent's entry missing"
ok "host-complete document lists this ACTIVE agent (ETag $ETAG)"
# Conditional re-fetch with the ETag → 304 Not Modified (cheap AHP poll).
aicat_304=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" \
  -H "If-None-Match: $ETAG" -o /dev/null -w '%{http_code}' \
  "$RA_URL/v2/ans/agents/$AGENT_ID/ai-catalog")
[ "$aicat_304" = "304" ] || fail "ai-catalog: If-None-Match did not yield 304 (got $aicat_304)"
ok "conditional GET (If-None-Match) returned 304 Not Modified"

# ----- summary -----
header "Lifecycle complete (both sides)"
printf "  agentId     %s\n" "$AGENT_ID" >&2
printf "  ansName     %s\n" "$ANS_NAME" >&2
printf "  identityId  %s  (%s)\n" "$IDENTITY_ID" "$IDENTITY_DID" >&2
printf "  saved to    %s\n" "$DATA/last-agent-id" >&2
printf "  root-keys   %s\n" "$ROOT_KEYS_FILE" >&2
printf "  receipt     %s\n" "$RECEIPT_FILE" >&2
printf "\n" >&2
printf "  revoke:     %s\n" "scripts/demo/revoke.sh" >&2
printf "  identities: %s\n" "scripts/demo/identity-lifecycle.sh (every identity operation)" >&2
