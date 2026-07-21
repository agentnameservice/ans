#!/usr/bin/env bash
# Shared helpers for the ans demo scripts.
# Sourced by start.sh / run-lifecycle.sh / revoke.sh / stop.sh.
#
# Exports:
#   ROOT         — repo root
#   DATA         — per-demo scratch dir (data/demo)
#   RA_URL       — http://localhost:18080
#   TL_URL       — http://localhost:18081
#   RA_API_KEY   — static API key used by the demo
#
# Functions:
#   header TEXT                  — bold section banner
#   curl_json METHOD PATH [BODY] — pretty-prints request + response,
#                                  echoes response body to stdout so
#                                  callers can capture via $( ... ).
#   wait_ready URL               — poll until /v2/admin/ready returns 200
#   require_cmd CMD              — fail with a clear error if CMD is missing
#
# AI Catalog helpers (shared by catalog.sh + ai-catalog.sh):
#   cat_req METHOD PATH [BODY]   — request; sets CAT_STATUS + CAT_BODY
#   assert_status WANT LABEL     — assert the last cat_req's status
#   cassert LABEL JSON FILTER    — assert a jq boolean filter over JSON
#   cat_activate AGENT_ID        — verify-acme → verify-dns → ACTIVE
#   gen_csrs HOST ANS_NAME       — emit IDENTITY_CSR_PEM + SERVER_CSR_PEM
#   cat_doc AGENT_ID OUTFILE     — GET host-complete ai-catalog document;
#                                  sets CAT_DOC_STATUS/CTYPE/ETAG, body→file
#   cat_doc_inm AGENT_ID ETAG    — conditional GET; sets CAT_DOC_STATUS (304)

set -euo pipefail

# ----- paths -----
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN:-$ROOT/bin}"
DATA="${DATA:-$ROOT/data/demo}"
# Pick up per-session exports start.sh may have persisted (e.g.
# ANS_DNS_ZONE when `--with-dns` was used). Each line is KEY=VALUE.
if [ -f "$DATA/env" ]; then
  # shellcheck disable=SC1091
  set -a; . "$DATA/env"; set +a
fi
RA_URL="${RA_URL:-http://localhost:18080}"
TL_URL="${TL_URL:-http://localhost:18081}"
FINDER_URL="${FINDER_URL:-http://localhost:18082}"
# The RA's externally-reachable TL base (config tl-client.public-base-url,
# which MUST be https). The AI Catalog entry's badgeUrl + SCITT-receipt
# attestation URI are built from this — same host:port as TL_URL in the
# demo, https scheme. Mirrors config/defaults.go's PublicBaseURL default.
TL_PUBLIC_URL="${TL_PUBLIC_URL:-https://localhost:18081}"
RA_API_KEY="${RA_API_KEY:-ans-dev-key-change-me}"
# ANS SDKs send `Authorization: sso-key <apiKey>:<apiSecret>` — the
# reference RA's format. The demo RA accepts both `Bearer` (the
# format used below for curl_json) and `sso-key` when an apiSecret
# is configured. Keep the secret configured by default so SDK-based
# tests work against a freshly-started demo stack.
RA_API_SECRET="${RA_API_SECRET:-ans-dev-secret-change-me}"
TL_API_KEY="${TL_API_KEY:-tl-internal-key}"

# ----- colors (disabled when stderr isn't a tty) -----
if [ -t 2 ]; then
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RESET=$'\033[0m'
  JQ_COLOR="-C"
else
  C_CYAN='' C_GREEN='' C_YELLOW='' C_RED='' C_DIM='' C_BOLD='' C_RESET=''
  JQ_COLOR=""
fi

# ----- display helpers (all to stderr so stdout stays capturable) -----

header() {
  printf "\n${C_BOLD}${C_CYAN}━━━ %s ━━━${C_RESET}\n" "$1" >&2
}

note() {
  printf "${C_DIM}%s${C_RESET}\n" "$1" >&2
}

ok() {
  printf "${C_GREEN}✔${C_RESET} %s\n" "$1" >&2
}

warn() {
  printf "${C_YELLOW}⚠${C_RESET} %s\n" "$1" >&2
}

fail() {
  printf "${C_RED}✘${C_RESET} %s\n" "$1" >&2
  exit 1
}

# require_cmd CMD — bail if CMD isn't on $PATH.
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

# pretty-print JSON through jq; fall back to raw if jq can't parse.
pretty_json() {
  local input
  input=$(cat)
  if [ -z "$input" ]; then
    return 0
  fi
  # shellcheck disable=SC2086  # JQ_COLOR is intentionally empty or "-C"
  if printf '%s' "$input" | jq $JQ_COLOR . 2>/dev/null; then
    return 0
  fi
  printf '%s\n' "$input"
}

# curl_json METHOD PATH [BODY]
#
#   METHOD  — GET / POST / DELETE / etc.
#   PATH    — request path, e.g. /v2/ans/agents
#   BODY    — optional JSON body (string). Omit for GET/no-body requests.
#
# Display output goes to stderr (shown in the terminal). The raw
# response body is printed to stdout so callers can capture it:
#
#     RESP=$(curl_json POST /v2/ans/agents "$REQ")
#     AGENT_ID=$(echo "$RESP" | jq -r .agentId)
#
# Returns 0 on any HTTP status (including 4xx/5xx) so the calling
# script can decide how to react. `set -e` only aborts on non-HTTP
# errors like DNS / connection refused.
curl_json() {
  local method="$1" path="$2" body="${3:-}"
  local url="${RA_URL}${path}"

  printf "${C_DIM}→ %s %s${C_RESET}\n" "$method" "$url" >&2
  if [ -n "$body" ]; then
    printf '%s' "$body" | pretty_json >&2
  fi

  local tmp
  tmp=$(mktemp)
  local status
  if [ -n "$body" ]; then
    status=$(curl -sS -X "$method" \
      -H "Authorization: Bearer $RA_API_KEY" \
      -H "Content-Type: application/json" \
      -o "$tmp" -w "%{http_code}" \
      --data "$body" \
      "$url") || true
  else
    status=$(curl -sS -X "$method" \
      -H "Authorization: Bearer $RA_API_KEY" \
      -o "$tmp" -w "%{http_code}" \
      "$url") || true
  fi

  # Expose the status to callers via LAST_HTTP_STATUS so they can
  # use `assert_2xx` after critical lifecycle steps. curl_json
  # itself never aborts on HTTP errors — that's the caller's job.
  LAST_HTTP_STATUS="$status"

  local color="$C_GREEN"
  if [ "$status" -ge 400 ]; then
    color="$C_YELLOW"
  fi
  printf "${color}← %s${C_RESET}\n" "$status" >&2
  pretty_json <"$tmp" >&2

  # Echo the raw body on stdout for capture.
  cat "$tmp"
  rm -f "$tmp"
}

# curl_tl METHOD PATH [BODY]
#
# Sibling of curl_json but talks to the TL (different base URL and
# API key). The TL config for the demo has `public-read: true`, so
# GETs work without auth; we include the bearer anyway for symmetry.
curl_tl() {
  local method="$1" path="$2" body="${3:-}"
  local url="${TL_URL}${path}"

  printf "${C_DIM}→ %s %s${C_RESET}\n" "$method" "$url" >&2
  if [ -n "$body" ]; then
    printf '%s' "$body" | pretty_json >&2
  fi

  local tmp
  tmp=$(mktemp)
  local status
  if [ -n "$body" ]; then
    status=$(curl -sS -X "$method" \
      -H "Authorization: Bearer $TL_API_KEY" \
      -H "Content-Type: application/json" \
      -o "$tmp" -w "%{http_code}" \
      --data "$body" \
      "$url") || true
  else
    status=$(curl -sS -X "$method" \
      -H "Authorization: Bearer $TL_API_KEY" \
      -o "$tmp" -w "%{http_code}" \
      "$url") || true
  fi

  LAST_HTTP_STATUS="$status"

  local color="$C_GREEN"
  if [ "$status" -ge 400 ]; then
    color="$C_YELLOW"
  fi
  printf "${color}← %s${C_RESET}\n" "$status" >&2
  pretty_json <"$tmp" >&2

  cat "$tmp"
  rm -f "$tmp"
}

# curl_tl_binary METHOD PATH OUTFILE
#
# Same as curl_tl but writes the response body verbatim to OUTFILE
# (binary-safe — no JSON pretty-printing). Intended for the SCITT
# receipt endpoint which returns application/scitt-receipt+cose
# bytes that a JSON pipe would corrupt. Prints the HTTP status +
# response Content-Type to stderr and echoes only the status code
# on stdout so callers can conditionally act on it.
curl_tl_binary() {
  local method="$1" path="$2" outfile="$3"
  local url="${TL_URL}${path}"

  printf "${C_DIM}→ %s %s${C_RESET}\n" "$method" "$url" >&2

  local hdrfile
  hdrfile=$(mktemp)
  local status
  status=$(curl -sS -X "$method" \
    -H "Authorization: Bearer $TL_API_KEY" \
    -D "$hdrfile" \
    -o "$outfile" -w "%{http_code}" \
    "$url") || true

  local color="$C_GREEN"
  if [ "$status" -ge 400 ]; then
    color="$C_YELLOW"
  fi
  printf "${color}← %s${C_RESET}\n" "$status" >&2
  # Echo only the Content-Type header to stderr for visibility.
  grep -i '^content-type:' "$hdrfile" | sed 's/\r$//' >&2 || true
  rm -f "$hdrfile"

  # Echo only the status on stdout.
  printf '%s' "$status"
}

# curl_tl_text METHOD PATH
#
# Same as curl_tl but treats the body as plain text (no JSON pretty
# print). Used for /root-keys which returns sumdb-note verification
# lines (one per key) — a jq pipe would silently drop them. Body is
# written to both stderr (for visibility) and stdout (so callers can
# capture it via $( ... )).
curl_tl_text() {
  local method="$1" path="$2"
  local url="${TL_URL}${path}"

  printf "${C_DIM}→ %s %s${C_RESET}\n" "$method" "$url" >&2

  local tmp
  tmp=$(mktemp)
  local status
  status=$(curl -sS -X "$method" \
    -H "Authorization: Bearer $TL_API_KEY" \
    -o "$tmp" -w "%{http_code}" \
    "$url") || true

  LAST_HTTP_STATUS="$status"

  local color="$C_GREEN"
  if [ "$status" -ge 400 ]; then
    color="$C_YELLOW"
  fi
  printf "${color}← %s${C_RESET}\n" "$status" >&2
  cat "$tmp" >&2

  cat "$tmp"
  rm -f "$tmp"
}

# assert_2xx [CONTEXT]
#
# Fails (exit 1) if the most recent curl_json / curl_tl /
# curl_tl_text call returned a non-2xx HTTP status. Use after
# critical lifecycle steps where a 4xx/5xx means the demo has gone
# off the rails (e.g. verify-acme, verify-dns, register, revoke).
# CONTEXT is an optional human-readable label included in the
# failure message; defaults to "request" if omitted.
#
# `curl_json` is documented to swallow HTTP errors so callers can
# decide; this helper is the explicit "decide it's fatal" path.
assert_2xx() {
  local context="${1:-request}"
  if [ -z "${LAST_HTTP_STATUS:-}" ]; then
    fail "assert_2xx: no prior curl_json/curl_tl/curl_tl_text call"
  fi
  if [ "$LAST_HTTP_STATUS" -lt 200 ] || [ "$LAST_HTTP_STATUS" -ge 300 ]; then
    fail "$context: HTTP $LAST_HTTP_STATUS (expected 2xx)"
  fi
}

# poll_tl_audit AGENT_ID EXPECTED_COUNT [TIMEOUT_SECONDS]
#
# Polls /v1/agents/{agentId}/audit until it shows at least
# EXPECTED_COUNT events, or timeout elapses. The outbox worker's
# poll interval is ~2s so 30s is plenty.
poll_tl_audit() {
  local agent_id="$1" expected="$2" timeout="${3:-30}"
  local i=0 count withproof
  while [ "$i" -lt "$timeout" ]; do
    # TL audit response: { records: [TransparencyLog, ...] }.
    # We wait for (a) enough records AND (b) the newest record to
    # carry a merkleProof — otherwise the checkpoint might not yet
    # cover the latest leaf and downstream badge queries look empty.
    local resp
    resp=$(curl -sSf -H "Authorization: Bearer $TL_API_KEY" \
      "$TL_URL/v1/agents/$agent_id/audit" 2>/dev/null || true)
    count=$(printf '%s' "$resp" | jq -r '(.records | length) // 0')
    withproof=$(printf '%s' "$resp" | jq -r '[.records[]? | select(.merkleProof)] | length // 0')
    if [ "${count:-0}" -ge "$expected" ] && [ "${withproof:-0}" -ge "$expected" ]; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  fail "TL not ready for $agent_id in ${timeout}s (records=${count:-0}, with merkle proof=${withproof:-0}; want $expected of each)"
}

# assert_tl_identity_audit IDENTITY_ID EXPECTED_COUNT [TIMEOUT_SECONDS]
#
# Sibling of poll_tl_audit for the identity stream — with ONE crucial
# difference: the RECORD COUNT is asserted on the very first read, no
# polling. Identity operations are seal-before-success (design
# §5.6.1): the RA reports success only after the TL acknowledges the
# seal, so the events MUST already be in the log the moment the API
# returned — a missing record here is a seal-before-success
# regression, not a timing flake. Merkle INCLUSION PROOFS are the one
# thing allowed to lag: proofs are built against the latest published
# checkpoint, and checkpoint publication is cadence-based (one root,
# one cadence — unchanged by this design), so proof coverage alone is
# polled briefly.
assert_tl_identity_audit() {
  local identity_id="$1" expected="$2" timeout="${3:-15}"
  local resp count withproof
  resp=$(curl -sSf -H "Authorization: Bearer $TL_API_KEY" \
    "$TL_URL/v1/identities/$identity_id/audit" 2>/dev/null || true)
  count=$(printf '%s' "$resp" | jq -r '(.records | length) // 0')
  if [ "${count:-0}" -lt "$expected" ]; then
    fail "seal-before-success violated for identity $identity_id: audit shows ${count:-0} records immediately after the API returned; want $expected"
  fi
  local i=0
  while [ "$i" -lt "$timeout" ]; do
    withproof=$(printf '%s' "$resp" | jq -r '[.records[]? | select(.merkleProof)] | length // 0')
    if [ "${withproof:-0}" -ge "$expected" ]; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
    resp=$(curl -sSf -H "Authorization: Bearer $TL_API_KEY" \
      "$TL_URL/v1/identities/$identity_id/audit" 2>/dev/null || true)
  done
  fail "checkpoint never covered identity $identity_id's leaves in ${timeout}s (records=${count}, with proof=${withproof:-0}; want $expected)"
}

# ──────────────────────────────────────────────────────────────────
# AI Catalog demo helpers (shared by catalog.sh and ai-catalog.sh)
# ──────────────────────────────────────────────────────────────────

# cat_req METHOD PATH [BODY] — issue an RA request and set CAT_STATUS +
# CAT_BODY in THIS shell. Unlike curl_json (whose LAST_HTTP_STATUS is lost
# when the call is captured in a $(...) subshell), this keeps body and
# status together so a caller can assert both — exactly what the catalog
# routes' 200-vs-422 paths need.
cat_req() {
  local method="$1" path="$2" body="${3:-}" tmp
  tmp=$(mktemp)
  if [ -n "$body" ]; then
    CAT_STATUS=$(curl -sS -X "$method" \
      -H "Authorization: Bearer $RA_API_KEY" \
      -H "Content-Type: application/json" \
      --data "$body" -o "$tmp" -w '%{http_code}' "$RA_URL$path" || true)
  else
    CAT_STATUS=$(curl -sS -X "$method" \
      -H "Authorization: Bearer $RA_API_KEY" \
      -o "$tmp" -w '%{http_code}' "$RA_URL$path" || true)
  fi
  CAT_BODY=$(cat "$tmp")
  rm -f "$tmp"
  local color="$C_GREEN"
  [ "${CAT_STATUS:-0}" -ge 400 ] && color="$C_YELLOW"
  printf "${C_DIM}→ %s %s${C_RESET}  ${color}← %s${C_RESET}\n" "$method" "$path" "$CAT_STATUS" >&2
  printf '%s' "$CAT_BODY" | pretty_json >&2
}

# assert_status WANT LABEL — fail unless the last cat_req returned WANT.
assert_status() {
  [ "${CAT_STATUS:-}" = "$1" ] || fail "$2: expected HTTP $1, got ${CAT_STATUS:-<none>}"
}

# cassert LABEL JSON JQ_FILTER — fail unless the jq boolean filter is
# true against JSON. Keeps the per-field assertions terse and readable.
cassert() {
  local label="$1" json="$2" filter="$3"
  if printf '%s' "$json" | jq -e "$filter" >/dev/null 2>&1; then
    ok "$label"
  else
    printf '%s' "$json" | pretty_json >&2
    fail "assertion failed: $label  (filter: $filter)"
  fi
}

# cat_activate AGENT_ID — drive an agent to ACTIVE (verify-acme →
# verify-dns). The demo's noop DNS verifier accepts any state, so both
# steps succeed. A catalog entry exists only once the agent is ACTIVE.
cat_activate() {
  local id="$1"
  cat_req POST "/v2/ans/agents/$id/verify-acme"
  assert_status 202 "verify-acme $id"
  cat_req POST "/v2/ans/agents/$id/verify-dns"
  assert_status 202 "verify-dns $id"
  ok "agent $id is ACTIVE"
}

# gen_csrs HOST ANS_NAME — generate an identity CSR (URI SAN = ANS name)
# and a server CSR (DNS SAN = host), exporting IDENTITY_CSR_PEM and
# SERVER_CSR_PEM. Mirrors register.sh.
gen_csrs() {
  local host="$1" ans="$2"
  local dir="$DATA/csr-catalog/$host"
  rm -rf "$dir"
  mkdir -p "$dir"
  cat >"$dir/identity.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $ans
[v3_req]
subjectAltName = URI:$ans
CNF
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/identity.key" 2>/dev/null
  openssl req -new -key "$dir/identity.key" -config "$dir/identity.cnf" -out "$dir/identity.csr" 2>/dev/null
  IDENTITY_CSR_PEM=$(cat "$dir/identity.csr")

  cat >"$dir/server.cnf" <<CNF
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no
[req_dn]
CN = $host
[v3_req]
subjectAltName = DNS:$host
CNF
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/server.key" 2>/dev/null
  openssl req -new -key "$dir/server.key" -config "$dir/server.cnf" -out "$dir/server.csr" 2>/dev/null
  SERVER_CSR_PEM=$(cat "$dir/server.csr")
}

# cat_doc AGENT_ID OUTFILE — GET the host-complete AI Catalog document for
# the host AGENT_ID belongs to, writing the body to OUTFILE and setting
# CAT_DOC_STATUS, CAT_DOC_CTYPE, and CAT_DOC_ETAG from the response headers.
# This is the literal ai-catalog.json an Agent-Host Provider republishes
# verbatim at https://{agentHost}/.well-known/ai-catalog.json.
#
# Fetched as the authenticated owner: this RA deployment owner-scopes the
# catalog routes (ReadOwnership), whereas IMPL §6 models them as public.
# A public deployment would simply drop the Authorization header; every
# document assertion below is otherwise identical.
cat_doc() {
  local id="$1" outfile="$2" hdr
  hdr=$(mktemp)
  CAT_DOC_STATUS=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" \
    -D "$hdr" -o "$outfile" -w '%{http_code}' \
    "$RA_URL/v2/ans/agents/$id/ai-catalog" || true)
  # Guard the grep so a missing header yields an empty var rather than
  # tripping `set -o pipefail` (a non-200 response may omit ETag).
  CAT_DOC_CTYPE=$({ grep -i '^content-type:' "$hdr" || true; } | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
  CAT_DOC_ETAG=$({ grep -i '^etag:' "$hdr" || true; } | sed -E 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*//' | tr -d '\r')
  rm -f "$hdr"
  local color="$C_GREEN"
  [ "${CAT_DOC_STATUS:-0}" -ge 400 ] && color="$C_YELLOW"
  printf "${C_DIM}→ GET /v2/ans/agents/%s/ai-catalog${C_RESET}  ${color}← %s${C_RESET}\n" "$id" "$CAT_DOC_STATUS" >&2
}

# cat_doc_inm AGENT_ID ETAG — conditional GET with If-None-Match; sets
# CAT_DOC_STATUS (304 when the document is byte-identical to ETAG). Lets an
# AHP poll the refresh target cheaply.
cat_doc_inm() {
  local id="$1" etag="$2"
  CAT_DOC_STATUS=$(curl -sS -H "Authorization: Bearer $RA_API_KEY" \
    -H "If-None-Match: $etag" -o /dev/null -w '%{http_code}' \
    "$RA_URL/v2/ans/agents/$id/ai-catalog" || true)
  printf "${C_DIM}→ GET /v2/ans/agents/%s/ai-catalog  (If-None-Match)${C_RESET}  ← %s\n" "$id" "$CAT_DOC_STATUS" >&2
}

# wait_ready URL [TIMEOUT_SECONDS]
#
# Polls URL once a second until it returns 200, or TIMEOUT expires.
wait_ready() {
  local url="$1"
  local timeout="${2:-30}"
  local i=0
  while [ "$i" -lt "$timeout" ]; do
    if curl -sSf "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  fail "timed out waiting for $url (${timeout}s)"
}
