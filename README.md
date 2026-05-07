# ans — Agent Name Service

`ans` is an open-source implementation of the Agent Name Service
(ANS), a registry + transparency log for discovering and verifying
AI agents by name. Every registered agent gets:

- A versioned DNS-style name: `ans://v1.0.0.my-agent.example.com`
- A publicly-auditable event history (append-only Merkle log)
- SCITT COSE_Sign1 receipts proving the agent's state at a point in time
- Identity certificates signed by a private CA for mTLS between agents
- Optional BYOC server certificates + pinned TLSA records

The wire shape — event envelope, SCITT COSE receipts, sumdb-note
checkpoints, `/root-keys` format — is the public contract. Offline
verifiers and TL clients depend on it byte-for-byte.

## Binaries

| Binary | Port | Role |
| --- | --- | --- |
| `ans-ra` | 18080 | Registration Authority — accepts registrations, issues identity certs, tracks lifecycle |
| `ans-tl` | 18081 | Transparency Log — durable Merkle-tree append log, serves badges + receipts |
| `ans-verify` | — | Offline CLI verifier for SCITT COSE receipts and status tokens |
| `ans-dns` | 15353 | Dev-only authoritative DNS server with `install` / `clear` subcommands for local end-to-end verify-dns testing |

Both daemons (`ans-ra`, `ans-tl`) serve Swagger UI at `/docs` —
browse <http://localhost:18080/docs> (RA) and
<http://localhost:18081/docs> (TL) after `make build &&
scripts/demo/start.sh`. The raw OpenAPI bytes live at
`/docs/openapi.yaml` on each host.

To call protected endpoints from Swagger UI's "Try it out" button:
click **Authorize** in the top-right and paste the static API key.
The quickstart defaults are:

- RA: `ans-dev-key-change-me` (from `config/ra-local.yaml`)
- TL: `tl-internal-key` (from `config/tl-local.yaml`)

The RA writes signed events; the TL verifies, ingests, and publishes
them. An operator can run just the TL (for read-only verification) or
both together (full registry).

## Quickstart (60 seconds)

```bash
# Prereqs: Go 1.26+, openssl, curl, jq
git clone https://github.com/godaddy/ans
cd ans
make build                        # builds bin/ans-ra, bin/ans-tl, bin/ans-verify, bin/ans-dns
scripts/demo/start.sh             # starts both daemons against ./data/demo
scripts/demo/run-lifecycle.sh     # registers an agent, verifies the receipt end-to-end
```

Expected output (last few lines):

```
━━━ 13. Offline verify (bin/ans-verify) ━━━
  ✓ Fetched 2 verification key(s) from /root-keys
  ✓ 1602 bytes (Content-Type: application/scitt-receipt+cose)
  ✓ VERIFIED (kid <8-char-hex> matched key directly)
```

Tear down with `scripts/demo/stop.sh` or `scripts/demo/stop.sh --clean`
to wipe the data directory.

### Local DNS testing with `ans-dns`

The default DNS verifier in `config/ra-local.yaml` is `noop`, which
accepts any DNS state. To exercise the real `lookup` verifier
end-to-end without touching public DNS, run the bundled
authoritative server:

```bash
# In one terminal: start the dev DNS server (serves ./data/demo/dns)
bin/ans-dns serve --addr 127.0.0.1:15353

# In another: install the records the RA expects after verify-acme
bin/ans-dns install --api-key <api-key> http://localhost:18080 <agentId>

# Switch ra-local.yaml to dns.type=lookup pointed at 127.0.0.1:15353
# and re-run verify-dns; ans-tl observes the AGENT_REGISTERED event.

# Tear down:
bin/ans-dns clear <agentId>
```

`ans-dns` is dev-only. Production deployments use the `lookup`
verifier against the operator's existing authoritative DNS.

## Docker

```bash
# Build images for the long-running daemons
make docker-build

# Or bring the stack up with compose (RA + TL, with healthchecks)
docker compose up --build
```

Compose persists `ra-data`, `ra-keys`, and `tl-data` volumes so
restarts are cheap; `docker compose down -v` wipes them. `ans-verify`
and `ans-dns` are local-development binaries and ship from `make
build` only — they are not in the compose stack.

## Architecture

Hexagonal / ports-and-adapters. The domain model (`internal/domain`)
has zero framework or storage dependencies. Services depend on port
interfaces (`internal/port`) which adapters in `internal/adapter/`
implement against real drivers.

```
cmd/ans-ra/main.go ───────┐
                          ├─► internal/ra/service ─► port.AgentStore     ─► internal/adapter/store/sqlite
cmd/ans-tl/main.go ───────┤                          port.KeyManager     ─► internal/adapter/keymanager
                          │                          port.DNSVerifier    ─► internal/adapter/dns
                          └─► internal/tl/service ─► port.RenewalStore   ─► …

cmd/ans-verify/main.go ─► internal/tl/receipt   (Verify, ExtractKID, ComputeLeafHash)
cmd/ans-dns/main.go    ─► miekg/dns authoritative server + RA-driven record install/clear
```

See `spec/api-spec-v2.yaml` + `spec/api-spec-tl-v2.yaml` for the
authoritative OpenAPI contracts.

## Core contracts

**Event envelope (signed on the RA side):**

```json
{
  "payload": {
    "logId": "<uuid>",
    "producer": {
      "event": { "ansId": "...", "ansName": "ans://...", "eventType": "AGENT_REGISTRATION", ... },
      "keyId": "ans-ra-signer",
      "signature": "<detached JWS over JCS(event)>"
    }
  },
  "schemaVersion": "V1",
  "signature": "<TL attestation JWS>",
  "status": "ACTIVE"
}
```

**Receipts (SCITT COSE_Sign1, RFC 8152 tag 18):**

- Protected header: `{1:-7 (ES256), 4:<kid 4-byte SPKI hash>, 395:1 (RFC 9162), 15:{1:<issuer>, 6:<iat>}}`
- Unprotected header: `{396:{-1:treeSize, -2:leafIndex, -3:path[][], -4:rootHash}}`
- Payload: the JCS-canonical event bytes (the *same bytes* the leaf hash is computed over)
- Signature: ES256 over the RFC 8152 §4.4 Sig_structure

**Leaf hash:** RFC 6962 — `SHA-256(0x00 || payload)`.

**Root-keys endpoint** (`GET /root-keys`) emits the
sumdb-note verification-key format (one line per key):

```
<origin>+<keyhash-hex>+<base64(0x02 || SPKI-DER)>
```

where `keyhash-hex` is the first 4 bytes of `SHA-256(SPKI-DER)` as
zero-padded big-endian hex. Verifiers match this against the `kid`
in the receipt's protected header for O(1) key lookup.

The TL signs every outbound artifact (checkpoints, attestations,
receipts, status tokens) with a single ECDSA P-256 key. `/root-keys`
advertises exactly one line.

## Verification workflow

Any third party can verify an agent's state cryptographically without
trusting the TL operator beyond the advertised verifier keys:

```bash
# Fetch receipt + keys + verify
ans-verify -url https://tl.example.com -agent <agentId>

# Or, air-gapped (receipt already on disk, key pinned in CI):
ans-verify -pubkey ./trusted-tl.pub -agent <agentId> \
  -url file://./receipt.cbor
```

The verifier:

1. Fetches `/root-keys` (or reads a pinned PEM).
2. Fetches the receipt CBOR.
3. Parses COSE_Sign1, extracts the inclusion proof from label 396.
4. Maps the receipt's 4-byte `kid` → verifier key in O(1).
5. Walks the Merkle path from `SHA-256(0x00 || payload)` to
   `rootHash`; rejects any mismatch.
6. ES256-verifies the signature over Sig_structure.
7. Cross-checks that the receipt's computed leaf hash matches the
   badge's `merkleProof.leafHash` (same leaf in the same tree).

## Configuration

Both daemons read YAML via [koanf](https://github.com/knadh/koanf).
The shipped quickstart configs are under `config/`:

- `config/ra-local.yaml` — local-filesystem dev config (SQLite, self-CA, noop DNS)
- `config/tl-local.yaml` — same for the TL
- `config/ra-docker.yaml` / `config/tl-docker.yaml` — compose-friendly paths + log format

Every YAML key is overridable via env vars using the `_` → `.` dotted
form (e.g. `ANS_RA_SERVER__PORT=18090`).

## Auth

Two providers ship today:

- **Static API key** (quickstart): accepts both `Authorization: Bearer
  <key>` (ans-native form) and `Authorization: sso-key
  <apiKey>:<apiSecret>` (the form generated SDK clients use). The
  static key is treated as admin, so it can hit
  `/internal/v1/producer-keys`.
- **OIDC**: standard bearer-token validation against an issuer URL.
  Configure admin groups with `auth.oidc.admin-groups[]`.

Every GET under `/v1/agents/`, `/v1/log/`, and the tlog-tiles paths
(`/checkpoint`, `/root-keys`, `/tile/*`) is anonymous when
`auth.public-read: true` (the default for the TL quickstart config) —
verifiers never need credentials.

## Pluggable architecture

Every external dependency lives behind a port interface in
`internal/port/`. Defaults target local development; you can swap any
of them at the port boundary without touching the service layer.

| Concern | Default adapter | Common production swap |
| --- | --- | --- |
| Auth | Static API key + OIDC | OIDC against your IdP |
| Identity cert issuance | File-backed self-signed CA | Cloud KMS-backed CA |
| Server cert issuance | Self-signed CA + BYOC PEM | ACME / public CA / BYOC PEM |
| DNS verification | `noop` and `lookup` (real miekg/dns queries with DNSSEC AD-bit propagation) | `lookup` against your authoritative DNS |
| Signing keys | File-based ECDSA P-256 | Cloud KMS adapter |
| Storage | SQLite | Postgres / managed RDBMS |

Cloud-KMS, Postgres, and managed-DNS adapters are
contribution-shaped — see `CONTRIBUTING.md`.

## Development

```bash
make test         # unit tests
make test-cover   # with coverage, enforces the repo gate (≥90%)
make test-race    # race detector
make check        # fmt + vet + lint + test-cover (pre-commit gate)
```

Test coverage targets: 100% on `internal/domain` and `internal/crypto`
(with annotated SAFETY exceptions for unreachable defensive
branches), ≥90% overall across `internal/` (enforced by `make
test-cover`). Adapter packages under `internal/adapter/` are the
primary remaining gap — contributions welcome, see
`CONTRIBUTING.md`.

Contributing guide: [`CONTRIBUTING.md`](CONTRIBUTING.md).
Project conventions for code generation tools: [`CLAUDE.md`](CLAUDE.md).

## Status

Shipped: full V1 + V2 RA surface (register, verify-acme, verify-dns,
revoke, list, detail, identity/server cert GET + POST, CSR status,
renewal lifecycle with BYOC + CSR paths, renewal expiry sweep) • TL
ingest, badge, audit, SCITT COSE receipts (tag 18, ES256), SCITT
status tokens (1h TTL, terminal-state aware), root-keys (sumdb-note
format), JSON + raw checkpoint, paginated checkpoint history, schema
lookup, Merkle tiles • Producer-key admin CRUD
(`/internal/v1/producer-keys`) • `ans-verify` CLI that fetches +
verifies both receipts and status tokens • `ans-dns` dev DNS server
with `install` / `clear` for verify-dns end-to-end testing.

Follow-up opportunities (community): cloud-KMS / Postgres /
managed-DNS adapters, real ACME DNS-01 verifier wiring, additional
schema versions.

## License

MIT License. See [LICENSE](LICENSE).
