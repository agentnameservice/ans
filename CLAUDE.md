# CLAUDE.md

Guidance for any Claude session working in this repository.

## Project

`ans` is an open-source implementation of the Agent Name Service:
a Registration Authority (`ans-ra`), an append-only Merkle-tree
Transparency Log (`ans-tl`), an offline verifier (`ans-verify`),
and a development DNS server (`ans-dns`). Written in Go.

The wire shape (event envelope, SCITT COSE receipts, sumdb-note
checkpoints, `/root-keys` format) is the public contract; offline
verifiers and TL clients depend on it byte-for-byte.

## Non-negotiable quality bar

Everything that lands on `main` must meet production-grade standards:

- **Best practices only.** Idiomatic Go, SOLID, hexagonal
  domain/port/adapter boundaries. No global mutable state, no panics
  in request paths, no swallowed errors, no `fmt.Println`/`log.Printf`
  in library code.
- **Unit test coverage is required.** Every new package ships with
  tests. `internal/domain` stays at 100% of statements.
  `internal/crypto` targets 100% but may sit at ≥95% when the
  remaining uncovered lines are defensive dead-code branches behind
  preceding guards (e.g., `toJWSWireFormat` type-assertion failures
  that `checkAlgMatchesKey` already rejects upstream). Any such
  exception must be annotated in-code with a SAFETY or NOTE comment
  explaining why the branch is unreachable. Overall coverage must
  not drop below 90% as enforced by `make test-cover`, computed
  across `internal/` only — the `cmd/*` entry-point binaries
  (main() + flag wiring + dependency init) are excluded from the
  coverage denominator; their correctness is exercised by
  integration tests and the `scripts/demo/` end-to-end scripts,
  not unit tests.
- **Zero TODOs, hacks, assumptions, or deferred features on `main`.**
  If something is not complete, it does not ship.
- **No placeholder routes.** A route registered on the HTTP router on
  `main` is a committed contract. If the real implementation depends
  on a piece of work that isn't ready, the route is NOT registered.
  A placeholder response on a live route creates a DTO that downstream
  clients will encode against, and replacing it later is a breaking
  change. The correct state is: unimplemented routes are unregistered,
  and the 404 is the signal.
- **Pre-implementation shape diff.** Before writing a handler, DTO,
  or wire-format envelope, locate the corresponding struct/schema in
  the canonical source — the OpenAPI contracts under `spec/` — and
  paste it with a citation into the change description. Every field
  that differs must be called out explicitly. This is how we catch
  shape drift before it reaches the wire, where it would become a
  breaking change for verifiers and clients.
- **`make check` must pass** (`fmt`, `vet`, `golangci-lint`,
  `test-cover`). CI blocks on any failure.
- **No AI `Co-Authored-By:` trailers.** Do not append
  `Co-Authored-By: Claude …`, `Co-Authored-By: Copilot …`, or any
  similar trailer naming an AI assistant on commits in this repo.
  This project follows the Developer Certificate of Origin: every
  author listed on a commit is asserting the DCO, which only a real
  person can do, and noreply@*.com addresses cannot sign off. The
  human running the tooling is the sole author. Use `Signed-off-by:`
  trailers (added automatically by `git commit -s`) to satisfy DCO;
  every commit on `main` must be both DCO-signed-off and GPG-signed.

## V1 vs V2 RA APIs

`ans` serves **both** the V1 and V2 RA APIs side by side. Two
independent lanes from the handler all the way down to the TL:

- **V1 lane**: `POST /v1/agents/register`, `GET /v1/agents/{agentId}`,
  `POST /v1/agents/{agentId}/verify-acme`, `POST
  /v1/agents/{agentId}/verify-dns`, `POST
  /v1/agents/{agentId}/revoke`, the five
  `/v1/agents/{agentId}/certificates/…` cert-management routes, and
  the four `/v1/agents/{agentId}/certificates/server/renewal{,
  /verify-acme}` renewal routes. V1 handlers stamp `SchemaVersion =
  "V1"` on outbox rows so events flow to the TL's `POST
  /v1/internal/agents/event` ingest lane and land as V1 envelopes
  (`eventv1.Envelope`: singleton `identityCert` + rotation-array
  `validIdentityCerts[]`, map-typed `dnsRecordsProvisioned`,
  four-state terminal `eventType` enum).
- **V2 lane**: `POST /v2/ans/agents` + the parallel V2 routes under
  `/v2/ans/agents/{agentId}/*`. V2 handlers stamp `SchemaVersion =
  "V2"` and the events flow to the TL's `POST
  /v2/internal/agents/event` ingest lane.

The two lanes share the same `RegistrationService` and all domain
code; they diverge only at the wire (DTO mapping) and the emit
(outbox `schema_version` column + V1/V2 event envelope builders).
Cross-lane posts are rejected at TL ingest via codec version guards
(a V1 body on the V2 ingest route fails validation with 422
INVALID_EVENT, and vice versa).

Canonical sources of truth:

- `spec/api-spec-v2.yaml` — V2 RA routes. Field names, status codes,
  error shapes.
- `spec/api-spec-tl-v2.yaml` — TL routes. The contract the
  quickstart and `ans-verify` speak.

## Outbox-replay invariant (RA ↔ TL coupling)

The RA → TL event pipeline relies on byte-for-byte replay of a signed
payload on retry, because the TL dedupes by content hash. Invariant:

> When the RA computes an outbox event, it JCS-canonicalizes the
> inner producer Event, signs those bytes with its KeyManager, and
> persists both `innerEventCanonical` AND `producerSignature` in the
> outbox row. A retry by the outbox worker MUST replay the exact
> same bytes and the exact same signature. Regenerating either on
> retry (fresh timestamp → different JCS output → different hash)
> would break TL dedup and force the same event to appear in the log
> twice.

This is enforced by `internal/ra/service/registration.go`
`buildOutboxPayload` — payloads are constructed once, persisted as
JSON blob, and replayed verbatim. Do not add "refresh on retry"
logic without rethinking dedup.

## TL signing-key topology

One ECDSA P-256 key drives **every** outbound TL signature:

- The primary C2SP checkpoint line (signed-note alg `0x02`,
  `logstore.C2SPECDSASigner`).
- The JWS additional-signer line on the same checkpoint
  (`logstore.JWSCheckpointSigner`).
- The outer envelope attestation on every appended event.
- SCITT COSE receipts.
- Status tokens.

`/root-keys` advertises exactly one verification line. Verifiers map
the 4-byte `kid` in a receipt's protected header to that key in
O(1). The single-key topology is intentional — multiple signing
keys would force verifiers to maintain a key-rotation strategy that
adds no security but doubles the implementation burden.

## Default adapters and extension points

The hexagonal layout means every external dependency lives behind a
port interface in `internal/port/`. The defaults target local
development; production deployments can swap any of them at the port
boundary without touching the service layer.

| Concern | Default | Port |
|---|---|---|
| Auth | Static API key (`Authorization: Bearer <apiKey>` and `Authorization: sso-key <apiKey>:<apiSecret>`) and OIDC | `port.Authenticator` |
| Identity certificate issuance | File-backed self-signed CA | `port.IdentityCertificateAuthority` |
| Server certificate issuance | File-backed self-signed CA (`ca.server.type: self`) or external RFC 8555 ACME CA such as Let's Encrypt (`ca.server.type: acme`) for the `serverCsrPEM` path, plus BYOC (`serverCertificatePEM` + chain). Exactly one of CSR/BYOC per registration/renewal. Issuance runs through a certificate-order lifecycle: `CreateOrder` (at registration/renewal submission) returns the provider's domain-control challenges, which are relayed verbatim to the domain owner — ANS never writes DNS or serves challenge files on their behalf; `FinalizeOrder` (at verify-acme, gated on a verified challenge artifact) returns the cert, or `ErrOrderPending` for asynchronous providers (ACME CAs such as Let's Encrypt), in which case re-POSTing verify-acme re-drives the order. | `port.ServerCertificateIssuer` |
| DNS verification | `noop` (quickstart; accepts any state) and `lookup` (real miekg/dns queries with TXT / TLSA / HTTPS support; TLSA responses carry the resolver's DNSSEC AuthenticatedData bit through to the TL attestation as `dnsRecordsProvisioned[].dnssecVerified`) | `port.DNSVerifier` |
| HTTP-01 challenge verification | Plain-HTTP fetch of the owner-published challenge artifact (`/.well-known/acme-challenge/<token>` by default). The verify-acme gate passes when either the DNS-01 TXT record or the HTTP-01 resource verifies. | `port.HTTPChallengeVerifier` |
| Signing keys | File-based ECDSA P-256 PEM | `port.KeyManager` |
| Storage (RA) | SQLite | `port.AgentStore`, `port.CertificateStore`, `port.RenewalStore`, `port.OutboxStore`, `port.UnitOfWork` |
| Storage (TL) | SQLite + Tessera POSIX tile storage | `tl/event` codec interfaces |
| Producer-key trust store | SQLite + `/internal/v1/producer-keys` admin CRUD; YAML `producerKeys[]` for bootstrap seeding | `producerkey.Store` and `producerkey.AdminStore` |
| Scheduler | Go goroutines + `time.Ticker` | (in-process) |

Cloud-KMS, cloud-DB (Postgres / managed RDBMS), and managed-DNS
adapters are good contribution-shaped opportunities — they slot in
at the port boundary.

The `ans-dns` binary ships an authoritative DNS server plus
`install` / `clear` subcommands for end-to-end testing of the
verify-dns flow without touching real DNS infrastructure.

## Wire-format choices

- **Error responses are RFC 7807 Problem Details** (`type`, `title`,
  `status`, `detail`, `code`) on every failure path. Clients should
  read `code` for programmatic handling and `detail` for the
  human-readable explanation.
- **Event envelope `attestations`**: unified `identityCerts[]` and
  `serverCerts[]` arrays (single-cert case is a one-element array)
  plus `dnsRecordsProvisioned[]` as typed `{name, data, type}`
  records. This distinguishes ephemeral ACME challenge records
  (never attested) from production-state records (always attested).
- **TXT-record version format**: bare semver (`1.0.0`) in TXT record
  values. The `v`-prefixed form only lives inside the ANS name's
  hostname label (`ans://v1.0.0.agent.example.com`).
- **Leaf hash**: RFC 6962 `SHA-256(0x00 || canonicalEvent)` over the
  JCS-canonical inner-event bytes — same bytes the RA signed.

## Required commands

- `make build` — builds all four binaries into `bin/`.
- `make test` — unit tests.
- `make test-cover` — coverage report; enforces the 90% gate.
- `make test-race` — race detector.
- `make lint` — `golangci-lint` with the repo config.
- `make check` — `fmt` + `vet` + `lint` + `test-cover`. Must pass
  before every commit.

## Project layout

- `cmd/` — the four binaries (`ans-ra`, `ans-tl`, `ans-verify`,
  `ans-dns`).
- `internal/domain/` + `internal/crypto/` — pure logic; 100%
  coverage expected.
- `internal/port/` — adapter interfaces (KeyManager, AgentStore,
  DNSVerifier, ServerCertificateIssuer, …).
- `internal/adapter/` — concrete adapters (SQLite, file-KMS, OIDC,
  static-key auth, miekg/dns, self-signed CA, docsui, …).
- `internal/ra/` + `internal/tl/` — service layer and HTTP
  handlers, split by RA/TL.
- `spec/` — authoritative OpenAPI contracts.
- `scripts/demo/` — end-to-end lifecycle scripts.
