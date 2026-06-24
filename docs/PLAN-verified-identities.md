# Implementation Plan — Verified Identities (the "who" behind an agent)

> **As-built notes (2026-06-10).** The implementation landed per this
> plan with three deliberate deviations, each truer to the design's
> own principles than the plan's first sketch:
>
> 1. **TL storage: one table, not two.** Instead of a parallel
>    `tl_identity_events` table, `tl_events` gained a nullable
>    `identity_id` column (+ partial index) and a
>    `tl_identity_event_agents` fan-out table for the link read-join
>    — the literal embodiment of "streams are read indexes over one
>    log". One mirror, one badge builder, one receipt path, one
>    Merkle-proof path; the identity envelope exposes its index keys
>    through an optional capability interface so `event.View` stayed
>    frozen for existing implementers.
> 2. **Key-type support: everything the JWS layer verifies.**
>    Ed25519 (EdDSA), ECDSA P-256 (ES256), and RSA ≥ 2048 (RS256)
>    are all accepted for identity proofs — the allowlist names
>    exactly what jws.go implements. Keys that structurally cannot
>    prove control are rejected with precise errors: X25519 is a
>    key-agreement key; secp256k1 and P-384/521 have no verifier
>    here (adding one is the gate for admitting them).
> 2a. **Seals quote the verification method verbatim.** Sealed
>    `ProvenKey` = `{verificationMethod, signedProof}` where
>    `verificationMethod` is the DID document's object exactly as
>    served — member-for-member, values untouched (JCS signing
>    preserves member values, so the quoted material survives
>    intact). Nothing derived, re-encoded, or normalized enters a
>    seal; thumbprints are compute-at-read conveniences. The badge
>    join surfaces `provenKeyIds` (verification-method ids). did:key
>    seals the method-spec-derived Multikey entry whose key material
>    is the method-specific id verbatim from the identifier. The
>    postponed lei kind remains the deliberate exception (subject
>    AID + thumbprint only — no document to quote, ACDC is PII, the
>    KEL is the authoritative key history).
> 3. **No localhost did:web host for development.** The hardened web
>    resolver pins fetches to port 443, requires WebPKI, and its SSRF
>    denylist rejects loopback — a local did.json server is
>    structurally unusable with it, by design. Local development is
>    the noop resolver (real JWS verification, waived live-document
>    binding); the web resolver is covered by TLS-server tests at the
>    parse seam plus dialer-level SSRF tests.

| | |
|---|---|
| **Source design** | `DESIGN-multi-identity-anchors.md` rev 4 (2026-06-10, who/what pivot) — design of record from the ans-registry working sessions |
| **Target repo** | `godaddy/ans` (this repo), branched from `main` @ `d94d531` |
| **Scope** | Identity aggregate + proof-of-control gate (did:web, did:key), identity links, the five `IDENTITY_*` TL events on a dedicated ingest lane, TL identity read surface + computed badge join, offline verification. **lei postponed** (design §3.6/§10.7 retained as design of record). |
| **Pattern requirement** | Every outbound I/O dependency ships a **noop adapter for local/quickstart** and a **fully functional adapter selected by config** — exactly the `dns.type: noop \| lookup` precedent (`cmd/ans-ra/main.go` `selectDNSVerifier`, `internal/adapter/dns/{noop,lookup}.go`). |

---

## 0. Design → this-repo mapping

The design doc was written against the `ans-registry-poc` codebase. Every code
anchor it cites maps onto this repo as follows; the *wire shapes and rules* in
the design (§3.2 IdentityProofInput, §5.3 bodies, §5.5 events, §5.7 schema)
carry over verbatim.

| Design reference | This repo |
|---|---|
| `AgentRegistration` aggregate, `agent.go:68/129/150/155` | `internal/domain/agent.go:54-179` (`AgentRegistration`, `NewRegistration`) |
| Status machine `status.go:62-71` | `internal/domain/status.go` (`ValidTransitions`) |
| `lifecycle.go` `VerifyACME` | `internal/ra/service/registration.go` + `lifecycle.go` (`VerifyACME`/`VerifyDNS`) |
| TL `event.go:92-102` `Type.IsValid()` closed switch | `internal/tl/event/event.go:92-102` — **stays frozen**; identity events get their own package (see §2.1) |
| V1 enum frozen (`internal/tl/event/v1/event.go:50-65`) | same path here — untouched |
| `migrations/001_initial.sql` (RA) | `internal/adapter/store/sqlite/migrations/` — latest is `005_agent_acme_challenge.sql`, so the identity migration is **006** |
| TL migrations | `internal/adapter/store/sqlitetl/migrations/` — latest is `002_producer_keys.sql`, so identity events migration is **003** |
| `spec/api-spec-v2.yaml`, `spec/api-spec-tl-v2.yaml` | same paths — the canonical contracts; every PR pastes its shape diff per CLAUDE.md |
| Producer lane / outbox | `internal/ra/service/registration.go` (`signAndMarshalPayload`, `enqueueTLEvent`), `internal/ra/outbox/worker.go`, `internal/adapter/tlclient/client.go` |
| `noop` vs real verification | `internal/adapter/dns/noop.go` / `lookup.go`, selected by `cfg.DNS.Type` in `cmd/ans-ra/main.go:410-421` |

One deliberate divergence from the design text: design §5.5 says the V2
`Type.IsValid()` switch "MUST widen." In this repo the cleaner equivalent is a
**parallel identity event package** with its own closed five-token enum — the
agent codec stays byte-frozen, and the cross-lane guard falls out of each
codec's `Validate()` (an `IDENTITY_*` token fails the agent enum **and** lacks
`ansId`; an `AGENT_*` token fails the identity enum and lacks `identityId` —
both 422 `INVALID_EVENT`). This satisfies the same normative requirement
(identity tokens accepted on the identity lane, V1 lane frozen) without
touching the existing agent contract.

---

## 1. The noop/full pattern, applied per kind

The single design invariant: **the RA seals an identity attestation only
after control is proven** — a challenge-bound signature verified against the
identifier's *authoritative* key. The only outbound I/O in Slices 1–3 is the
did:web `did.json` HTTPS fetch. That fetch is the port.

| Kind | Outbound I/O | noop adapter (quickstart) | full adapter (configured) |
|---|---|---|---|
| `did:key` | **none** — key decodes from the DID string | not needed; real crypto runs locally out of the box | same code path |
| `did:web` | HTTPS GET of `did.json` (registrant-steered host) | `didresolver.Noop` — never dials; synthesizes the DID document from the submitted proofs' embedded keys (below) | `didresolver.Web` — hardened fetcher: WebPKI, SSRF dialer guards, 5 s timeout, size cap, ≤5 same-registrable-domain redirects (design §3.7) |
| `lei` *(postponed)* | GLEIF L1 GET + internal `vlei-verifier` | `Noop` variants of both clients | real HTTP clients behind `port.LEIControlVerifier` |

**Noop semantics — mirror the DNS precedent precisely.** The noop DNS
verifier waives the *external-world binding* (does the zone really contain
the record?) while every pure-crypto check (CSR self-signature) still runs.
The did:web analog: the noop resolver waives "does the live `did.json`
really list this key?" while the JWS verification still genuinely runs.

Port shape that makes both adapters uniform from the service's view:

```go
// internal/port/didresolver.go
type DIDResolver interface {
    // Resolve returns the DID document for did. Hints carry the
    // kid → public-JWK pairs the caller extracted from the submitted
    // proofs' protected headers; the web resolver ignores them
    // (authoritative fetch), the noop resolver synthesizes a document
    // from them so local flows run with zero hosting.
    Resolve(ctx context.Context, did string, hints []KeyHint) (*DIDDocument, error)
}

type KeyHint struct {
    Kid          string
    PublicKeyJWK json.RawMessage // from the proof's `jwk` protected header
}

type DIDDocument struct {
    ID              string
    AssertionMethod []VerificationMethod
}

type VerificationMethod struct {
    ID                 string
    Controller         string
    Type               string
    PublicKeyJwk       json.RawMessage
    PublicKeyMultibase string
}
```

Consequences, stated honestly:

- In **noop mode** the registrant's JWS proofs must carry the `jwk` protected
  header (standard JOSE) so the synthesized document has key material. The
  202 challenge list contains a single `{kid: "", signingInput}` entry (the
  `signingInput` is key-independent — design §5.3 notes every per-key entry
  carries the same bytes), and the registrant names keys via the JWS `kid` +
  `jwk` headers.
- In **web mode** the register-time advisory fetch enumerates the document's
  `assertionMethod` kids into the challenge list, and verify-control
  **re-fetches authoritatively** (design §3.6); the `jwk` header, if present,
  is ignored — the resolved document is always the key source.
- Sealed events remain **self-verifying in both modes**: the sealed
  `signedProof` really verifies against the sealed `publicKeyJwk`. Noop mode
  waives only the authoritative web binding — the documented quickstart
  caveat, same as noop DNS ("accepts any state; NOT for production").

Config (mirrors `dns:`):

```yaml
identity:
  resolver:
    type: noop            # noop | web   (default noop — quickstart parity)
  challengeTTL: 1h        # nonce TTL; design floor 5m for high-assurance
```

`cmd/ans-ra/main.go` gains `selectDIDResolver(cfg)` next to
`selectDNSVerifier`. `IdentityProofInput.raId` reuses the already-configured
producer identity (`cfg.Signer.RAID`) — one RA, one `raId`, no new key.

---

## 2. PR slices

Ordered so TL lands before anything emits to it, and so the event vocabulary
(append-only-forever) is settled in the first sealing-relevant PR — design
§5.5's sequencing note. Each PR: `make check` green, spec shape-diff pasted
into the PR description, DCO sign-off + GPG signature, no AI trailers.

```
PR1 (TL ingest) ──> PR2 (TL reads/join) ──> PR3 (RA identity + did:web) ──> PR4 (RA links + views + demo)
                                                        └────────────────> PR5 (did:key) ──> PR6 (ans-verify)
```

### PR 1 — `feat(tl): identity event family + ingest lane`

**The vocabulary-freezing PR.** The five tokens and the identity event shape
land here and are forever after.

New package `internal/tl/event/identity/` (import alias `identityevent`),
mirroring `internal/tl/event/event.go` structure exactly:

- `Type` enum: `IDENTITY_VERIFIED`, `IDENTITY_UPDATED`, `IDENTITY_REVOKED`,
  `IDENTITY_LINKED`, `IDENTITY_UNLINKED` + closed `IsValid()`.
- `Event` struct (design §5.5 shapes):
  `identityId` (required, stream key), `kind`, `value`, `providerId`,
  `proofMethod`, `keys[]` (`ProvenKey{verificationMethodId, keyThumbprint,
  publicKeyJwk, signedProof}` — JWK/proof omitted for lei's thumbprint-only
  tier), `ansIds[]` (LINKED/UNLINKED only), `previousValue` (UPDATED only),
  `verifiedAt`, `revokedAt`, `raId`, `timestamp`.
- Own `Envelope`/`Payload`/`Producer` wrapper (same outer shape, typed inner
  event) implementing `event.Signable`; `SchemaVersion = "V2"`;
  identical JCS canonicalization + RFC 6962 `SHA-256(0x00 || leaf)` rules.
- `Validate()` per-type required-key matrix (design §5.6.1): proofs/rotation/
  revocation require `identityId`; link events additionally require non-empty
  `ansIds[]`; `keys[]` required and non-empty on VERIFIED/UPDATED.

TL service + handler:

- `internal/tl/service/codec.go`: add `identityCodec` implementing
  `envelopeCodec` (same `ParseAndBuild` contract, `RAID_MISMATCH` guard
  included).
- `internal/tl/service/log.go`: the `append()` pipeline is already
  version-agnostic except the SQLite mirror; introduce a small per-lane
  bundle `{codec envelopeCodec; mirror eventMirror}` where `eventMirror` is
  `{ExistsByEventHash; StoreEvent}` — the agent lanes keep the existing
  store, the identity lane mirrors into the new tables.
- `internal/tl/handler/handler.go`: route `POST /v1/internal/identities/event`
  (same producer-signature discipline, same 256 KiB cap, same response shape).
  Producer-key verification is untouched — same trust store, same `kid`
  lookup.

Storage — `internal/adapter/store/sqlitetl/migrations/003_identity_events.sql`:

```sql
CREATE TABLE tl_identity_events (
    id            INTEGER PRIMARY KEY,
    leaf_index    INTEGER NOT NULL UNIQUE,
    leaf_hash     TEXT    NOT NULL,
    event_hash    TEXT    NOT NULL UNIQUE,   -- dedup key, SHA-256(JCS inner)
    log_id        TEXT    NOT NULL,
    identity_id   TEXT    NOT NULL,
    provider_id   TEXT,
    kind          TEXT,
    value         TEXT,
    event_type    TEXT    NOT NULL,
    raw_event     TEXT    NOT NULL CHECK (json_valid(raw_event)),
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_tl_identity_events_identity_leaf
    ON tl_identity_events(identity_id, leaf_index DESC);

-- the read-join index: one row per (link event, named agent) — design §5.6.1
CREATE TABLE tl_identity_event_agents (
    id            INTEGER PRIMARY KEY,
    leaf_index    INTEGER NOT NULL,
    identity_id   TEXT    NOT NULL,
    ans_id        TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,          -- IDENTITY_LINKED | IDENTITY_UNLINKED
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_tl_identity_event_agents_ans
    ON tl_identity_event_agents(ans_id, leaf_index DESC);
```

Plus `internal/adapter/store/sqlitetl/identityevents.go` (StoreEvent — also
fans the `ansIds[]` into the agent-index table; GetLatestByIdentityID;
GetByIdentityID paginated; ExistsByEventHash; ListLinkEventsByAgent;
ListAgentLinkStateByIdentity).

Spec: `spec/api-spec-tl-v2.yaml` — the ingest path + `IdentityProducerEvent`
schema + the five-token enum.

Tests: codec round-trip + leaf-hash vectors; per-type validation matrix;
**cross-lane guards both directions** (V2 agent body on the identity route →
422 `INVALID_EVENT`; identity body on `/v1/` and `/v2/internal/agents/event`
→ 422; V1 lane rejects all `IDENTITY_*`); ingest handler tests with real
producer signatures; dedup-by-content-hash including ansIds-index idempotence
on duplicate.

**Acceptance:** one Merkle tree — identity and agent leaves interleave in the
same tiles; checkpoints/witnesses/receipt machinery untouched; `/tile/*`
serves both.

### PR 2 — `feat(tl): identity read surface + computed badge join`

No new persistence beyond PR 1 — everything here is read-time computation
(design §5.6.3), the same pattern as the V2 badge's computed `status`.

- `internal/tl/service/identitybadge.go` — `Get` (latest identity event +
  Merkle proof + computed status `VERIFIED|REVOKED`), `Audit` (paginated,
  **format-identical to the agent audit envelope** — no bespoke shape).
- Receipt support for identity leaves: `ReceiptService.ForIdentity` — reuse
  the leaf-index receipt machinery; `tl_receipts` keying generalizes (add a
  nullable `identity_id` column or a `subject_type` discriminator in the same
  003 migration — implementation detail, decide at code time).
- The **join**, both directions, computed in the service from PR 1's stores:
  a link is *effective* iff latest link/unlink for `(identityId, ansId)` is
  `LINKED` ∧ identity stream says `VERIFIED` ∧ agent badge status is live.
- Routes (`internal/tl/handler/handler.go`):
  - `GET /v1/identities/{identityId}` — identity badge.
  - `GET /v1/identities/{identityId}/audit` — full chain, audit envelope.
  - `GET /v1/identities/{identityId}/receipt` — COSE receipt.
  - `GET /v1/identities/{identityId}/agents` — reverse join (currently linked).
  - `GET /v1/agents/{agentId}` — **gains computed `identities[]`** (design
    §5.6.3 badge shape: identityId, kind, value, identityStatus,
    provenKeyThumbprints, linkedAt, linkLogId, identityLogId). Covered by the
    TL's response signature, never by the seal.
  - `GET /v1/agents/{agentId}/identities` and `…/identities/history` — the
    audit envelope filtered through the agent index.
- Spec: full read-surface delta to `spec/api-spec-tl-v2.yaml`.

Tests: join truth-table (link → badge shows it; rotate → thumbprints flip on
every linked badge with **one** sealed event; revoke identity → all badges
show REVOKED; unlink → gone; agent revoked → link ineffective, identity
stream untouched); audit pagination; receipt round-trip; agent audit remains
pure `AGENT_*`.

### PR 3 — `feat(ra): verified-identity aggregate + proof gate + did:web`

The RA half: domain, storage, the generalized verify-control gate, sealing,
and the noop/web resolver pair. Internal milestone "2a" of the design.

**Domain** (`internal/domain/identity.go`, 100% coverage):

- `IdentifierKind` + lexical `InferKind(value)` (`did:web:` / `did:key:` /
  `lei` — only did:web *enabled* this PR; others →
  `IDENTIFIER_KIND_UNSUPPORTED`), canonicalization rules, did:web →
  resolution-URL mapping (root → `/.well-known/did.json`, path-bearing →
  `/{path}/did.json`, **reject port/userinfo** → `DID_BAD_FORMAT`).
- `VerifiedIdentity` aggregate (design §2.1): identityId (UUIDv7 —
  `google/uuid` v1.6 has `NewV7`), providerId, kind, value, status
  (`PENDING_CONTROL → VERIFIED → REVOKED`), proofMethod, staged
  `pendingValue`, challenge (nonce/expiry/consumed); transitions
  `IssueChallenge`, `MarkVerified`, `StageRotation`, `CompleteRotation`,
  `Revoke`; **no public-key field** (ANS-0 §6.2).
- `IdentityLink` (status `LINKED|UNLINKED`) — used in PR 4, lands with the
  aggregate.
- Domain events appended to `internal/domain/events.go` pattern.

**Crypto** (`internal/crypto/`, ≥95–100%):

- `jwk.go` — JWK → `crypto.PublicKey` (Ed25519 OKP, ECDSA P-256 allowlist),
  RFC 7638 thumbprint, `publicKeyMultibase`/Multikey → JWK conversion (the
  pinned thumbprint rule, design §3.6 semantic note).
- `proofinput.go` — `IdentityProofInput` builder: exactly the §3.2 JCS object
  `{identifier, identityId, nonce, purpose:"ans:identity-proof:v1", raId,
  scheme}` via the existing `Canonicalize`; the served `signingInput` is the
  base64url of those bytes, and verify-control checks **payload-equality
  before signature** (clients never canonicalize).
- JWS verification reuses `VerifyWithPublicKey` (go-jose v4 already supports
  EdDSA + ES256); pin `alg` to the resolved key type.

**Port + adapters:**

- `internal/port/didresolver.go` — as §1 above.
- `internal/adapter/didresolver/web.go` — hardened fetcher (design §3.7):
  custom dialer that re-resolves, **rejects RFC 1918 / loopback / link-local
  / ULA / metadata at connect time**, pins the resolved IP per
  verify-control call; WebPKI + hostname verification on every fetch; 5 s
  timeout; response cap; ≤5 redirects within the same registrable domain
  (needs `golang.org/x/net/publicsuffix`); error `detail` never echoes
  resolved IPs/redirect chains.
- `internal/adapter/didresolver/noop.go` — synthesizes from hints (§1).
- `internal/adapter/store/sqlite/identity.go` (+ link store) implementing new
  `port.IdentityStore` / `port.IdentityLinkStore` in `internal/port/store.go`.
  Challenge consumption is a **conditional
  `UPDATE … WHERE challenge_consumed_at_ms IS NULL`** inside the
  verify-success `uow.Run` transaction — the TOCTOU guard (§3.2).

**Storage** — `internal/adapter/store/sqlite/migrations/006_identities.sql`:
verbatim design §5.7 (`identities` + `identity_links`, partial unique
indexes `idx_identities_live` on `(provider_id, kind, value) WHERE status !=
'REVOKED'` and `idx_identities_proven` on `(kind, value) WHERE status =
'VERIFIED'` — first-to-prove wins, no squatting). Plus
`007_outbox_identity_lane.sql`: SQLite cannot widen a CHECK in place, so
rebuild `outbox_events` (create-copy-drop-rename inside the migration tx)
with `schema_version IN ('V1','V2','IDENTITY')`.

**Service** (`internal/ra/service/identity.go`):

- `Register` — infer/canonicalize kind, advisory resolve (noop: empty doc),
  idempotent re-add (same owner + same value while `PENDING_CONTROL` → same
  identityId, fresh nonce; `IDENTIFIER_DUPLICATE` only for genuine conflicts
  per §4.2/§9 Q1), 202 with `{identityId, nonce, expiresAt, challenges[]}`.
- `VerifyControl` — authoritative re-resolve; per-proof checks in design
  §3.6 order (payload-equality; `kid ∈ assertionMethod`; `{DID}#fragment`
  rule; `controller == DID`; key-type allowlist; verify **every** JWS,
  one bad proof fails closed; nonce fresh, consumed once in-tx); flip to
  `VERIFIED` (or swap staged rotation) and **seal in the same flow**:
  build `identityevent.Event`, JCS + sign **once** via the existing
  `signAndMarshalPayload` pattern, enqueue with lane `IDENTITY` —
  the outbox-replay invariant applies unchanged.
- `Rotate` (PUT — stage `pending_value`, old state stands, fresh challenges),
  `Revoke` (POST — seal `IDENTITY_REVOKED`), `List`, `Detail`.

**Outbox/tlclient:** `tlclient.Client` URL map gains
`IDENTITY → /v1/internal/identities/event`; worker untouched (lane passes
through `Sender.Append`).

**HTTP** (`internal/ra/handler/identity.go` + routes in `cmd/ans-ra/main.go`):

```
POST /v2/ans/identities                              202 + challenges
POST /v2/ans/identities/{identityId}/verify-control  200 VERIFIED (seals)
PUT  /v2/ans/identities/{identityId}                 202 + fresh challenges
POST /v2/ans/identities/{identityId}/revoke          200 (seals; POST, never DELETE)
GET  /v2/ans/identities                              list (mine)
GET  /v2/ans/identities/{identityId}                 detail
```

New `internal/ra/middleware/identityownership.go` mirroring the agent
ownership middleware (read → 404 hides existence, write → 403). RFC 7807
codes added to the handler error map: `IDENTIFIER_KIND_UNSUPPORTED`,
`IDENTIFIER_DUPLICATE`, `IDENTIFIER_CHALLENGE_EXPIRED`,
`PRICC_SIGNATURE_INVALID`, `PRICC_TOKEN_EXPIRED`, `PRICC_TOKEN_ALREADY_USED`,
`DID_BAD_FORMAT`, `DID_RESOLUTION_FAILED`, `DID_DOCUMENT_ID_MISMATCH`,
`DID_REDIRECT_DOMAIN_MISMATCH`, `DID_VERIFICATION_METHOD_INVALID`.

**Config:** `Identity` block in `internal/config/config.go` (§1 above);
`selectDIDResolver` in main.go; `config/ra-local.yaml` gains the block with
`resolver.type: noop`.

**Spec:** `spec/api-spec-v2.yaml` — six identity routes + request/response/
challenge schemas (design §5.2/§5.3), shape diff pasted in the PR.

Per CLAUDE.md "no placeholder routes": the link routes and the RA-side
computed `identities[]` do **not** register in this PR — they land
implemented in PR 4.

Tests: domain 100% (state machine, kind inference, challenge lifecycle);
proof-gate table tests (good/bad kid, wrong controller, external reference,
alg confusion, expired/consumed nonce, multi-key one-bad-fails-closed,
concurrent verify double-consume race via `make test-race`); web resolver
against `httptest.NewTLSServer` + SSRF dialer unit tests (denylist matrix,
rebind pin); noop resolver; handler 202/422/403/404 paths; end-to-end
RA→outbox→TL integration sealing `IDENTITY_VERIFIED` against the PR 1 lane.

### PR 4 — `feat(ra): identity links + computed agent views + demo`

Internal milestone "2b": the link mechanism + read-side joins + quickstart.

- Service `Link`/`Unlink`: **single owner-gated call, no signature** (§4.3 —
  caller's principal must own the identity **and every** agent; identity must
  be `VERIFIED`); batch upsert against `idx_identity_links_live`; seal **one**
  `IDENTITY_LINKED` carrying `ansIds[]` (chunk very large batches to bound
  leaf size); unlink seals `IDENTITY_UNLINKED`. Cascade rules §4.4: agent
  revocation emits zero identity events and vice versa — enforced by tests.
- Routes: `POST /v2/ans/identities/{identityId}/links` (200 `{linked: N}`),
  `DELETE /v2/ans/identities/{identityId}/links/{agentId}`.
- RA `AgentDetails` gains the additive computed `identities[]` (design §5.4)
  in lifecycle `Detail` — computed from the link + identity tables, never
  stored on the registration; `agent_registrations` untouched.
- Spec deltas for both files.
- **Demo** (`scripts/demo/`): `identity-lifecycle.sh` against the noop
  resolver — register identity → sign challenge → verify-control → link to
  the demo agent → show TL badge `identities[]` → rotate (one event) →
  revoke. JWS signing from shell needs a helper: small
  `scripts/demo/signproof/main.go` run via `go run` (mints an Ed25519 key,
  emits the compact JWS with `kid`+`jwk` headers over the served
  `signingInput`). README quickstart section updated.

### PR 5 — `feat(ra): did:key`

Reuses every PR 3 seam; **zero I/O — no noop needed**, the keyless test
track (§2.2).

- `internal/crypto/didkey.go` — decode `did:key:z…`: multibase base58btc +
  multicodec varint (`0xed01` Ed25519; optionally `0x1200` P-256). Hand-roll
  base58btc (~40 lines, fully testable) rather than adding multiformats deps.
- Kind dispatch: challenges return exactly one entry
  (`kid = {did}#{method-specific-id}` per did:key convention); verify against
  the key decoded **from the DID string**; `alg` pinned.
- Seal `keys[]` with thumbprint + JWK + signedProof (self-verifying; key also
  derivable from the DID itself).
- Demo extension + table tests with fixed vectors.

### PR 6 — `feat(verify): offline verification of IDENTITY_* leaves`

`ans-verify` learns the identity stream so third parties can check seals
offline (design D5 / §5.6.3 verifier walk):

- Parse identity envelopes; verify TL attestation JWS, producer JWS,
  inclusion proof to checkpoint — all existing machinery, new inner shape.
- **Self-verifying key proofs**: verify each sealed `signedProof` against its
  sealed `publicKeyJwk`; decode the payload and confirm it is an
  `IdentityProofInput` binding this `identityId` + `identifier` + `purpose`
  — offline, without trusting the RA.
- CLI surface consistent with existing verify commands.

### PR 7 *(postponed — do not schedule)* — `lei`

Design §3.6/§10.7 retained as design of record. When resumed:
`port.LEIControlVerifier` (present / authorization / verify-signature) with
a **noop adapter** + a real adapter for the internal GLEIF `vlei-verifier`;
fixed-host GLEIF L1 client (noop + real); present-once at register /
prove-repeatably at verify-control; AID pinned at presentation;
thumbprint-only sealing (PII rule). Until then the kind returns
`IDENTIFIER_KIND_UNSUPPORTED`.

---

## 3. Cross-cutting rules (gates on every PR)

1. **Event vocabulary is frozen by PR 1.** Sealed shapes are
   append-only-forever; nothing seals to a shared TL until the five tokens +
   payload schemas in PR 1 are reviewed against design §5.5 and the spec
   delta is merged (design §5.9 amendment rows A–F note the upstream ANS-spec
   ratification — track it in the PR description).
2. **Outbox-replay invariant** extends verbatim to identity events: payload
   JCS-canonicalized + signed exactly once at enqueue; retries replay bytes;
   TL dedups on content hash.
3. **No placeholder routes.** Every route registers only in the PR that
   implements it end-to-end; unsupported kinds are `IDENTIFIER_KIND_UNSUPPORTED`
   at dispatch, never a stubbed seal.
4. **Streams never cross at write time.** Identity operations write zero
   agent-stream events and vice versa; all propagation is read-time join.
   Every PR 2/4 test suite asserts the negative.
5. **Minimal abstraction** (design §6): per-kind control logic starts as a
   switch + functions inside the identity service; no `port.ControlVerifier`
   until did:key is the second real caller (extract the seam in PR 5 only if
   it pays for itself). No `LocationChallenger` interface — one implementer
   (ACME) exists and it stays where it is.
6. **Coverage**: `internal/domain` 100%; `internal/crypto` 100% target
   (≥95% with annotated SAFETY/NOTE exceptions); overall ≥90% via
   `make test-cover`. `make check` before every commit; `make test-race` for
   the nonce-consumption race.
7. **Commits**: conventional commits (`feat(tl):`, `feat(ra):` …),
   `git commit -s` (DCO), GPG-signed, **no AI Co-Authored-By trailers**.

---

## 4. Open decisions (flagged for review before/during PR 1 & 3)

| # | Decision | Recommendation | Where it lands |
|---|---|---|---|
| 1 | Outbox lane mechanism: widen `schema_version` CHECK (table rebuild) vs dispatch on `IDENTITY_*` event-type prefix in the worker | **Widen the CHECK** — explicit lane column beats stringly dispatch; SQLite rebuild migration is routine | PR 3, migration 007 |
| 2 | Noop resolver semantics: synthesize from `jwk`-header hints (real JWS verification, waived web binding) vs accept-any | **Hint synthesis** — keeps sealed events self-verifying even from quickstart runs | PR 3, §1 above |
| 3 | `IdentityProofInput.raId` source | **Reuse `cfg.Signer.RAID`** — one RA identity everywhere; deployment docs say to set it to the external base URL per design §3.2 | PR 3 |
| 4 | did:key multibase: hand-rolled base58btc vs `go-multiformats` deps | **Hand-roll** (~40 lines + vectors) — two deps for one decode is poor trade | PR 5 |
| 5 | Key-type allowlist v1 | **Ed25519 + ECDSA P-256** (matches go-jose EdDSA/ES256 and the TL's own P-256 posture) | PR 3 |
| 6 | Must linked agents be `ACTIVE` at link time, or any live (non-terminal) status? | **Any live status** — effectiveness is computed at read time anyway (§5.6.3); blocking on ACTIVE adds a write-time race for no read-time gain | PR 4 |
| 7 | Identity envelope `schemaVersion` token | **`"V2"`** — same producer-lane generation; lane separation is the route + event family, not the version string | PR 1 |
| 8 | Receipt table generalization for identity leaves (`tl_receipts`) | Nullable `identity_id` column in migration 003 | PR 2 |

---

## 5. What this plan explicitly does NOT do

- No change to the agent registration path — `AgentRegistration`,
  `agent_registrations`, the ACME/CSR/BYOC flows, and `AGENT_*` event shapes
  are byte-for-byte untouched (design §2.1, §5.1).
- No keyless *primary* agents (§2.3) — the policy guard stands; did:key
  exercises the keyless path as a linked identity only.
- No cross-owner links, no `EquivalenceLink`, no `clientCatalog` (§2.3).
- No AIM/monitoring emission to the TL (§4.6 — operator alerting concern,
  out of scope for this repo today).
- V1 RA/TL lanes frozen — zero identity surface on `/v1/agents/*` RA routes
  or the V1 ingest lane.
