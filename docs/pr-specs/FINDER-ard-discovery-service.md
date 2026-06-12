# FINDER — ARD-conformant discovery service for ANS

Design document for `ans-finder`, a new binary in the ANS reference
implementation that makes every ANS-registered agent discoverable
through the Agentic Resource Discovery (ARD) protocol.

- **Status**: Proposal (design of record for the first finder slice)
- **Date**: 2026-06-12
- **Audience**: ANS contributors and ARD working-group reviewers
- **Scope**: the design across the whole finder; the implementation
  lands in three independently reviewed PRs (a documentation PR, a
  refactor PR, and a spec-plus-projection PR), with the binary and
  its remote MCP endpoint following in later slices.

---

## 1. Header

`ans-finder` is the fourth runtime service of the ANS reference
implementation, alongside the Registration Authority (`ans-ra`), the
Transparency Log (`ans-tl`), and the offline verifier (`ans-verify`).
It serves the ARD search and explore endpoints over an index built
from agents the RA has registered and the TL has sealed.

The protocol is the **Agentic Resource Discovery Specification (ARD),
v0.5 (Draft), dated May 28, 2026** — the public draft maintained by
the `agenticresourcediscovery` working group. GoDaddy participates in
that working group, and Microsoft's "Agent Finder" product implements
the same protocol. `ans-finder` is a reference implementation of the
registry role: it ingests ANS registrations, projects them into ARD
catalog entries, indexes them, and answers `POST /v1/search` and
`POST /v1/explore` requests so that any HTTP client — a Claude,
ChatGPT, Copilot, or Gemini orchestrator using a published connector —
can find ANS agents by natural-language query or structured filter.

What makes the ANS finder distinct from a generic ARD registry is the
trust chain underneath each entry. Every catalog entry carries a SCITT
receipt URI that resolves against the transparency log, so a client
can verify that the agent it just discovered was actually sealed into
an append-only log — not merely asserted by the finder. The finder is
a search convenience; the receipt is the proof.

This document records the architecture, the ingestion decision and its
trades, the projection rules, the API surface, the security contracts
that must be frozen before any wire format ships, and the deliberate
deviations from both the ARD spec and the ANS RA spec.

---

## 2. Problem, goals, non-goals

### Problem

ANS registers agents, issues their certificates, and seals their
lifecycle events into a transparency log. But there is no way for an
LLM orchestrator to *find* an ANS agent by what it does. Discovery
today requires knowing an agent's ANS name in advance and resolving it
through DNS. As the population of registered agents grows, "you must
already know the name" does not scale — the same problem ARD was
written to solve for the wider agent ecosystem.

### Goals

- Serve an ARD-conformant search interface (`POST /v1/search`,
  `POST /v1/explore`) over the population of ANS-registered agents.
- Make every entry independently verifiable: each carries a SCITT
  receipt URI a client can check against the transparency log.
- Build the index from a single, well-defined ingestion source with a
  clear integrity story, rather than scraping or guessing.
- Keep the projection from ANS events to ARD entries pure and fully
  testable, with golden vectors pinning every mapping decision.
- Treat all registrant-supplied text and URLs as untrusted input and
  pass them through one sanitization chokepoint and one URL-policy
  chokepoint before they reach an AI orchestrator.

### Non-goals

- **Not** a crawler in this slice. ARD's required Web Ingestion
  pipeline (crawling `ai-catalog.json` files) is deferred to a later
  phase (§10); the first slice ingests only from the ANS events feed.
- **Not** a federation hub. Federated multi-registry routing is
  designed for (§8) but the first slice ships referrals as
  configuration only, with no automatic upstream following.
- **Not** a second source of truth. The finder asserts only what it
  derived from the feed. Clients needing certainty verify the receipt
  or the TL status token, not the finder's word.
- **Not** an authentication layer. Per ARD §3.6, agent authentication
  is the artifact protocol's job, not the discovery layer's.

---

## 3. Background

### The Registration Authority

The RA (`ans-ra`) accepts agent registrations, drives them through
ACME and DNS verification, issues identity and server certificates,
and records each lifecycle transition as an event. Registration is a
two-step flow: `POST` to create a registration returns `202` with the
agent in a PENDING state; the agent becomes ACTIVE only after
`verify-dns` succeeds. The RA writes lifecycle events to an outbox
table and a background worker ships them to the TL.

### The Transparency Log and SCITT receipts

The TL (`ans-tl`) is an append-only Merkle-tree log. When the RA's
outbox worker delivers an event, the TL seals it as a leaf and issues
a SCITT COSE receipt — a signed inclusion proof. A client holding a
receipt can verify, offline, that a specific event was included in the
log at a specific tree size, against the single ECDSA P-256
verification key the TL advertises at `/root-keys`. The receipt proves
inclusion of the agent's **latest** sealed event; verifying the
*content* of that event requires fetching the agent's badge envelope
from the TL and field-comparing.

### The production events contract

The canonical events contract is the production
`GET /v1/agents/events` feed, whose schema is published on
developer.godaddy.com as `swagger_ans.json` (mirrored in this
repository's sibling at
`~/Code/ans-registry-poc/swagger-docs/swagger_ans.json`). It returns a
paginated stream of `EventItem` records — one per lifecycle event —
carrying the agent's identity, lifecycle state, timestamps, and
optional display and endpoint metadata. This contract, not any
internal structure, is the finder's ingestion currency. Its full field
tables are transcribed verbatim in the appendix (§17).

### Why the in-process event bus is NOT an ingestion source

The RA has an in-process event bus
(`internal/adapter/eventbus/inmemory.go`). It is tempting to subscribe
the finder to it, but the bus is the wrong source for four concrete
reasons, each verified against the code:

1. **One pre-validation publish site.** There is exactly one
   `bus.Publish` call in the RA service layer
   ([registration.go:393](../../internal/ra/service/registration.go)),
   and the event it publishes is constructed inside the registration
   constructor
   ([agent.go:177](../../internal/domain/agent.go)) — at register time,
   when the agent is still PENDING, *before* DNS verification. An agent
   that never completes verification would still have hit the bus. The
   feed, by contrast, reflects sealed lifecycle state.

2. **No lifecycle events.** The bus event
   (`AgentRegisteredEvent`,
   [events.go:29](../../internal/domain/events.go)) carries only
   `agentID`, `ansName`, `ownerID`, and a timestamp. It has no display
   name, no description, no endpoints, and no way to express
   revocation or renewal. There is nothing to project into an ARD
   entry beyond an identifier.

3. **Non-durable.** The bus runs handlers synchronously in the
   publisher's goroutine; handler errors are logged and swallowed, not
   retried. The package's own doc comment says to "use async outbox
   patterns for durability across processes"
   ([inmemory.go:18-25](../../internal/adapter/eventbus/inmemory.go)).
   A finder subscribed to the bus would silently miss any event whose
   handler errored or whose process restarted.

4. **Token collision.** The bus uses the token `AGENT_REGISTERED`
   ([events.go:9](../../internal/domain/events.go)) to mean "a
   registration was created (pending)", while the events contract and
   the TL use the same token `AGENT_REGISTERED` to mean "the agent
   reached ACTIVE and was sealed". Subscribing to the bus would import
   a token that looks identical to the contract's but means something
   different at a different point in the lifecycle.

The conclusion is firm: the finder ingests from the events contract,
never the bus.

---

## 4. Architecture overview

`ans-finder` follows the same hexagonal layout as the rest of the
codebase — pure domain logic in the center, external dependencies
behind port interfaces at the edges.

```
              feed (events contract)
                       │
         ┌─────────────▼─────────────┐
         │  ingestion port            │  currency: feed.EventItem
         │  (poll GET /v1/agents/events)
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  projection (pure)         │  FromEvent(item) → entries / skips
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  index (finder's SQLite)   │  FTS5 + facets + tombstones
         └─────────────┬─────────────┘
                       │
         ┌─────────────▼─────────────┐
         │  ARD API handlers          │  POST /v1/search, /v1/explore
         └────────────────────────────┘
```

The defining boundary is the **ingestion port**, whose currency is the
events contract type `feed.EventItem`. "Future adapters" therefore
means *other transports of the same events contract* — for example, a
cross-deployment poller against a remote RA's feed — not a different
data model. It deliberately does **not** mean a transparency-log-tail
reader; that would be a different currency and a different trust model
(§5). The projection stage is pure: it takes a validated `EventItem`
and returns either catalog entries or enumerated skips, with no I/O,
so the entire mapping is exercisable with golden vectors.

---

## 5. Ingestion design

### Sole source: `GET /v1/agents/events`

The finder's only ingestion source is the production events contract,
`GET /v1/agents/events`. The finder polls it, validates each
`EventItem`, projects the survivors into catalog entries, and applies
the result to its index. There is no second source in this slice.

This was a deliberate decision (Keith P, 2026-06-12: feed-only). The
alternative considered was reading the transparency-log tail directly.

### Why feed-only, and what a TL-tail reader would have added

A TL-tail reader would have given the finder an index **rebuildable
from the public log by any third party** — anyone could replay the log
and reconstruct the same entries, making the finder's index publicly
auditable end to end. That is a real property the feed-only design
gives up.

The feed-only design was chosen anyway because:

- The events contract is the published, stable, documented interface;
  the TL leaf format, while public, is lower-level and would couple the
  finder to TL storage internals.
- The feed already carries the display and endpoint metadata the
  projection needs in one record; reconstructing equivalent content
  from TL leaves would mean re-deriving the badge envelope.
- Client-side verifiability is preserved by a different mechanism (see
  below), so the finder does not need to *be* the audit path to keep
  entries verifiable.

### How client-side verifiability is preserved

Even though the index is not third-party-rebuildable, every entry stays
client-verifiable, with this precision:

- Each entry carries a SCITT receipt URI in its trust manifest. The
  receipt proves inclusion of the agent's **latest** sealed event.
- Verifying the *content* of an entry (does the display name, the URL,
  the endpoint match what was sealed?) requires the client to fetch the
  agent's badge envelope from the TL (`GET /v1/agents/{agentId}`) and
  field-compare. The receipt alone proves inclusion, not content.
- The latest-event inclusion property doubles as a
  revocation/freshness check: if the latest sealed event is a
  revocation, the client sees it when it resolves the receipt.
- Each entry carries `metadata.logId`, so a client can detect
  divergence — if the finder built the entry from an older event than
  the receipt proves, the `logId` in the entry will not match, and the
  client can tell.

### The feed must serve only TL-acked rows

For the invariant *in the feed ⇒ sealed ⇒ receipt resolvable* to hold,
the feed must serve only events the TL has acknowledged. In the OSS RA
this corresponds to outbox rows where delivery has completed —
`sent_at_ms IS NOT NULL`
([outbox.go:92,119](../../internal/adapter/store/sqlite/outbox.go):
the pending-fetch query selects `sent_at_ms IS NULL`, and `MarkSent`
stamps `sent_at_ms` only after successful delivery). Implementing the
feed route to gate on acked rows is owned by the feed-route PR (the
finder's PR 2), not this slice. The invariant holds modulo the TL's
documented checkpoint-lag window, during which the TL may answer a
receipt request with `503` and a `Retry-After` header.

### Degraded mode

If the feed becomes unavailable, the finder serves its last-known
index rather than failing closed on reads. Entries served while the
feed is stale carry a `staleSince` marker once the poll gap exceeds a
configured bound. The security cost is stated plainly: **a feed stall
is revocation latency for the duration of the stall.** If an agent is
revoked while the finder cannot reach the feed, the finder keeps
serving the agent as active until the feed recovers and the revocation
is ingested. The `staleSince` marker is the concrete signal a client
can act on; the poll cadence, the staleness bound, and the alerting on
prolonged stalls are owned by the finder-binary PR (PR 3).

### Accepted trades (recorded)

These are the explicit, accepted trades of the feed-only design. They
also appear in the trust model (§11) and the deviations table (§15).

| # | Trade | Consequence |
|---|---|---|
| 1 | Bootstrap is bounded by feed retention | A new finder can only see back as far as the feed retains (production: 30 days; OSS: configurable in PR 2). Older registrations are invisible until they next emit an event. |
| 2 | Index not rebuildable from the public log by third parties | Loses end-to-end public auditability of the index; client-side verifiability preserved via receipts + `metadata.logId` (above). |
| 3 | Single-RA scope by design | The ingestion port's currency is `feed.EventItem`, so additional adapters mean other transports of this contract, not TL-tail drop-ins. |
| 4 | Revocation rides the unsigned feed | TLS-verified transport is the sole ingestion integrity control. Split-view (RA seals X, feeds Y) and silent omission (opaque cursor, no contiguity signal) are accepted residual risks, detectable only by client receipt verification or external log-vs-index audit. Feed stall = revocation latency for its duration. |
| 5 | OSS lifecycle reality on `main` | Only `AGENT_REGISTERED` and `AGENT_REVOKED` have producers in the OSS RA; renewal emits nothing and there is no Deprecate method. The projection supports all four contract types, but renewed/deprecated fixtures are contract-shape-only. |

---

## 6. Projection

The projection stage maps a validated `EventItem` into ARD catalog
entries (or tombstones, or skips). It is a pure function with a single
exported entry point — `FromEvent(item, opts)` — and no I/O.

### EventItem → CatalogEntry mapping (Active path)

For an `AGENT_REGISTERED` event, the projection fans out **one catalog
entry per endpoint whose protocol is includable**:

| Source field (EventItem) | Target (CatalogEntry) | Rule |
|---|---|---|
| `endpoints[].protocol` = `A2A` | `type` = `application/a2a-agent-card+json` | one entry |
| `endpoints[].protocol` = `MCP` | `type` = `application/mcp-server+json` | one entry |
| `endpoints[].protocol` = `HTTP-API` | — | no entry (HTTP-API is not an ARD artifact type) |
| unknown protocol token | — | per-endpoint Skip |
| `agentDisplayName` | `displayName` | sanitized |
| `agentDescription` | `description` | sanitized |
| `endpoints[].metaDataUrl` | `url` | policy-checked; see URL selection below |
| `endpoints[].functions[].name` | `capabilities` | sanitized, deduped, sorted, capped at 50 |
| `endpoints[].functions[].tags` | `tags` | union, sanitized, deduped, sorted, capped at 10 |
| `version` | `version` | sanitized |
| `createdAt` | `updatedAt` | verbatim string passthrough (no re-parse / re-format) |
| `ansName`, `logId`, validated `agentUrl` | `metadata` | `{ansName, logId, agentUrl?}` |
| derived | `trustManifest` | identity + ANS-Registration receipt attestation |
| derived from `agentHost` + label | `identifier` | URN, Active path only (see §6 URN) |

**URL selection (pinned).** The `url` of an entry is chosen as follows:

- If `metaDataUrl` is **absent**, construct the well-known fallback
  `https://{agentHost}/.well-known/{agent-card.json|mcp.json}` (path
  per protocol), then pass it through the URL policy chokepoint.
- If `metaDataUrl` is **present but fails** the URL policy, **Skip the
  endpoint, fail-closed** — do not fall back to the well-known URL. A
  policy-failing `metaDataUrl` is a signal, not an excuse to substitute.
- The constructed fallback is never trusted by construction; it passes
  the same `validateEmittedURL` chokepoint as any other URL.

**Trust manifest (Active path).** The entry's trust manifest is:

- `identity`: `"https://" + agentHost` (the host is already
  syntax-validated and bound to `ansName` by feed validation).
- `identityType`: `"https"`.
- `attestations`: a single attestation of type `ANS-Registration`,
  `uri` = `TLBaseURL + "/v1/agents/" + pathEscape(agentId) + "/receipt"`,
  `mediaType` = `application/scitt-receipt+cose`. No `digest` (see trade
  2 — the receipt proves latest-event inclusion, not entry content, so
  a content digest would overclaim).
- When `TLBaseURL` is empty (not configured), attestations are omitted
  entirely rather than emitting a malformed URI.

**Entry ordering.** Entries are sorted by `(identifier, type, url)`.
Duplicate protocols on one agent are contract-legal, so the sort key
must break ties down to the URL to stay deterministic for golden
vectors.

### Tombstones (the safety rule)

`AGENT_REVOKED` and `AGENT_DEPRECATED` events produce **tombstones**,
not entries. A tombstone is **minted from required identity fields
only**:

- It is keyed and applied by `agentId` / `ansName` — both required
  fields, always present on a valid `EventItem`.
- It carries identity (`agentId`, `ansName`), the cursor (`logId`), and
  the timestamp (`createdAt` verbatim). It carries **no display
  metadata** — no display name, no description, no endpoints.
- It **never passes through label minting or URL policy.** Those
  belong to the Active path only.

The consequence is a hard guarantee: **a revocation always
tombstones, even with no display metadata at all.** A
revocation event carrying only the required fields still produces a
working tombstone — pinned by the `event_revoked_minimal.json` golden
fixture. Tombstones are how the index hides revoked agents (§7); making
them depend on optional display fields would mean a revocation could
silently fail to hide an agent, which would be a security defect.

### Error vs Skip (pinned)

The projection distinguishes two failure modes:

- **Error** — `feed.Validate()` failure (a missing required field, a
  malformed `agentId`, a bad `ansName`/`agentHost` binding) returns
  `(Projection{}, error)`. The event is structurally invalid; the
  caller decides what to do.
- **Skip** — record-level issues that don't invalidate the event
  produce enumerated `Skip{Kind, Detail}` entries alongside any
  surviving entries. An unknown `eventType` is an **alertable Skip
  (`UnknownEventType`), never an error** — because the finder ingests
  from a single source behind a cursor, a structural error on an
  unknown event type would *wedge ingestion at that cursor* the moment
  the producer's enum grows. Failing closed must not mean failing
  stuck.

**Skip granularity**: a label-minting failure produces one Skip per
event; a per-endpoint failure produces one Skip per endpoint.

---

## 7. Index

The finder owns its own SQLite database — separate from the RA's and
the TL's. The index is built from projected entries and tombstones.

- **Full-text search** uses SQLite FTS5 over the searchable text
  (display name, description, capabilities, tags) to answer the `text`
  member of an ARD query.
- **Facets** are computed over indexed fields to answer `POST
  /v1/explore` aggregations (§8).
- **Tombstones are applied and then hidden.** When a tombstone arrives
  for an `agentId` / `ansName`, the index marks that registration's
  entries as revoked and excludes them from search and explore results.
  The tombstone row itself is retained (so re-ingestion is idempotent)
  but never surfaced.
- **Keys**: entries and tombstones are keyed per registration by
  `agentId` / `ansName`. The ingestion cursor is the feed's `logId`.

The index is a cache derived from the feed, not a source of truth. It
can be discarded and rebuilt by re-polling the feed from the start of
its retention window.

---

## 8. API

The finder serves the ARD API. The two endpoints in this slice are
`POST /v1/search` and `POST /v1/explore`, both modeled on the house
style of `spec/api-spec-v2.yaml`.

### POST /v1/search (`searchCatalog`)

Accepts an ARD `query` object (`{text, filter}`) plus root-level
`federation`, `pageSize`, and `pageToken`. For Search, `text` is
required and `filter` is optional (ARD §7.2). Returns `results[]` —
catalog entries each annotated with a `score` (0–100 relevance) and a
`source` — plus optional `referrals[]` and a `nextPageToken`.

- `filter` keys are dot-paths into the catalog entry; values are
  arrays (OR within a key, AND across keys), per ARD §7.1. The slice
  supports `type`, `tags`, `capabilities`, `publisher`, and
  `trustManifest.attestations.type`.
- `federation` is `auto | referrals | none`, default `auto` (ARD §8),
  though the first slice's referrals are configuration-only with no
  auto-follow (§11, §15).
- `pageSize` defaults to 10 and is capped at 100 (ARD §7.2).

POST is used (not GET) because the query object is a structured body
and search responses are not cacheable; each operation documents this
rationale in the spec.

### POST /v1/explore (`exploreCatalog`)

Accepts an ARD `query` plus a `resultType.facets[]` request and returns
real facet `buckets` with an `otherCount`, per ARD §7.3. For Explore,
both `text` and `filter` are optional. `facets[].limit` defaults to 20
and `minCount` suppresses small buckets. This implementation computes
real facets; the spec documents `501 Not Implemented` as the behavior
*other* ARD registries may exhibit when they don't implement Explore,
not this one.

### Federation

The `federation` query parameter controls topology (ARD §8). In this
slice, `referrals` returns configured referral entries; `auto` does not
silently fan out to upstreams. Referral targets are operator
configuration, never auto-discovered (§13.f).

### Errors: RFC 7807 Problem

Every failure path returns `application/problem+json` with the RFC
7807 `Problem` shape — `type`, `title`, `status`, `detail`, `code` —
matching CLAUDE.md, the TL spec (`spec/api-spec-tl-v2.yaml`), and the
RA's actual handler
([errors.go:14](../../internal/ra/handler/errors.go)). The `code` field
carries one of the five ARD error codes. Invalid arguments return
`400` (ARD's convention), which differs from the house `422`; this
deviation is recorded in §15.

---

## 9. Remote MCP (PR 5)

ARD §7.3 permits a registry to additionally expose its search
capability natively as an MCP tool or A2A skill, provided the response
follows the same catalog-entry format. A later PR (PR 5) adds a remote
MCP endpoint to `ans-finder` so an MCP-native orchestrator can call
search without speaking the REST API. The MCP request shape is
pending further definition in the ARD spec; the response will reuse the
catalog-entry projection unchanged. This is out of scope for the first
slice and listed here so the architecture leaves room for it.

---

## 10. Phase 2: card fetch + crawler

Two capabilities are deferred to a second phase:

- **Card fetch.** Today an entry's `url` points at the agent's
  metadata document (agent card or MCP server descriptor); the finder
  does not fetch it. Phase 2 may fetch and validate the card to enrich
  ranking and to surface `representativeQueries` (ARD §4.2), which the
  events contract does not carry.
- **Crawler (ARD-required Web Ingestion).** ARD §6.2 makes crawling
  `ai-catalog.json` files a **required** ingestion pipeline for a
  conformant registry. The first slice does not crawl; it ingests only
  the ANS feed. Web ingestion is a phase-2 addition that brings the
  finder to full ARD ingestion conformance. Until then the finder is a
  single-source registry by design (§5, trade 3).

---

## 11. Trust model

The finder asserts **feed-derived data, including lifecycle state**. It
is a search convenience layered over the RA and TL, not an independent
authority. Precisely:

- **Lifecycle/revocation freshness is only as good as the feed.** The
  finder shows an agent as active until it ingests a revocation. A feed
  stall is revocation latency for the duration of the stall (§5,
  trade 4). Clients that need certainty about current state must check
  the receipt or the TL status token, not the finder's answer.
- **Receipt semantics, stated precisely.** Each entry's
  `ANS-Registration` attestation is a SCITT receipt URI that proves
  inclusion of the agent's **latest sealed event**. It does **not** by
  itself prove the entry's *content* matches what was sealed. To verify
  content, a client fetches the agent's badge envelope from the TL
  (`GET /v1/agents/{agentId}`) and field-compares. The latest-event
  inclusion property also serves as the revocation/freshness check: if
  the latest sealed event is a revocation, resolving the receipt
  reveals it.
- **Divergence is client-detectable.** Each entry carries
  `metadata.logId`. If the finder built an entry from an older event
  than the receipt proves, the `logId` mismatch lets the client detect
  it.
- **Residual risks are accepted and disclosed.** Because revocation
  rides the unsigned feed over TLS-verified transport (the sole
  ingestion integrity control), split-view (the RA seals one thing and
  feeds another) and silent omission (an opaque cursor with no
  contiguity signal) are accepted residual risks. They are detectable
  only by client receipt verification or an external log-vs-index
  audit, not by the finder itself.
- **The score is not a trust signal.** Per ARD §7.2, the `score` is a
  relevance metric (0–100) and MUST NOT be read as a trust, compliance,
  or safety rating. Trust evaluation is decoupled and handled through
  the trust manifest / receipt.

---

## 12. Config / deployment

`ans-finder` runs as a fourth binary.

- **Port**: `:18082` (RA is `:18080`, TL is `:18081`).
- **Storage**: its own SQLite database (§7), independent of RA and TL.
- **Ingestion config**: the feed base URL (must be https with verified
  TLS; plaintext only behind a dev override — §13.d), poll cadence, and
  staleness bound (PR 3).
- **Health / readiness**: standard health and readiness endpoints so
  the service can be probed in a container orchestrator. Readiness
  should reflect whether the index has completed an initial ingestion
  pass.
- **Logging**: the finder uses `slog` (the rest of the codebase uses
  `zerolog`; this split is noted so contributors don't assume one
  logger throughout).

---

## 13. Security contracts

These contracts MUST be frozen before PR 1 ships any wire format,
because once a verifier or an AI orchestrator encodes against the wire,
changing it is a breaking change. They precede the PR 1 wire freeze.

### (a) Text hygiene

Every emitted string passes through **one chokepoint** that strips
Unicode `Cc` control characters plus the `Cf` bidi and zero-width
characters that can be used to spoof or hide content in an
orchestrator's display — at minimum the right-to-left override
(`U+202E`), the bidi isolates (`U+2066`–`U+2069`), and the
zero-width-space family. Marshaling uses the standard library
`encoding/json` HTML-escaping behavior, **never** the JCS marshaller
(JCS is for signing, not for emitting display text to a browser-facing
client). The spec marks every free-text field as untrusted. The
chokepoint is applied to display name, description, capabilities, tags,
version, and metadata string values.

### (b) URL policy

**Every emitted URL** — including constructed well-known fallbacks and
`metadata.agentUrl` — passes through **one shared chokepoint**,
`validateEmittedURL(raw, attestedHost)`. The policy:

- absolute URL;
- `https` scheme (a dev `AllowHTTP` override permits `http` for local
  testing only);
- no userinfo, no query, no fragment;
- hostname (port-stripped, case-insensitive) equal to the attested
  `agentHost`, following `ValidateHostMatch` semantics
  ([endpoint.go:125](../../internal/domain/endpoint.go) — parses the
  URL, lowercases `parsed.Hostname()`, compares to the lowercased
  expected FQDN). Non-default ports are permitted by design and
  documented;
- fail-closed on any violation.

**No emitted URL is ever built by string concatenation alone.** The
constructed well-known fallback goes through this same chokepoint; it
is never trusted because the finder built it. This policy mirrors the
existing config-side precedent
([config.go:424](../../internal/config/config.go) `validatePublicBaseURL`:
https-only, host required, no userinfo/query/fragment).

### (c) Identity-field syntax validation

The feed validator structurally validates identity fields:

- `agentHost` is validated by `domain.ParseAnsName(ansName)` followed
  by `parsed.FQDN() == lower(agentHost)` — this both syntax-validates
  the host (RFC 1123 via `ParseAnsName`,
  [ansname.go:37](../../internal/domain/ansname.go)) and binds the host
  to the `ansName` in one step
  ([ansname.go:101](../../internal/domain/ansname.go) `FQDN()` returns
  the lowercased host).
- `agentId` is validated as a UUID.
- `createdAt` is validated as RFC 3339.

All are structural checks at the ingestion boundary.

### (d) Feed transport

The feed base URL must be `https` with verified TLS. Plaintext is
permitted only behind an explicit dev override, and TLS verification is
**never** skipped — TLS-verified transport is the sole ingestion
integrity control (§5, trade 4), so weakening it removes the only
guard against a tampered feed.

### (e) Rate limiting

Search is unauthenticated (§13.g), so the search endpoint is rate
limited to bound the cost of anonymous traffic.

### (f) Federation referrals are config-only

Referral targets are operator configuration. The finder does not
auto-follow referrals or auto-discover upstream registries; `auto`
federation does not silently fan out in this slice. This prevents a
search from triggering outbound requests to attacker-influenced
endpoints.

### (g) Auth exemption for the events route

The events route is anonymous by design (it is a public feed). The auth
layer grants it an **exact-path** exemption — not a prefix exemption —
so the exemption cannot be widened by a crafted path.

### (h) Follow-up hardening PR (out of slice)

Two RA-side hardening items are identified but deliberately out of this
slice:

- **RA-side URL scheme allowlist.** The RA's current URL validation
  ([endpoint.go:205](../../internal/domain/endpoint.go) `validateURL`)
  rejects only an *empty* scheme (`parsed.Scheme == ""`); it does not
  enforce an https/scheme allowlist. A follow-up PR should add a scheme
  allowlist at that validation site. The finder defends itself with its
  own emit-side URL policy (§13.b) regardless, but tightening the RA
  source is the right long-term fix.
- **Charset guard on display fields.** A complementary RA-side guard on
  the charset of display fields would reduce the burden on the finder's
  sanitization chokepoint.

Both are recorded here so the finder's emit-side defenses are
understood as the near-term control, with RA-side tightening as
follow-up.

---

## 14. Test / coverage per PR

| PR | Package | Coverage requirement |
|---|---|---|
| docs | — | none (docs-only; `make check` must still pass) |
| PR 0 | `internal/lognote` | 100% of statements; `go list -deps ./cmd/ans-verify` clean of TL/Tessera storage; golden checkpoint note verifies end-to-end with a real key |
| PR 1 | `internal/finder/feed`, `internal/finder/project` | 100% of statements each; golden vectors regenerate cleanly; fixture shapes diffed field-by-field against `swagger_ans.json` |

Overall repository coverage must stay at or above the 90% gate
enforced by `make test-cover` across `internal/`. PR 1's golden vectors
cover the registered fan-out (A2A + MCP + HTTP-API exclusion), the
revoked and revoked-minimal tombstone paths, contract-shape-only
renewed and deprecated fixtures, no-endpoints and no-display-name
edge cases, an adversarial-text fixture (ESC, `U+202E`, zero-width,
NUL across every text path), and a non-`Z`-offset timestamp fixture to
pin verbatim passthrough. The live cross-check (register an agent →
feed returns its `EventItem` → `FromEvent` output matches the golden)
happens in PR 2's demo.

---

## 15. Deviations

Each row is a deliberate departure from a referenced contract, with its
rationale. Deviations are flagged, not silently resolved.

| # | Deviation | From | Rationale |
|---|---|---|---|
| 1 | Error body is RFC 7807 `Problem`, not the RA spec's `ErrorResponse` | RA OpenAPI spec | The RA spec's documented `ErrorResponse` has drifted from the RA's *actual* handler ([errors.go:14](../../internal/ra/handler/errors.go), which emits `Problem`). The finder matches the real handler and the TL spec. Reconciling the RA spec to its handler is an upstream candidate. |
| 2 | Endpoints live under `/v1/search`, `/v1/explore` | ARD §7 (which writes `/search`, `/explore`) | ARD discovers the operational base URL dynamically via the `application/ai-registry+json` catalog entry (§4.1, §7), so a `/v1` base path is ARD-compatible — the version lives in the discovered base, the relative paths match. |
| 3 | Invalid arguments return `400`, not the house `422` | CLAUDE.md house style (422) | ARD's convention is `400` for invalid arguments (§7.1). The finder follows the protocol it implements on its own surface. |
| 4 | `pageSize` defaults to 10 | (no single house default) | Matches ARD §7.2's documented default of 10 for Search (the house list endpoint uses 20; ARD's own List endpoint also uses 20, but Search is the relevant operation here). |
| 5 | Search/Explore are `POST`, not `GET` | REST cacheability intuition | The query is a structured object and responses are non-cacheable; ARD §7 specifies `POST` for both. Each operation documents this. |
| 6 | `identifier` is a lineage handle, not a per-instance unique key | ARD §4.2.1 (globally unique identifier) | The URN `urn:ai:{agentHost}:agents:{label}` is shared across version successions of the same logical agent by design. Per-registration uniqueness is carried on the wrapper keys (`agentId` / `ansName`), and the intra-host label space is publisher-owned. An empty/missing label means Active entries are **Skipped** (no fallback); **tombstones are unaffected** because they never depend on labels (§6). |
| 7 | Attestation carries no content `digest` | ARD §5.2 (digest optional) | The receipt proves latest-event *inclusion*, not entry *content* (§5, §11). A content digest would overclaim what the receipt verifies, so it is omitted deliberately. |
| 8 | Unknown `eventType` is an alertable Skip, not an error | strict validation intuition | Feed-only ingestion behind a cursor means a structural error on an unknown event type would halt the only ingestion source at that cursor when the producer's enum grows. Fail-closed must not mean fail-stuck (§6). |
| 9 | Protocol-token map (domain underscored ↔ wire hyphenated) is owned by the feed-route PR (PR 2) | — | The OSS domain tokens are underscored (`HTTP_API`, `STREAMABLE_HTTP`, `JSON_RPC` — [protocol.go:14,51-53](../../internal/domain/protocol.go)) and the wire is hyphenated (`HTTP-API`, `STREAMABLE-HTTP`, `JSON-RPC`). PR 2 owns the explicit domain→wire token map and asserts enum *values* against the swagger, not just marshal shape. The finder's `feed` types use the production hyphenated values directly. |

---

## 16. Risks

1. **ARDS transcription fidelity.** The canonical ards.io site is
   auth-gated; the source used here is the working group's public
   `docs/spec.md` (v0.5 Draft, 2026-05-28). Mitigation: the appendix
   (§17) transcribes the field tables verbatim with section citations,
   so any drift is checkable against the source.
2. **Production-swagger fidelity for `feed` types.** The finder's
   consumer-side types must match `swagger_ans.json` byte-for-byte.
   Mitigation: the appendix transcribes the `EventPageResponse` /
   `EventItem` / `AgentEndpoint` / `AgentFunction` tables verbatim, and
   PR 2's conformance tests close the loop on both shape and enum
   values.
3. **PR 0 parser-unification byte-compat.** Extracting the duplicated
   checkpoint parser into `internal/lognote` must not change the bytes
   verified. Mitigation: reconciliation pin tests, including an
   adversarial case (known keyhash + garbage signature → rejected, and
   parsing continues to a later valid line).
4. **URN non-injectivity.** The lineage-handle URN is intentionally
   shared across version successions, so it is not a unique key.
   Mitigation: per-registration uniqueness lives on the wrapper keys;
   tombstones never depend on labels.
5. **Registrant text and URLs reaching AI orchestrators.** This is the
   sharpest risk: registrant-controlled strings and URLs flow toward an
   LLM. Mitigation: a single text-sanitization chokepoint (§13.a) and a
   single URL-policy chokepoint (§13.b), with both contracts frozen
   before any wire ships.
6. **Renewed/deprecated have no OSS producer.** The projection supports
   all four contract event types, but only registered and revoked have
   producers on `main`. Mitigation: renewed/deprecated fixtures are
   contract-shape-only; live validation covers registered and revoked.

---

## 17. Appendix: verbatim field tables

### 17.1 ARDS v0.5 — Catalog Entry Object (§4.2)

Each object in the `entries` array MUST contain:

| Field | Type | Description |
|---|---|---|
| identifier | String | Globally unique logical identifier for discovery. MUST use a domain-anchored URN namespace format (`urn:ai:<publisher>:<namespace>:<agent-name>`) where `<publisher>` is a verifiable domain name. This guarantees cross-network uniqueness, nomenclature stability, and decentralized trust binding. See §4.2.1 for detailed format specifications and architectural rationale. |
| displayName | String | Human-readable name. |
| type | String | Type of the AI artifact. |

Exactly one of the following MUST be present:

| Field | Type | Description |
|---|---|---|
| url | String | URL to retrieve the full artifact. |
| data | Object | The complete artifact document inline. |

Optional fields:

| Field | Type | Description |
|---|---|---|
| description | String | Short description. |
| tags | Array | Keywords for filtering. |
| capabilities | Array | Strings representing specific skills or tools (e.g., `["WeatherTool"]`) to enable fast discovery database filtering without full artifact lookup. |
| representativeQueries | Array | Sample natural-language queries (e.g., `["find me a flight booking agent"]`). Used by registries to build semantic vector embeddings for search ranking. SHOULD contain 2–5 examples. |
| version | String | Version of the artifact. |
| updatedAt | String | ISO 8601 timestamp. |
| metadata | Map | Custom metadata key-value pairs. |
| trustManifest | Object | Verifiable identity and trust metadata. |

### 17.2 ARDS v0.5 — Trust Manifest Object (§5.1)

The `trustManifest` object sits alongside the artifact content in a
catalog entry and contains the following key members:

| Field | Type | Description |
|---|---|---|
| identity | String | **Required**. Globally unique cryptographic workload identifier (e.g., a SPIFFE ID, DID, or HTTPS FQDN URI). Decoupled from the entry's discovery identifier. The cryptographic trust domain inside this identity MUST align with the authority domain root embedded in the discovery identifier namespace. |
| identityType | String | Optional. Type hint for the identity URI (e.g., "did", "spiffe", "https"). |
| attestations | Array | Optional. List of Attestation objects providing verifiable claims. |
| provenance | Array | Optional. List of Provenance Link objects recording lineage. |
| signature | String | Optional. Detached JWS signature computed over the Trust Manifest content. |

### 17.3 ARDS v0.5 — Attestation Object (§5.2)

| Field | Type | Description |
|---|---|---|
| type | String | **Required**. Attestation type (e.g., "SOC2-Type2", "HIPAA-Audit"). |
| uri | String | **Required**. Location of the attestation document. |
| mediaType | String | **Required**. Format of the document (e.g., "application/pdf"). |
| digest | String | Optional. Cryptographic hash for integrity verification. |

### 17.4 ARDS v0.5 — Provenance Link Object (§5.3)

| Field | Type | Description |
|---|---|---|
| relation | String | **Required**. Relationship type (e.g., "derivedFrom", "publishedFrom"). |
| sourceId | String | **Required**. Identifier of the source artifact or data. |
| sourceDigest | String | Optional. Digest of the source for verification. |

### 17.5 ARDS v0.5 — Query Model (§7.1)

The `POST /search` and `POST /explore` endpoints accept a common
`query` object with two members, `text` and `filter`:

| Field | Type | Description |
|---|---|---|
| text | String | Natural-language description of the need. Narrows the result set by semantic relevance. |
| filter | Object | Structured constraints. Keys are field paths into the catalog entry; values are arrays (a bare scalar is accepted as a single-element array). |

**Filter Semantics** (§7.1): Field paths are dot-separated to address
nested fields (e.g. `trustManifest.attestations.type`). When the value
at a path is an array, a constraint matches if any element satisfies
it. Within a single key, values are combined with OR; across keys, with
AND. The `publisher` key is derived from the `<publisher>` segment of
an entry's URN identifier (§4.2.1), not a stored field. A registry MAY
reject a filter that references an unsupported field path with a `400`
error.

### 17.6 ARDS v0.5 — Search request additions (§7.2)

For Search, `text` is required and `filter` is optional. In addition to
the `query` object, Search accepts:

| Field | Type | Description |
|---|---|---|
| federation | String | Optional. auto (default), referrals, or none. |
| pageSize | Integer | Optional (root-level). Max results to return per page (default: 10, max: 100). |
| pageToken | String | Optional (root-level). Pagination token to retrieve the next page. |

### 17.7 ARDS v0.5 — Search response (§7.2)

The response returns standard catalog entries with additional
relevance scores, plus optional referrals. Per §7.2, the `score`
denotes semantic relevance ranking (0–100) computed by the search
registry; it is strictly an informational relevance metric and MUST
NOT be interpreted by orchestrators as a cryptographic trust,
compliance, or safety rating. The response object carries `results[]`
(each a catalog entry plus `score` and `source`), an optional
`referrals[]`, and an optional `pageToken` for the next page.

### 17.8 ARDS v0.5 — Explore request additions (§7.3)

For Explore, `text` and `filter` are both optional; when both are
absent the aggregation covers the entire registry. In addition to the
`query` object, Explore accepts:

| Field | Type | Description |
|---|---|---|
| resultType | Object | Required. The shape of result to compute. The only defined shape is facets (below); future shapes such as counts or sample extend this field without protocol changes. |

Each element of `resultType.facets`:

| Field | Type | Description |
|---|---|---|
| field | String | Required. Field path to aggregate (same syntax as filter keys, §7.1). |
| limit | Integer | Optional. Maximum number of buckets returned. Default: 20. |
| minCount | Integer | Optional. Suppress buckets with counts below this threshold. |

**Explore response** (§7.3): a `resultType: "facets"` object whose
`facets` map keys each field to `{buckets: [{value, count}], otherCount}`.
Each bucket carries `value` and SHOULD carry `count`; `otherCount`
reports matching entries in buckets beyond `limit`. Facets are computed
over the full matched set, not a single page. Explore does not
federate; a registry that does not implement it returns `501 Not
Implemented`.

### 17.9 ARDS v0.5 — Federation (§8)

The client controls federation through the `federation` query
parameter:

| Value | Behavior |
|---|---|
| auto | The Registry queries upstream registries automatically, merges their results with its own, and returns a unified response. The client gets a single merged result set. |
| referrals | The Registry returns its results plus catalog entries for other Registries the client may query. The client decides which to follow. |
| none | The Registry searches only its own index. |

### 17.10 Production swagger — `EventPageResponse`

Source: `swagger_ans.json`, `definitions.EventPageResponse`. Required:
`items`.

| Field | Type | Required | Description |
|---|---|---|---|
| items | array of `EventItem` | yes | Array of event items. |
| lastLogId | string | no | The log ID of the last event in this page. Use as the `lastLogId` parameter in the next request to retrieve the subsequent page. Omitted when there are no more results. |

Note: the consumer-side Go type marshals `items` as `[]` (never
`null`) and tags `lastLogId` with `omitempty`.

### 17.11 Production swagger — `EventItem`

Source: `swagger_ans.json`, `definitions.EventItem`. Required: `logId`,
`eventType`, `createdAt`, `agentId`, `ansName`, `agentHost`, `version`.

| Field | Type | Required | Constraints / notes |
|---|---|---|---|
| logId | string | yes | Unique identifier for this event in the stream. |
| eventType | string (enum) | yes | One of `AGENT_DEPRECATED`, `AGENT_REGISTERED`, `AGENT_REVOKED`, `AGENT_RENEWED`. |
| createdAt | string (date-time) | yes | Timestamp when the event was created. |
| expiresAt | string (date-time) | no | When the agent's registration expires (if applicable). |
| agentId | string | yes | Unique identifier of the agent. |
| ansName | string | yes | Fully qualified ANS name in format `ans://{version}.{agentHost}`. |
| agentHost | string | yes | The agent's hosting domain. maxLength 253. |
| agentDisplayName | string | no | Human-readable display name. maxLength 64. |
| agentDescription | string | no | Description of the agent. maxLength 150. |
| version | string | yes | Semantic version of the agent. |
| providerId | string | no | The provider identifier associated with the agent (if any). |
| endpoints | array of `AgentEndpoint` | no | Array of agent endpoints with protocol-specific configuration. |

### 17.12 Production swagger — `AgentEndpoint`

Source: `swagger_ans.json`, `definitions.AgentEndpoint`. Required:
`agentUrl`, `protocol`.

| Field | Type | Required | Constraints / notes |
|---|---|---|---|
| agentUrl | string (uri) | yes | The URL where the agent is hosted and accepts requests. |
| metaDataUrl | string (uri) | no | URL for agent metadata. |
| documentationUrl | string (uri) | no | URL for agent documentation. |
| protocol | string (enum) | yes | One of `A2A`, `MCP`, `HTTP-API`. |
| functions | array of `AgentFunction` | no | Functions provided by this endpoint. The meaning varies by protocol: for MCP these are tools, for A2A these are skills, for HTTP-API these are routes. |
| transports | array of string (enum) | no | One or more of `STREAMABLE-HTTP`, `SSE`, `JSON-RPC`, `GRPC`, `REST`, `HTTP`. |

### 17.13 Production swagger — `AgentFunction`

Source: `swagger_ans.json`, `definitions.AgentFunction`. Required:
`id`, `name`.

| Field | Type | Required | Constraints / notes |
|---|---|---|---|
| id | string | yes | Unique identifier for the function. maxLength 64. |
| name | string | yes | Human-readable name for the function. maxLength 64. |
| tags | array of string | no | Tags for categorizing and discovering functions. maxItems 5; each item maxLength 20. |

### 17.14 Token note: domain underscore vs. wire hyphen

The OSS domain layer and the production wire use different spellings
for the same protocol and transport enums. The `feed` consumer types
use the **production hyphenated wire values**; the OSS RA's domain
layer uses **underscored values**, with the domain→wire mapping owned
by the feed-route PR (PR 2) and asserted against the swagger.

| Concept | OSS domain token | Production wire token |
|---|---|---|
| HTTP API protocol | `HTTP_API` ([protocol.go:14](../../internal/domain/protocol.go)) | `HTTP-API` |
| Streamable HTTP transport | `STREAMABLE_HTTP` ([protocol.go:51](../../internal/domain/protocol.go)) | `STREAMABLE-HTTP` |
| JSON-RPC transport | `JSON_RPC` ([protocol.go:53](../../internal/domain/protocol.go)) | `JSON-RPC` |

`A2A` and `MCP` are spelled identically in both layers, so only the
three multi-word tokens above differ.

---

## Source references

- **ARD spec**: Agentic Resource Discovery Specification, v0.5 (Draft),
  2026-05-28 — working-group public `docs/spec.md`. Section citations
  throughout (§3.4, §4.1, §4.2, §4.2.1, §5.1–5.3, §6.2, §7.1–7.3, §8).
- **Production events contract**: `swagger_ans.json`
  (developer.godaddy.com), `definitions.EventPageResponse` /
  `EventItem` / `AgentEndpoint` / `AgentFunction`.
- **In-repo citations**: `internal/domain/protocol.go`,
  `internal/domain/agent.go`, `internal/domain/events.go`,
  `internal/domain/ansname.go`, `internal/domain/endpoint.go`,
  `internal/adapter/eventbus/inmemory.go`,
  `internal/adapter/store/sqlite/outbox.go`,
  `internal/ra/service/registration.go`,
  `internal/ra/handler/errors.go`, `internal/config/config.go`.
