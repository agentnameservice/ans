# Composing capability descriptors via `metaDataUrl`

ANS discovers and cryptographically verifies agents by name. Once a caller has
done that, a natural next question is *what can I actually do with this agent,
and how?* — where "how" may mean calling it, authenticating to it, or paying it.

This demo shows that the answer is already in the schema. An ANS-registered
agent can advertise arbitrary capabilities through the existing optional
`AgentEndpoint.metaDataUrl`, pinned with `metaDataHash` and published as a `cap`
locator by the default `ANS_DNSAID` discovery profile. No new `Protocol` enum
member, no new `DiscoveryProfile`, no wire change, no Go change.

Payment is used as the worked example below because it is the case people most
often assume needs new protocol machinery. It does not.

```
scripts/demo/payable-endpoints/verify.sh          # offline, fixtures only
scripts/demo/payable-endpoints/verify.sh --live   # also compare the live descriptor
```

No running ANS stack is required to *run* this demo — it asserts against
committed fixtures. Those fixtures were produced by running the registration
below against `ans-ra` from `scripts/demo/start.sh`; see "Reproducing the
fixtures" at the end.

## The gap this closes

The `Protocol` enum is deliberately transport-only — `A2A`, `MCP`, `HTTP_API`.
`internal/catalog/generate.go` says so directly:

```go
// The protocol enum is A2A/MCP/HTTP-API;
// there is no PAYMENT.
```

That is the right call. Payment is not a discovery transport, and baking a rail
into the enum would drag ANS toward settlement concerns it should not own. But
it leaves the follow-on question unanswered in the docs, and the absence reads
to integrators as a missing feature rather than a deliberate boundary.

## The mechanism: capability is metadata, not protocol

`metaDataUrl` (`spec/api-spec-v2.yaml`, `components.schemas.AgentEndpoint`) is an
optional `https` URI whose only job is to locate a richer descriptor for the
endpoint. Nothing constrains what that descriptor advertises. If the descriptor
declares a capability, then following `metaDataUrl` is how a caller learns of
it — through machinery that already ships.

Two implementation constraints shape any such composition:

1. **Catalog eligibility is `A2A`/`MCP` only.** `protocolMediaType`
   (`internal/catalog/generate.go`) yields an artifact media type only for `A2A`
   and `MCP`; `HTTP_API` endpoints are catalog-ineligible
   (`NO_ELIGIBLE_ENDPOINT`). A descriptor must ride an `A2A` or `MCP` endpoint to
   be both discoverable *and* capability-bearing. An `HTTP_API` endpoint can
   still carry a `cap` over DNS-AID, but will not surface in the ARD catalog.
2. **`metaDataUrl` host must equal `agentHost`.** The emit-side URL policy
   (`internal/catalog/generate.go`, `internal/finder/project/project.go`, and the
   spec text) requires absolute `https`, no userinfo/query/fragment, and
   `host == agentHost`. An off-host `metaDataUrl` fails catalog eligibility and
   is published without an integrity pin unless `metaDataHash` is supplied.
   **Host the descriptor on the same origin as the agent.**

## Worked example: an A2A card advertising payment tooling

The committed fixture — `testdata/agent-card.json` — is an A2A agent-card whose
skills include `get_payment_requirements` (which returns an x402 `accepts`
block), alongside `resolve_alias`, `discover_agent`, `check_alias_available`, and
`get_agent_registration_info`. It is served from the same host registered as
`agentHost`, so the same-host policy holds and the endpoint stays
catalog-eligible.

`verify.sh` prints the registration body this produces:

```json
{
  "agentHost": "api.dnsofmoney.com",
  "discoveryProfiles": ["ANS_DNSAID"],
  "endpoints": [
    {
      "protocol": "A2A",
      "agentUrl": "https://api.dnsofmoney.com/a2a/v1",
      "metaDataUrl": "https://api.dnsofmoney.com/.well-known/agent-card.json",
      "metaDataHash": "SHA256:23133f65cc200a06f79009d3b43e65dd743fb7d0a914109274a6c5b5a9c0d41b",
      "transports": ["JSON_RPC"]
    }
  ]
}
```

Wire keys are capital-D `metaDataUrl` / `metaDataHash`, matching
`scripts/demo/register.sh`.

Nothing here is payment-specific except the contents of the descriptor. Swap the
card for one advertising a different capability and every field above is
unchanged.

## What `ANS_DNSAID` emits

With `discoveryProfiles` defaulting to `["ANS_DNSAID"]`, the RA provisions
RFC 9460 SVCB rows (ServiceMode `1 .` at the agent FQDN) via
`internal/adapter/discovery/ans/dnsaid.go`.

This is the row `ans-ra` **actually emitted** for the registration above,
captured verbatim from `scripts/demo/dns-records.sh --json` and committed as
`testdata/expected-svcb.txt`:

```
1 . alpn=a2a port=443 key65400=https://api.dnsofmoney.com/.well-known/agent-card.json key65401=IxM_ZcwgCgb3kAnTtD5l3XQ_t9CpFBCSdKbFtanA1Bs key65402=a2a key65409=agent-card.json
```

| SvcParam | Value | Source |
|---|---|---|
| `alpn` | `a2a` | from the endpoint's `protocol` |
| `port` | `443` | default |
| `key65400` (`cap`) | the `metaDataUrl` | the locator a resolver follows |
| `key65401` (`cap-sha256`) | `IxM_ZcwgCgb3kAnTtD5l3XQ_t9CpFBCSdKbFtanA1Bs` | base64url of the **raw** digest bytes, not the hex text |
| `key65402` (`bap`) | `a2a` | agent protocol |
| `key65409` (`well-known`) | `agent-card.json` | emitted because `metaDataUrl` is a `https://{fqdn}/.well-known/<suffix>` URL |

`verify.sh` **derives** `cap-sha256` from the fixture and asserts it against this
recorded row. The check is therefore against reference-implementation output, not
against a value the script re-computed for itself — if the emit path changes
shape, the demo fails rather than agreeing with its own arithmetic.

The same registration also emits a `_ans-badge` TXT record and a `_443._tcp`
TLSA record. Those are the standard `ANS_DNSAID` record set and are unrelated to
the capability composition; they are omitted from the fixture deliberately, since
the badge URL embeds a per-run `agentId`.

A resolver that already speaks `ANS_DNSAID` needs no new capability to reach an
integrity-pinned capability descriptor.

## The integrity pin

The fixture's SHA-256 is:

```
23133f65cc200a06f79009d3b43e65dd743fb7d0a914109274a6c5b5a9c0d41b
```

`verify.sh` asserts the committed fixture against this value. That assertion is
offline and deterministic, so this example stays verifiable regardless of what
the live endpoint does later.

`--live` additionally fetches the real descriptor and compares. **A mismatch
there is reported, not failed.** A changed descriptor is either drift or a
legitimate new version, and a digest alone cannot distinguish the two — which is
precisely why the teaching example is pinned to a fixture rather than to
whatever the network happens to return.

That distinction is the practical lesson of `metaDataHash`: it detects change,
and change is the operator's signal to re-verify and re-register. It is not a
liveness check.

## Scope and non-goals

**In scope:** documenting that ANS already supports capability-bearing agents via
`metaDataUrl` + `metaDataHash` + `ANS_DNSAID`, with a runnable, verifiable
example.

**Non-goals:**

- No new `Protocol` enum member. The enum stays transport-only, as the code
  comment intends.
- No new `DiscoveryProfile` value; the enum stays `[ANS_DNSAID, ANS_TXT]`.
- No change to the RA, TL, verifier, or the wire contract. Zero Go changes.
- No claim that ANS settles, custodies, or routes anything. The capability lives
  entirely in the descriptor the caller fetches; ANS's role ends at verified
  discovery.

## Reproducing the fixtures

`testdata/expected-svcb.txt` is recorded output, not a hand-written expectation.
To regenerate it against a local stack:

```bash
scripts/demo/start.sh
# register the endpoint with the metaDataUrl + metaDataHash shown above
# (register.sh does not send metaDataHash, so POST /v2/ans/agents directly),
# then drive it to PENDING_DNS:
#   POST /v2/ans/agents/{agentId}/verify-acme
scripts/demo/dns-records.sh --json | jq -r '.[] | select(.type=="SVCB") | .value' \
  > scripts/demo/payable-endpoints/testdata/expected-svcb.txt
scripts/demo/stop.sh --clean
```

Recorded against `upstream/main` at `d8ed4bb` on 2026-08-01.

## References

- `spec/api-spec-v2.yaml` — `AgentEndpoint` (`metaDataUrl`, `metaDataHash`), `DiscoveryProfile`.
- `internal/catalog/generate.go` — catalog eligibility, the "no PAYMENT" comment, host policy.
- `internal/adapter/discovery/ans/dnsaid.go` — `cap` / `cap-sha256` / `well-known` SvcParam emission.
- `scripts/demo/register.sh` — the registration body shape this example matches.
- RFC 9460 (SVCB), the A2A agent-card spec, and x402 (HTTP 402 agent payments) for the worked example.
