# vLEI ecosystem + identifier / `verify-control` demo

This directory stands up a **local, self-contained** GLEIF/KERI stack so
a genuine AID holding a (self-issued) vLEI can be registered with the RA
on the identity-scoped routes — `POST /v2/ans/identities` (carrying the
full-chain CESR) + `.../verify-control` — and the RA can present it to,
and verify the AID-signed `signingInput` against, a **real
`vlei-verifier`**, seal the `IDENTITY_VERIFIED` event on the TL, and link
the verified `lei` identity to an agent.

Proves the *RA integration* against the stock
GLEIF verifier, including the credential-chain / authorized-LEI check.

## No genuine LEI/vLEI required

The entire ecosystem is self-issued against a **synthetic local GLEIF
root** registered via `POST /root_of_trust/{aid}` (the verifier runs
with `VERIFIER_ENV=development`, `VERIFY_ROOT_OF_TRUST=True`). The LEI is
any well-formed 20-char string you choose — the verifier checks the
chain to *your* local root, not `api.gleif.org`. The RA's `ValidateLEI`
checks ISO-17442 **format only** (20-char `[A-Z0-9]`), so any well-formed
string works; `build-chain.ts` uses LEI `875500ELOZEL05BVXV37`.

A genuine vLEI is needed *only* if you point the verifier at the real
GLEIF production root — out of scope here.

## Notes
- **Everything is version-pinned for reproducibility.** GLEIF's
  KERI/KERIA/vLEI images and the `vlei-verifier` config schema move
  between releases, so the compose file pins every image to a known-good
  tag (`weboftrust/keri:1.2.0-rc4`, `gleif/vlei:1.0.0`,
  `gleif/keria:0.3.0`) and builds the verifier from the `0.1.5` source.
  The verifier uses its own bundled `verifier-config-docker-local.json`
  (keri-style `iurls`/`durls` pointing at `witness-demo` + `vlei-server`),
  so there is no local config file to keep in sync. Bumping any pin means
  re-confirming flags/endpoints and the config shape against that release.
- **The RA is the single touchpoint for the verifier.** The holder hands
  the RA their full-chain credential CESR via the `vleiPresentation` of
  `POST /v2/ans/identities`; the RA reads the leaf credential SAID out of
  it (the only thing it parses — never KERI key state), presents the chain
  to the verifier (`PUT /presentations/{said}`), reads the verifier-reported
  subject AID, and pins it on the identity. The holder never calls the
  verifier directly. The one bootstrap the RA can't do is registering the
  *synthetic local* GLEIF root of trust — that is a one-time admin step
  against the verifier (`build-chain.ts` does it).

## Components (`docker-compose.yml`)

| Service | Image | Ports | Role |
|---|---|---|---|
| `witnesses` | `weboftrust/keri:1.2.0-rc4` | 5642-5644 | KERI witness network (key-event logs) |
| `vlei-server` | `gleif/vlei:1.0.0` | 7723 | ACDC schema + OOBI server (LE/OOR/ECR/QVI) |
| `keria` | `gleif/keria:0.3.0` | 3901-3903 | KERIA edge agent for the holder (signify-ts) |
| `vlei-verifier` | built from source @ `0.1.5` | **7676** | the service `ans-ra` calls |
| `signify` | `denoland/deno:alpine-2.8.2` | — | runs `build-chain.ts` (build chain, present, export) and `sign-proof.ts` |

> `vlei-verifier` is not published to any registry, so the compose file
> builds it from the pinned [`GLEIF-IT/vlei-verifier`](https://github.com/GLEIF-IT/vlei-verifier)
> `0.1.5` tag via a git build context. The first `up.sh` therefore runs a
> `docker build` (git clone + `pip install`) that takes a few minutes; later
> runs reuse the cached `ans-vlei-verifier:0.1.5` image. The verifier loads
> its **bundled** `verifier-config-docker-local.json` (selected via
> `VERIFIER_CONFIG_FILE`), which already points at this stack's `witness-demo`
> and `vlei-server` hostnames — there is no local config file to edit.

> **The SignifyTS runner is self-contained.** The `signify` service is the
> stock `denoland/deno` image — no custom build. It bind-mounts
> [`signify/`](signify/) in this directory, which holds the demo's
> [`scripts_ts/`](signify/scripts_ts/): `build-chain.ts` (the trust-chain build,
> converted from the old `ans-vlei-verifier.ipynb`), `sign-proof.ts` (the
> standalone proof signer), and `utils.ts` (the SignifyTS helpers, vendored from
> [GLEIF-IT/vlei-trainings](https://github.com/GLEIF-IT/vlei-trainings)). The
> container is on the same Docker network as the rest of the stack and reaches
> `keria`, `vlei-server`, `witness-demo`, and `vlei-verifier` by service name —
> no external network / `docker network connect` required. On start it pre-caches
> the npm deps (`signify-ts`, `libsodium`) so the first `deno run` is fast. The
> exported artifacts land in [`signify/out/`](signify/out/) via the bind mount.
> When re-vendoring, re-pull `utils.ts` from the upstream repo.

## End-to-end sequence

### Prerequisites (the RA — once)

The vLEI stack is self-contained, but the RA owns its own lifecycle, so two
RA-side steps happen first:

1. **Enable the verifier wiring.** Set the `vlei:` block in
   `config/ra-local.yaml` to the real verifier (it ships as `type: noop`):
   ```yaml
   vlei:
     type: verifier
     base-url: "http://localhost:7676"
   ```
   The identity routes (`POST /v2/ans/identities`, `.../verify-control`,
   `.../links`) are always registered — `did:web`/`did:key` use them too.
   `vlei.type` only selects which control verifier backs the `lei` kind:
   `noop` runs real Ed25519 crypto but waives the GLEIF authorization
   binding (zero-infra quickstart), while `verifier` routes every
   CESR/KERI question to this stack's `vlei-verifier`. The real end-to-end
   flow below requires `type: verifier`.
2. **Start the RA and register an agent.** `scripts/demo/start.sh` starts
   `ans-ra`; `scripts/demo/run-lifecycle.sh` registers an agent and writes its
   id to `data/demo/vlei/last-agent-id`. That id is the `AGENT_ID` below.

### Commands

```bash
ANS_VLEI_TYPE=verifier ANS_VLEI_BASE_URL=http://localhost:7676 ./scripts/demo/start.sh
AGENT_ID=$(scripts/demo/register.sh --v2)
scripts/demo/vlei/run-vlei.sh
```

`run-vlei.sh` checks the RA is reachable, then chains the three steps below
with **no manual paste**:

1. **`up.sh`** — build + start the whole stack (witnesses, vlei-server, KERIA,
   vlei-verifier, signify Deno runner) on one Docker network; wait for the
   verifier's `/health` (`:7676`) and for the `signify` container to finish
   pre-caching its deps. The first run includes a `docker build` of the
   verifier image and the signify container's npm-dep download, which together
   take a few minutes; later runs reuse the cached image and deps.
2. **`build-chain.sh`** — run [`build-chain.ts`](signify/scripts_ts/build-chain.ts)
   via `deno run` in the `signify` container. It builds the synthetic
   `GLEIF → QVI(delegated) → LE → ECR` chain, issues the ECR to the `role`
   holder AID (LEI `875500ELOZEL05BVXV37`), presents it via IPEX, **registers
   the local `gleif` root of trust** at the verifier, and exports two files into
   the bind-mounted [`signify/out/`](signify/out/) dir:
   - `ecr-presentation.json` — `{cesr, lei, aid}` the shell hands to the RA;
   - `tier1-outputs.json` — carries the holder's `roleBran` for the signer.
3. **`verify-control-demo.sh`** (invoked with `AUTO_SIGN=1` and `DATA` pointed
   at `build-chain.ts`'s exports) — the RA-mediated register + verify-control flow:
   - `POST /v2/ans/identities { value: <LEI>, vleiPresentation:{ cesr } }` — the
     RA reads the leaf SAID, presents the chain to the verifier, pins the
     verifier-reported subject AID, and returns the challenge round (nonce +
     `signingInput`) plus the advisory `presentationStatus`;
   - **auto-sign** — runs [`sign-proof.ts`](signify/scripts_ts/sign-proof.ts)
     inside the `signify` container, reconstructing `roleClient` from the
     exported `roleBran` and signing the served `signingInput` with the `role`
     AID's KERIA-held keys;
   - **re-present** — re-POST the same body while `PENDING_CONTROL` to refresh
     the verifier's authorization window (same `identityId`, fresh nonce);
   - `POST .../verify-control { cesrSignature }` — **no aid in the body**; the
     RA pins the signer AID to the identity → expects `status: VERIFIED`,
     then polls the TL for the sealed `IDENTITY_VERIFIED`;
   - `POST .../links { agentIds: [ <AGENT_ID> ] }` then
     `GET /v2/ans/agents/<AGENT_ID>` → the computed `identities[]` badge
     carries the verified `lei` identity.

Add `--down` to tear the stack down after a successful run.

### Step by step / fallback

Each stage is runnable on its own:

```bash
scripts/demo/vlei/up.sh                                  # stack
scripts/demo/vlei/build-chain.sh                         # headless chain build + export
AGENT_ID=<id> DATA=scripts/demo/vlei/signify/out \
  AUTO_SIGN=1 scripts/demo/vlei/verify-control-demo.sh   # present + verify
scripts/demo/vlei/down.sh                                # tear down
```

**Manual signing fallback.** To sign by hand, run `verify-control-demo.sh`
**without** `AUTO_SIGN`: it prints the served `signingInput`, then prints the
exact `deno run … sign-proof.ts <roleBran> <signingInput>` command to sign it
in the `signify` container. Run that, copy the printed signature (indexed Siger
qb64, e.g. `AAB…`), and paste it back at the prompt. You can also pass a
signature non-interactively with `SIGNED_PROOF=<qb64>`.

The `lei` control proof is uniform with the JWS kinds: every kind signs the
served `signingInput` (the base64url of the JCS-canonical `IdentityProofInput`,
which binds the nonce, the identity id, the identifier, and the proof purpose).
The RA forwards the signature to the verifier as `non_prefixed_digest = signingInput`.

**The 10-minute authorization window.** The `vlei-verifier` ages credential
authorizations off after `TimeoutAuth = 600s`. `verify-control` re-checks
authorization **live** on every call, so a slow manual signing step can lapse
the window and surface as `LEI_NOT_AUTHORIZED` even with a valid signature. The
script re-presents the chain (the idempotent re-add) immediately before the
verify to reset the window; if you still hit it, just re-run.

**Registering the root of trust by hand.** `build-chain.sh` registers it for
you; if the verifier was restarted (its DB is in-container and ephemeral) and
you need to re-register without re-running the chain build, the raw call is:
```bash
curl -X POST http://localhost:7676/root_of_trust/{gleifRootAID} \
  -H 'Content-Type: application/json' \
  -d '{"vlei":"<gleif KEL / chain CESR>","oobi":"<gleif OOBI url>"}'
```

## Troubleshooting

### Step 1 (QVI Credential) fails with `unknown AID`

Symptom — the IPEX grant in *Step 1* dies with:

```
HTTP POST /identifiers/gleif/ipex/grant - 400 Bad Request
{"description": "attempt to send to unknown AID=<qvi prefix>"}
```

and the keria container loops forever on:

```
ERROR eventing .processEscrowDelegables  Kevery unescrow failed: No delegation seal found for event.
keri.kering.MissingDelegableApprovalError: No delegation seal found for event.
INFO  routing  .acceptReply  Revery: escrowing without key state for signer on reply ...
```

**Cause.** A *previous* run approved the QVI delegation incorrectly — e.g.
older setup code using `identifiers().interact()` (which only anchors
the seal) instead of `delegations().approve()` (which also ingests the
QVI's `dip`). That leaves a QVI `dip` that can never be promoted, churning
in gleif's `delegables` escrow. Because `gleif` uses a **fixed bran** (so
the same gleif agent is reused on every run) and the compose file mounts
**no data volume** for keria (agent DBs live in the container's ephemeral
writable layer), this poison survives across runs — and a plain
`docker compose restart keria` does **not** clear it (same container, same
writable layer).

**Fix.** Recreate the keria container to wipe all agent state, then re-run
the chain build:

```bash
docker compose -f scripts/demo/vlei/docker-compose.yml \
  up -d --force-recreate keria
```

gleif comes back with the **same prefix** (it is deterministic from the
fixed bran), so any root-of-trust registration still matches. Then just
re-run `scripts/demo/vlei/build-chain.sh`. `build-chain.ts` already uses
`delegations().approve()` in a retry loop, so on a clean keria the
delegation completes and the QVI credential grants/admits cleanly.

### Benign noise

`Unverified loc scheme reply URL=… SAID=…` (a `/loc/scheme` reply, often
with a `dt` of `2024-12-31`) is **not** an error you need to chase — it is
transient witness-resolution churn that self-resolves once the witness KEL
loads. Only delegation/escrow errors (`MissingDelegableApprovalError`,
`escrowing without key state`) indicate the poisoned-agent state above.

## Scope

This implements the **RA-mediated register-with-presentation +
verify-control** flow for the `lei` identifier kind on the identity-scoped
`/v2/ans/identities` routes:

- The RA is the single touchpoint for the verifier: `POST /v2/ans/identities`
  carries the holder's full-chain CESR in `vleiPresentation`, the RA presents
  it and pins the verifier-reported subject AID on the identity;
  `.../verify-control` is a CESR-signature proof over the served `signingInput`
  that **pins the signer AID to the identity** — never a request-body value.
- On a clean verify the RA seals an `IDENTITY_VERIFIED` event on the identity's
  TL stream (the demo polls the TL identity audit for it), and `.../links`
  binds the verified `lei` identity to an agent so it surfaces in the agent's
  computed `identities[]` badge.
- The seal commits the subject AID + a thumbprint only (no JWK, no document):
  the KEL-backed key state lives at the verifier, so a `lei` seal is **not**
  offline-re-verifiable from the seal alone — the documented `lei` trust
  boundary (`ans-verify` enforces the AID+thumbprint shape, not an offline
  signature re-check).
