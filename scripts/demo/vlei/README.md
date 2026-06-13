# vLEI ecosystem + `verify-control` demo

A **local, self-contained** GLEIF/KERI stack that proves the RA's `lei`
identity flow against a **real `vlei-verifier`**: a genuine AID holding a
self-issued vLEI is registered on `POST /v2/ans/identities` (carrying the
full-chain CESR), the RA presents the chain to the verifier and verifies the
AID-signed `signingInput` via `.../verify-control`, seals `IDENTITY_VERIFIED`
on the TL, and links the verified `lei` identity to an agent — including the
credential-chain / authorized-LEI check.

## No genuine LEI/vLEI required

The whole chain is self-issued against a **synthetic local GLEIF root**
registered via `POST /root_of_trust/{aid}` (verifier runs with
`VERIFIER_ENV=development`, `VERIFY_ROOT_OF_TRUST=True`). The verifier checks
the chain to *your* local root, not `api.gleif.org`. The RA's `ValidateLEI`
checks ISO-17442 **format only** (20-char `[A-Z0-9]`), so any well-formed
string works; `build-chain.ts` uses `875500ELOZEL05BVXV37`. A genuine vLEI is
needed *only* against the real GLEIF production root — out of scope here.

## The RA is the single touchpoint for the verifier

The holder hands the RA the full-chain CESR in the `vleiPresentation` of `POST
/v2/ans/identities`. The RA reads the leaf credential SAID out of it (the only
thing it parses — never KERI key state), presents the chain to the verifier
(`PUT /presentations/{said}`), reads back the subject AID, and pins it on the
identity. The holder never calls the verifier directly. The one thing the RA
can't bootstrap is registering the synthetic local GLEIF root of trust — a
one-time admin step `build-chain.ts` does.

## Components (`docker-compose.yml`)

| Service | Image | Ports | Role |
|---|---|---|---|
| `witnesses` | `weboftrust/keri:1.2.0-rc4` | 5642-5644 | KERI witness network (key-event logs) |
| `vlei-server` | `gleif/vlei:1.0.0` | 7723 | ACDC schema + OOBI server (LE/OOR/ECR/QVI) |
| `keria` | `gleif/keria:0.3.0` | 3901-3903 | KERIA edge agent for the holder (signify-ts) |
| `vlei-verifier` | built from source @ `0.1.5` | **7676** | the service `ans-ra` calls |
| `signify` | `denoland/deno:alpine-2.8.2` | — | Deno runner for `build-chain.ts` + `sign-proof.ts` |

Everything is version-pinned: GLEIF's KERI/KERIA/vLEI images and the verifier
config schema move between releases, so bumping any pin means re-confirming
flags, endpoints, and config shape against that release.

- **`vlei-verifier` is built, not pulled** — it ships to no registry, so the
  compose file builds it from the pinned
  [`GLEIF-IT/vlei-verifier`](https://github.com/GLEIF-IT/vlei-verifier) `0.1.5`
  tag via a git build context. The first `up.sh` runs a `docker build` (git
  clone + `pip install`) taking a few minutes; later runs reuse the cached
  `ans-vlei-verifier:0.1.5` image. It loads its **bundled**
  `verifier-config-docker-local.json` (`VERIFIER_CONFIG_FILE`), already pointed
  at this stack's `witness-demo` + `vlei-server` hostnames — no local config to
  edit.
- **`signify` is the stock Deno image** — no custom build. It bind-mounts
  [`signify/`](signify/), holding [`scripts_ts/`](signify/scripts_ts/):
  `build-chain.ts` (trust-chain build), `sign-proof.ts` (proof signer), and
  `utils.ts` (SignifyTS helpers vendored from
  [GLEIF-IT/vlei-trainings](https://github.com/GLEIF-IT/vlei-trainings) —
  re-pull on re-vendor). It reaches the other services by name on the shared
  network and pre-caches its npm deps at start. Exports land in
  [`signify/out/`](signify/out/) via the bind mount.

## Run it

No prerequisites — `run-vlei.sh` bootstraps everything with **no manual paste**:

```bash
scripts/demo/vlei/run-vlei.sh          # add --down to tear everything down after
```

It starts `ans-ra` (+ `ans-tl`) in verifier mode, registers an agent, brings up
the stack, builds the chain, and runs the register + verify-control flow.
Re-running is safe: a running RA and a previously-registered agent are reused.

**Why "mode" matters.** `vlei.type` selects the `lei` control verifier: `noop`
runs real Ed25519 crypto but waives the GLEIF authorization binding (zero-infra
quickstart); `verifier` routes every CESR/KERI question to this stack's
`vlei-verifier`. This demo presents **real CESR**, which only `verifier`
accepts. So `run-vlei.sh` guarantees verifier mode — starting the RA in it if
down, or restarting via `stop.sh` + `start.sh --keep` (preserves the registered
agent, SQLite store, and signer keys) if it's running in the `noop` default.
The identity routes are always registered regardless (`did:web`/`did:key` use
them too). Editing `config/ra-local.yaml` has no effect here: `start.sh`
composes its config from `ANS_VLEI_*` env vars. To start in verifier mode up
front and skip the mid-run restart:

```bash
ANS_VLEI_TYPE=verifier ANS_VLEI_BASE_URL=http://localhost:7676 scripts/demo/start.sh
```

### What `run-vlei.sh` chains

0. **ensure ans-ra + agent** — RA up in verifier mode (per above), then
   `register.sh --v2` if `AGENT_ID` / `data/demo/last-agent-id` names none.
1. **`up.sh`** — build + start the stack on one Docker network; wait for the
   verifier's `/health` (`:7676`) and for `signify` to finish pre-caching deps.
2. **`build-chain.sh`** — runs
   [`build-chain.ts`](signify/scripts_ts/build-chain.ts) via `deno run` in the
   `signify` container: builds the synthetic `GLEIF → QVI(delegated) → LE → ECR`
   chain, issues the ECR to the `role` holder AID, presents it via IPEX,
   **registers the local `gleif` root of trust**, and exports into
   [`signify/out/`](signify/out/):
   - `ecr-presentation.json` — `{cesr, lei, aid}` the shell hands the RA;
   - `holder-state.json` — the holder's `roleBran` for the signer.
3. **`verify-control-demo.sh`** (`AUTO_SIGN=1`, `DATA` → the exports) — the
   register + verify-control flow:
   - `POST /v2/ans/identities { value:<LEI>, vleiPresentation:{cesr} }` — RA
     reads the leaf SAID, presents the chain, pins the subject AID, returns the
     challenge (nonce + `signingInput`) + advisory `presentationStatus`;
   - **auto-sign** — [`sign-proof.ts`](signify/scripts_ts/sign-proof.ts)
     reconstructs `roleClient` from `roleBran` and signs the `signingInput` with
     the `role` AID's KERIA-held keys;
   - **re-present** — re-POST the same body while `PENDING_CONTROL` to refresh
     the verifier's authorization window (same `identityId`, fresh nonce);
   - `POST .../verify-control { cesrSignature }` — **no aid in the body**; the
     RA pins the signer AID → expects `status: VERIFIED`, then polls the TL for
     the sealed `IDENTITY_VERIFIED`;
   - `POST .../links { agentIds:[<AGENT_ID>] }`, then
     `GET /v2/ans/agents/<AGENT_ID>` → the computed `identities[]` badge carries
     the verified `lei` identity.

### Run stages individually

```bash
scripts/demo/vlei/up.sh                                  # stack
scripts/demo/vlei/build-chain.sh                         # headless chain build + export
AGENT_ID=<id> DATA=scripts/demo/vlei/signify/out \
  AUTO_SIGN=1 scripts/demo/vlei/verify-control-demo.sh   # present + verify
scripts/demo/vlei/down.sh                                # tear down
```

**Manual signing fallback.** Run `verify-control-demo.sh` **without**
`AUTO_SIGN`: it prints the served `signingInput` and the exact `deno run …
sign-proof.ts <roleBran> <signingInput>` command. Run it, copy the printed
signature (indexed Siger qb64, e.g. `AAB…`), paste it at the prompt. Or pass it
non-interactively with `SIGNED_PROOF=<qb64>`.

The `lei` control proof is uniform with the JWS kinds: every kind signs the
served `signingInput` (base64url of the JCS-canonical `IdentityProofInput`,
binding the nonce, identity id, identifier, and proof purpose). The RA forwards
the signature to the verifier as `non_prefixed_digest = signingInput`.

**The 10-minute authorization window.** The verifier ages authorizations off
after `TimeoutAuth = 600s`, and `verify-control` re-checks authorization
**live** on every call — so a slow manual signing step can lapse the window and
surface as `LEI_NOT_AUTHORIZED` even with a valid signature. The script
re-presents the chain immediately before the verify to reset the window; if you
still hit it, just re-run.

**Re-registering the root of trust by hand.** `build-chain.sh` does it for you.
If the verifier was restarted (its DB is in-container and ephemeral) and you
need to re-register without re-running the chain build:

```bash
curl -X POST http://localhost:7676/root_of_trust/{gleifRootAID} \
  -H 'Content-Type: application/json' \
  -d '{"vlei":"<gleif KEL / chain CESR>","oobi":"<gleif OOBI url>"}'
```

## Scope

The `lei` kind on the identity-scoped `/v2/ans/identities` routes:

- `POST /v2/ans/identities` carries the full-chain CESR; the RA presents it and
  pins the verifier-reported subject AID. `.../verify-control` is a
  CESR-signature proof over the served `signingInput` that **pins the signer
  AID to the identity** — never a request-body value.
- On a clean verify the RA seals `IDENTITY_VERIFIED` on the identity's TL
  stream, and `.../links` binds the verified `lei` identity to an agent so it
  surfaces in the agent's computed `identities[]` badge.
- The seal commits the subject AID + a thumbprint only (no JWK, no document):
  the KEL-backed key state lives at the verifier, so a `lei` seal is **not**
  offline-re-verifiable from the seal alone. `ans-verify` enforces the
  AID+thumbprint shape, not an offline signature re-check.
