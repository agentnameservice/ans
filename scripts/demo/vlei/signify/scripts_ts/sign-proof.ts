// ============================================================================
// ANS demo — standalone holder-side proof signer.
//
// Signs the RA's verify-control `signingInput` with the holder (role) AID,
// OUTSIDE the notebook, so the verify-control flow needs no manual copy-paste.
// This is the automated equivalent of the notebook's interactive sign cell
// (tagged `skip-headless`); that cell stays in the notebook as the human
// fallback.
//
// WHY the signingInput and not the bare nonce: the lei control proof is
// uniform with the JWS kinds — every kind signs the served `signingInput`
// (the base64url of the JCS-canonical IdentityProofInput), never a bare
// nonce. The RA forwards the signature to the vlei-verifier as
// `non_prefixed_digest = signingInput`, and the verifier checks it over the
// exact UTF-8 bytes of that string. So we sign those bytes verbatim.
//
// USAGE (run inside the jupyter/signify container, on the stack network):
//   deno run -A scripts_ts/sign-proof.ts <roleBran> <signingInput>
//
// Prints ONLY the indexed Siger qb64 signature to stdout (e.g. "AAB…") so a
// shell can capture it directly; all diagnostics go to stderr.
//
// WHY connect, not boot: utils.ts initializeAndConnectClient() calls
// client.boot() first, which fails (and is re-thrown) when the agent already
// exists. The role agent was booted by the notebook run, so here we ONLY
// connect. Reconnecting with the SAME roleBran re-attaches to that same
// persistent KERIA agent — the role AID's salty signing keys live server-side
// and are reachable through the keeper without any OOBI re-resolution.
//
// WHY the role AID and not `kli sign`: the holder is a KERIA/signify
// identifier whose keys live in the cloud agent reachable only via this
// client. A local kli keystore would be a different AID, and the verifier
// pins the signer to the credential's subject AID — so a kli signature is
// rejected as SIGNATURE_INVALID.
// ============================================================================

// Pin libsodium-wrappers-sumo to 0.7.15 BEFORE signify-ts (must be the first
// import). signify-ts's range otherwise resolves 0.7.16, whose ESM packaging
// Deno cannot resolve (ERR_MODULE_NOT_FOUND on libsodium-sumo.mjs). Mirrors
// build-chain.ts so both scripts and the compose pre-cache agree.
import "npm:libsodium-wrappers-sumo@0.7.15";
// Pinned to match build-chain.ts so both scripts (and the compose pre-cache)
// resolve the same signify-ts the holder's KERIA agent was created with.
import { ready, SignifyClient, Tier } from "npm:signify-ts@0.3.0-rc1";
import { DEFAULT_ADMIN_URL, DEFAULT_BOOT_URL } from "./utils.ts";

const ROLE_ALIAS = "role";

const [roleBran, signingInput] = Deno.args;
if (!roleBran || !signingInput) {
  console.error("usage: deno run -A sign-proof.ts <roleBran> <signingInput>");
  Deno.exit(2);
}

await ready();

// Connect only — do NOT boot an already-existing agent.
const client = new SignifyClient(DEFAULT_ADMIN_URL, roleBran, Tier.low, DEFAULT_BOOT_URL);
await client.connect();

const hab = await client.identifiers().get(ROLE_ALIAS);
const keeper = client.manager!.get(hab);
const sigs = await keeper.sign(new TextEncoder().encode(signingInput));

// stderr: human-readable context; stdout: the signature only.
console.error(`signerAid   : ${hab.prefix}`);
console.log(sigs[0]);
