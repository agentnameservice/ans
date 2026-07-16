// ============================================================================
// ANS demo.
//
// Builds the synthetic GLEIF → QVI(delegated) → LE → ECR vLEI trust chain,
// issues the ECR to the holder (role) AID, presents it via IPEX, registers the
// LOCAL synthetic GLEIF root of trust at the vlei-verifier, and exports the two
// artifacts the shell demo consumes:
//   - out/ecr-presentation.json  {cesr, lei, aid}  → verify-control-demo.sh
//   - out/holder-state.json      {roleBran, ...}   → the nonce signer
//
// This is the headless equivalent of the old Jupyter notebook — same SignifyTS
// logic, no notebook/kernel layer. The interactive sign cell is gone entirely;
// sign-proof.ts is the standalone signer (run by verify-control-demo.sh).
//
// USAGE (inside the signify container, on the stack's docker network):
//   deno run -A scripts_ts/build-chain.ts
//
// Service hostnames (keria, vlei-server, witness-demo, vlei-verifier) resolve
// because the container shares the compose default network — see utils.ts.
// ============================================================================

import "npm:libsodium-wrappers-sumo@0.7.15";
import { randomPasscode, Saider, SignifyClient } from "npm:signify-ts@0.3.0-rc1";
import {
  initializeSignify,
  initializeAndConnectClient,
  createNewAID,
  addEndRoleForAID,
  generateOOBI,
  resolveOOBI,
  createCredentialRegistry,
  issueCredential,
  ipexGrantCredential,
  waitForAndGetNotification,
  ipexAdmitGrant,
  markNotificationRead,
  DEFAULT_IDENTIFIER_ARGS,
  ROLE_AGENT,
  IPEX_GRANT_ROUTE,
  IPEX_ADMIT_ROUTE,
  SCHEMA_SERVER_HOST,
  prTitle,
  prMessage,
  prContinue,
  sleep,
} from "./utils.ts";

const OUT_DIR = "out";
const VERIFIER_URL = "http://vlei-verifier:7676";

const WITNESS_OOBIS = [
  { url: "http://witness-demo:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller?name=wan&tag=witness", alias: "wan" },
  { url: "http://witness-demo:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller?name=wil&tag=witness", alias: "wil" },
  { url: "http://witness-demo:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller?name=wes&tag=witness", alias: "wes" },
];

async function resolveWitnesses(client: SignifyClient, who: string) {
  for (const w of WITNESS_OOBIS) {
    await resolveOOBI(client, w.url, `${who}-${w.alias}`);
  }
  prMessage(`Resolved witnesses for ${who}`);
}

// Cross-step state. Each issuance step is wrapped in its own block so its local
// consts (credentialSaid, grantResponse, …) don't collide across steps; the
// credentials and the LE claim flow forward through these module-scope `let`s.
let qviCredential;
let leCredential;
let ecrCredential;
let leData;

// ---------------------------------------------------------------------------
// Setup Phase — create the four actor clients/AIDs, OOBIs, and registries.
// ---------------------------------------------------------------------------
await initializeSignify();

prTitle("Creating clients setup");

// Fixed Bran to keep a consistent root of trust (DO NOT MODIFY or else
// validation with the verifier will break — the registered root AID is
// deterministic from this bran).
const gleifBran = "Dm8Tmz05CF6_JLX9sVlFe";
const gleifAlias = "gleif";
const { client: gleifClient } = await initializeAndConnectClient(gleifBran);
await resolveWitnesses(gleifClient, "gleif");
let gleifPrefix;

// GLEIF GEDA setup. GLEIF is the root, so it stays a plain (non-delegated)
// AID — the root of trust we register with the verifier.
try {
  const gleifAid = await gleifClient.identifiers().get(gleifAlias);
  gleifPrefix = gleifAid.prefix;
} catch {
  prMessage("Creating GLEIF AID");
  const { aid: newAid } = await createNewAID(gleifClient, gleifAlias, DEFAULT_IDENTIFIER_ARGS);
  await addEndRoleForAID(gleifClient, gleifAlias, ROLE_AGENT);
  gleifPrefix = newAid.i;
}
const gleifOOBI = await generateOOBI(gleifClient, gleifAlias, ROLE_AGENT);
prMessage(`GLEIF Prefix: ${gleifPrefix}`);

// QVI — DELEGATED by GLEIF. The vlei-verifier requires the QVI AID to be a
// delegated identifier whose delegator is the registered Root Of Trust (gleif).
const qviBran = randomPasscode();
const qviAlias = "qvi";
const { client: qviClient } = await initializeAndConnectClient(qviBran);
await resolveWitnesses(qviClient, "qvi"); // qvi's agent must know the witnesses
await resolveOOBI(qviClient, gleifOOBI, gleifAlias); // ...and the delegator's (gleif) KEL

// 1. qvi initiates a delegated inception (delpre = gleif). The operation stays
//    pending until the delegator anchors its approval.
const qviIcpResult = await qviClient.identifiers().create(qviAlias, {
  delpre: gleifPrefix,
  toad: DEFAULT_IDENTIFIER_ARGS.toad,
  wits: DEFAULT_IDENTIFIER_ARGS.wits,
});
const qviPrefix = qviIcpResult.serder.pre;
const qviIcpOp = await qviIcpResult.op();
prMessage(`QVI delegated inception pending gleif approval: ${qviPrefix}`);

// 2. gleif (the delegator) APPROVES the delegation. This MUST use
//    delegations().approve() (POST /identifiers/gleif/delegation), NOT
//    identifiers().interact(). Only the /delegation endpoint runs KERIA's
//    approveDelegation: it promotes qvi's dip out of gleif's `delegables`
//    escrow into gleif's kevers. A plain interact anchors the seal but never
//    ingests qvi's KEL, so gleif later rejects qvi's dip as "unknown AID".
//    For an inception event the seal digest equals the prefix. Retry: qvi's
//    post may not have reached gleif's escrow on the first approve; the seal
//    anchor is idempotent, so re-approving just re-runs the promotion.
const delegationSeal = { i: qviPrefix, s: "0", d: qviPrefix };
let approved = false;
for (let attempt = 1; attempt <= 10 && !approved; attempt++) {
  try {
    const gleifApproval = await gleifClient.delegations().approve(gleifAlias, delegationSeal);
    await gleifClient.operations().wait(await gleifApproval.op(), { signal: AbortSignal.timeout(30000) });
    approved = true;
  } catch (_e) {
    prMessage(`Waiting for qvi's dip to reach gleif's delegation escrow (attempt ${attempt})...`);
    await sleep(2000);
  }
}
if (!approved) throw new Error("gleif failed to approve qvi's delegated inception");

// 3. qvi pulls gleif's anchoring event, then its delegated inception completes.
const qviQueryOp = await qviClient.keyStates().query(gleifPrefix);
await qviClient.operations().wait(qviQueryOp, { signal: AbortSignal.timeout(60000) });
await qviClient.operations().wait(qviIcpOp, { signal: AbortSignal.timeout(60000) });
await qviClient.operations().delete(qviIcpOp.name);

await addEndRoleForAID(qviClient, qviAlias, ROLE_AGENT);
const qviOOBI = await generateOOBI(qviClient, qviAlias, ROLE_AGENT);
prMessage(`QVI Prefix (delegated by gleif): ${qviPrefix}`);

// LE
const leBran = randomPasscode();
const leAlias = "le";
const { client: leClient } = await initializeAndConnectClient(leBran);
await resolveWitnesses(leClient, "le");
const { aid: leAid } = await createNewAID(leClient, leAlias, DEFAULT_IDENTIFIER_ARGS);
await addEndRoleForAID(leClient, leAlias, ROLE_AGENT);
const leOOBI = await generateOOBI(leClient, leAlias, ROLE_AGENT);
const lePrefix = leAid.i;
prMessage(`LE Prefix: ${lePrefix}`);

// Role Holder
const roleBran = randomPasscode();
const roleAlias = "role";
const { client: roleClient } = await initializeAndConnectClient(roleBran);
await resolveWitnesses(roleClient, "role");
const { aid: roleAid } = await createNewAID(roleClient, roleAlias, DEFAULT_IDENTIFIER_ARGS);
await addEndRoleForAID(roleClient, roleAlias, ROLE_AGENT);
const roleOOBI = await generateOOBI(roleClient, roleAlias, ROLE_AGENT);
const rolePrefix = roleAid.i;
prMessage(`ROLE Prefix: ${rolePrefix}`);

// Client OOBI resolution (create contacts)
prTitle("Resolving OOBIs");
await Promise.all([
  resolveOOBI(gleifClient, qviOOBI, qviAlias),
  resolveOOBI(qviClient, gleifOOBI, gleifAlias),
  resolveOOBI(qviClient, leOOBI, leAlias),
  resolveOOBI(qviClient, roleOOBI, roleAlias),
  resolveOOBI(leClient, gleifOOBI, gleifAlias),
  resolveOOBI(leClient, qviOOBI, qviAlias),
  resolveOOBI(leClient, roleOOBI, roleAlias),
  resolveOOBI(roleClient, gleifOOBI, gleifAlias),
  resolveOOBI(roleClient, leOOBI, leAlias),
  resolveOOBI(roleClient, qviOOBI, qviAlias),
]);

// Create credential registries
prTitle("Creating Credential Registries");

let gleifRegistrySaid;
try {
  const registries = await gleifClient.registries().list(gleifAlias);
  gleifRegistrySaid = registries[0].regk;
} catch {
  prMessage("Creating GLEIF Registry");
  const { registrySaid: newRegistrySaid } = await createCredentialRegistry(gleifClient, gleifAlias, "gleifRegistry");
  gleifRegistrySaid = newRegistrySaid;
}
const { registrySaid: qviRegistrySaid } = await createCredentialRegistry(qviClient, qviAlias, "qviRegistry");
const { registrySaid: leRegistrySaid } = await createCredentialRegistry(leClient, leAlias, "leRegistry");
prContinue();

// ---------------------------------------------------------------------------
// Schemas — well-known, preloaded into the local schema server.
// ---------------------------------------------------------------------------
const QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";
const ECR_AUTH_SCHEMA_SAID = "EH6ekLjSr8V32WyFbGe1zXjTzFs9PkTYmupJ9H65O14g";
const ECR_SCHEMA_SAID = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw";
const OOR_AUTH_SCHEMA_SAID = "EKA57bKBKxr_kN7iN5i7lMUxpMG-s19dRcmov1iDxz-E";
const OOR_SCHEMA_SAID = "EBNaNu-M9P5cgrnfl2Fvymy4E_jvxxyjb70PRtiANlJy";

const QVI_SCHEMA_URL = `${SCHEMA_SERVER_HOST}/oobi/${QVI_SCHEMA_SAID}`;
const LE_SCHEMA_URL = `${SCHEMA_SERVER_HOST}/oobi/${LE_SCHEMA_SAID}`;
const ECR_AUTH_SCHEMA_URL = `${SCHEMA_SERVER_HOST}/oobi/${ECR_AUTH_SCHEMA_SAID}`;
const ECR_SCHEMA_URL = `${SCHEMA_SERVER_HOST}/oobi/${ECR_SCHEMA_SAID}`;
const OOR_AUTH_SCHEMA_URL = `${SCHEMA_SERVER_HOST}/oobi/${OOR_AUTH_SCHEMA_SAID}`;
const OOR_SCHEMA_URL = `${SCHEMA_SERVER_HOST}/oobi/${OOR_SCHEMA_SAID}`;

prTitle("Resolving Schemas");
await Promise.all([
  resolveOOBI(gleifClient, QVI_SCHEMA_URL),

  resolveOOBI(qviClient, QVI_SCHEMA_URL),
  resolveOOBI(qviClient, LE_SCHEMA_URL),
  resolveOOBI(qviClient, ECR_AUTH_SCHEMA_URL),
  resolveOOBI(qviClient, ECR_SCHEMA_URL),
  resolveOOBI(qviClient, OOR_AUTH_SCHEMA_URL),
  resolveOOBI(qviClient, OOR_SCHEMA_URL),

  resolveOOBI(leClient, QVI_SCHEMA_URL),
  resolveOOBI(leClient, LE_SCHEMA_URL),
  resolveOOBI(leClient, ECR_AUTH_SCHEMA_URL),
  resolveOOBI(leClient, ECR_SCHEMA_URL),
  resolveOOBI(leClient, OOR_AUTH_SCHEMA_URL),
  resolveOOBI(leClient, OOR_SCHEMA_URL),

  resolveOOBI(roleClient, QVI_SCHEMA_URL),
  resolveOOBI(roleClient, LE_SCHEMA_URL),
  resolveOOBI(roleClient, ECR_AUTH_SCHEMA_URL),
  resolveOOBI(roleClient, ECR_SCHEMA_URL),
  resolveOOBI(roleClient, OOR_AUTH_SCHEMA_URL),
  resolveOOBI(roleClient, OOR_SCHEMA_URL),
]);
prContinue();

// ---------------------------------------------------------------------------
// Step 1: QVI Credential — GLEIF issues a Qualified vLEI Issuer credential to
// the QVI. First link in the chain, so no edge block.
// ---------------------------------------------------------------------------
{
  const qviData = {
    LEI: "254900OPPU84GM83MG36", // QVI LEI (arbitrary value)
  };

  prTitle("Issuing Credential");
  const { credentialSaid } = await issueCredential(
    gleifClient, gleifAlias, gleifRegistrySaid,
    QVI_SCHEMA_SAID,
    qviPrefix,
    qviData,
  );

  qviCredential = await gleifClient.credentials().get(credentialSaid);

  prTitle("Granting Credential");
  await ipexGrantCredential(gleifClient, gleifAlias, qviPrefix, qviCredential);

  const grantNotifications = await waitForAndGetNotification(qviClient, IPEX_GRANT_ROUTE);
  const grantNotification = grantNotifications[0];

  prTitle("Admitting Grant");
  await ipexAdmitGrant(qviClient, qviAlias, gleifPrefix, grantNotification.a.d);
  await markNotificationRead(qviClient, grantNotification.i);

  const admitNotifications = await waitForAndGetNotification(gleifClient, IPEX_ADMIT_ROUTE);
  await markNotificationRead(gleifClient, admitNotifications[0].i);

  prContinue();
}

// ---------------------------------------------------------------------------
// Step 2: LE Credential — QVI issues a Legal Entity credential to the LE,
// chained back to the QVI credential via the leEdge `n` pointer.
// ---------------------------------------------------------------------------
{
  leData = {
    LEI: "875500ELOZEL05BVXV37",
  };

  const leEdge = Saider.saidify({
    d: "",
    qvi: {
      n: qviCredential.sad.d,
      s: qviCredential.sad.s,
    },
  })[1];

  const leRules = Saider.saidify({
    d: "",
    usageDisclaimer: {
      l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
    },
    issuanceDisclaimer: {
      l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
    },
  })[1];

  prTitle("Issuing Credential");
  const { credentialSaid } = await issueCredential(
    qviClient, qviAlias, qviRegistrySaid,
    LE_SCHEMA_SAID,
    lePrefix,
    leData, leEdge, leRules,
  );

  prTitle("Granting Credential");
  leCredential = await qviClient.credentials().get(credentialSaid);

  await ipexGrantCredential(qviClient, qviAlias, lePrefix, leCredential);

  const grantNotifications = await waitForAndGetNotification(leClient, IPEX_GRANT_ROUTE);
  const grantNotification = grantNotifications[0];

  prTitle("Admitting Grant");
  await ipexAdmitGrant(leClient, leAlias, qviPrefix, grantNotification.a.d);
  await markNotificationRead(leClient, grantNotification.i);

  const admitNotifications = await waitForAndGetNotification(qviClient, IPEX_ADMIT_ROUTE);
  await markNotificationRead(qviClient, admitNotifications[0].i);

  prContinue();
}

// ---------------------------------------------------------------------------
// Step 3: ECR Credential — LE directly issues an Engagement Context
// Role credential to the Role holder, chained to the LE's own vLEI credential.
// ---------------------------------------------------------------------------
{
  const ecrData = {
    LEI: leData.LEI,
    personLegalName: "John Doe",
    engagementContextRole: "Managing Director",
  };

  const ecrEdge = Saider.saidify({
    d: "",
    le: {
      n: leCredential.sad.d,
      s: leCredential.sad.s,
    },
  })[1];

  const ecrRules = Saider.saidify({
    d: "",
    usageDisclaimer: {
      l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
    },
    issuanceDisclaimer: {
      l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
    },
    privacyDisclaimer: {
      l: "It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification.",
    },
  })[1];

  prTitle("Issuing Credential");
  const { credentialSaid } = await issueCredential(
    leClient, leAlias, leRegistrySaid,
    ECR_SCHEMA_SAID,
    rolePrefix,
    ecrData, ecrEdge, ecrRules,
    true,
  );

  ecrCredential = await leClient.credentials().get(credentialSaid);

  prTitle("Granting Credential");
  await ipexGrantCredential(leClient, leAlias, rolePrefix, ecrCredential);

  const grantNotifications = await waitForAndGetNotification(roleClient, IPEX_GRANT_ROUTE);
  const grantNotification = grantNotifications[0];

  prTitle("Admitting Grant");
  await ipexAdmitGrant(roleClient, roleAlias, lePrefix, grantNotification.a.d);
  await markNotificationRead(roleClient, grantNotification.i);

  const admitNotifications = await waitForAndGetNotification(leClient, IPEX_ADMIT_ROUTE);
  await markNotificationRead(leClient, admitNotifications[0].i);

  prContinue();
}

// ---------------------------------------------------------------------------
// Register the local GLEIF root of trust + export the holder's full-chain ECR
// vLEI for the RA to present.
//
// The RA is the single touchpoint for the verifier, so this does NOT PUT the
// presentation or poll /authorizations — ans-ra does that itself inside POST
// /v2/ans/identities (the vleiPresentation). This only does the two things the
// RA cannot do: register the synthetic local GLEIF root of trust (an admin
// bootstrap of the verifier), and export the holder's full-chain CESR + LEI.
// ---------------------------------------------------------------------------
{
  const ecrSaid = ecrCredential.sad.d;
  const ecrLEI = ecrCredential.sad.a.LEI;

  // Export the ECR credential as a self-contained CESR stream. KERIA's exporter
  // walks the full edge chain (ECR -> LE -> QVI) and emits every issuer/subject
  // KEL and TEL — including the local GLEIF root's KEL and the holder's (role)
  // KEL — so this single blob is everything the verifier needs to verify the
  // chain to root. The RA parses the leaf SAID + subject AID out of this blob.
  const ecrCesr = await roleClient.credentials().get(ecrSaid, true);

  // Register the LOCAL `gleif` AID as a root of trust. The verifier ships
  // trusting the real GLEIF external root; our synthetic chain roots at this
  // `gleif` AID, so the verifier must be told to trust it or the presented
  // chain will not verify. The chain CESR already contains gleif's KEL (it is
  // the root issuer), so it doubles as the `vlei` payload.
  const rotResp = await fetch(`${VERIFIER_URL}/root_of_trust/${gleifPrefix}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vlei: ecrCesr, oobi: gleifOOBI }),
  });
  const rotBody = await rotResp.text();
  if (!rotResp.ok) {
    throw new Error(
        `root_of_trust registration failed: ${rotResp.status} ${rotResp.statusText} — ${rotBody}`,
    );
  }
  console.log("root_of_trust:", rotResp.status, rotBody);

  // Export {cesr, lei, aid} for the shell demo. The RA parses said+aid out of
  // the CESR itself and presents it to the verifier on the holder's behalf.
  await Deno.mkdir(OUT_DIR, { recursive: true });
  const presentation = { cesr: ecrCesr, lei: ecrLEI, aid: rolePrefix };
  await Deno.writeTextFile(`${OUT_DIR}/ecr-presentation.json`, JSON.stringify(presentation, null, 2));

  console.log("\n✅ root of trust registered and full-chain CESR exported.");
  console.log(`   holder AID : ${rolePrefix}`);
  console.log(`   LEI        : ${ecrLEI}`);
  console.log(`   leaf SAID  : ${ecrSaid}`);
  console.log(`   wrote ${OUT_DIR}/ecr-presentation.json`);
}

// ---------------------------------------------------------------------------
// Export the holder state the proof signer needs (roleBran reconnects to the
// holder's KERIA agent so sign-proof.ts can sign with the role AID's keys).
// ---------------------------------------------------------------------------
{
  const outputs = {
    gleifPrefix,
    rolePrefix,
    roleBran,
    LEI: leData.LEI,
    ecrCredentialSaid: ecrCredential.sad.d,
    gleifOOBI,
  };
  await Deno.writeTextFile(`${OUT_DIR}/holder-state.json`, JSON.stringify(outputs, null, 2));
  console.log(`   wrote ${OUT_DIR}/holder-state.json`);
}
