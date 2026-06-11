import {
    randomPasscode,
    ready,
    SignifyClient,
    Tier,
    CreateIdentiferArgs,
    State,
    Operation,
    Contact,
    Salter,
    Serder
} from 'npm:signify-ts';

class Ansi {
  // Text Colors
  static readonly BLACK = '\x1b[30m';
  static readonly RED = '\x1b[31m';
  static readonly GREEN = '\x1b[32m';
  static readonly YELLOW = '\x1b[33m';
  static readonly BLUE = '\x1b[34m';
  static readonly MAGENTA = '\x1b[35m';
  static readonly CYAN = '\x1b[36m';
  static readonly WHITE = '\x1b[37m';
  
  // Bright/Light versions
  static readonly BRIGHT_BLACK = '\x1b[90m';
  static readonly BRIGHT_RED = '\x1b[91m';
  static readonly BRIGHT_GREEN = '\x1b[92m';
  static readonly BRIGHT_YELLOW = '\x1b[93m';
  static readonly BRIGHT_BLUE = '\x1b[94m';
  static readonly BRIGHT_MAGENTA = '\x1b[95m';
  static readonly BRIGHT_CYAN = '\x1b[96m';
  static readonly BRIGHT_WHITE = '\x1b[97m';
  
  // Background colors
  static readonly BG_BLACK = '\x1b[40m';
  static readonly BG_RED = '\x1b[41m';
  static readonly BG_GREEN = '\x1b[42m';
  static readonly BG_YELLOW = '\x1b[43m';
  static readonly BG_BLUE = '\x1b[44m';
  static readonly BG_MAGENTA = '\x1b[45m';
  static readonly BG_CYAN = '\x1b[46m';
  static readonly BG_WHITE = '\x1b[47m';
  
  // Bright Background colors
  static readonly BG_BRIGHT_BLACK = '\x1b[100m';
  static readonly BG_BRIGHT_RED = '\x1b[101m';
  static readonly BG_BRIGHT_GREEN = '\x1b[102m';
  static readonly BG_BRIGHT_YELLOW = '\x1b[103m';
  static readonly BG_BRIGHT_BLUE = '\x1b[104m';
  static readonly BG_BRIGHT_MAGENTA = '\x1b[105m';
  static readonly BG_BRIGHT_CYAN = '\x1b[106m';
  static readonly BG_BRIGHT_WHITE = '\x1b[107m';
  
  // Styles
  static readonly BOLD = '\x1b[1m';
  static readonly UNDERLINE = '\x1b[4m';
  static readonly RESET = '\x1b[0m';
}

export function prTitle(message: string): void {
  console.log(`\n${Ansi.BOLD}${Ansi.UNDERLINE}${Ansi.BG_BLUE}${Ansi.BRIGHT_BLACK}  ${message}  ${Ansi.RESET}\n`);
}

export function prMessage(message: string): void {
  console.log(`\n${Ansi.BOLD}${Ansi.BRIGHT_BLUE}${message}${Ansi.RESET}\n`);
}

export function prAlert(message: string): void {
  console.log(`\n${Ansi.BOLD}${Ansi.BG_YELLOW}${Ansi.BRIGHT_BLUE}${message}${Ansi.RESET}\n`);
}

export function prContinue(): void {
  const message = "  You can continue ✅  ";
  console.log(`\n${Ansi.BOLD}${Ansi.BG_GREEN}${Ansi.BRIGHT_BLACK}${message}${Ansi.RESET}\n\n`);
}

// Helper function for sleeping
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Function to check the health of a container
export async function isServiceHealthy(healthCheckUrl: string): Promise<boolean> {
  
  console.log(`Checking health at: ${healthCheckUrl}`);

  try {
    const response = await fetch(healthCheckUrl);
    
    if (response.ok) {
        console.log(`Received status: ${response.status}. Service is healthy.`);
        return true;
    } else {
        console.warn(`Received a non-ok status: ${response.status}. Service is running but may be unhealthy.`);
        return false;
    }
  } catch (error) {
    console.error(`Failed to connect to service. It may be down. Error:`, error.message);
    return false;
  }
}

// Default KERIA connection parameters (adjust as needed for your environment)
export const DEFAULT_ADMIN_URL = 'http://keria:3901'; 
export const DEFAULT_BOOT_URL = 'http://keria:3903';  
export const DEFAULT_TIMEOUT_MS = 30000; // 30 seconds for operations
export const DEFAULT_DELAY_MS = 5000; // 5 seconds for operations
export const DEFAULT_RETRIES = 5;     // For retries
export const ROLE_AGENT = 'agent'
export const IPEX_GRANT_ROUTE = '/exn/ipex/grant'
export const IPEX_ADMIT_ROUTE = '/exn/ipex/admit'
export const IPEX_APPLY_ROUTE = '/exn/ipex/apply'
export const IPEX_OFFER_ROUTE = '/exn/ipex/offer'
export const SCHEMA_SERVER_HOST = 'http://vlei-server:7723';

export const DEFAULT_IDENTIFIER_ARGS = {
    toad: 3,
    wits: [  
        'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
        'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
        'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX'
    ]
};

/**
 * Initializes the Signify-ts library.
 */
export async function initializeSignify() {
    await ready();
    console.log('Signify-ts library initialized.');
}

/**
 * Creates a new SignifyClient instance, boots it, and connects to the KERIA agent.
 *
 * @returns {Promise<{ client: SignifyClient; bran: string; clientState: State }>}
 * The initialized client, its bran, and state. 
 */
export async function initializeAndConnectClient(
    bran: string,
    adminUrl: string = DEFAULT_ADMIN_URL,
    bootUrl: string = DEFAULT_BOOT_URL,
    tier: Tier = Tier.low
): Promise<{ client: SignifyClient;clientState: State }> {

    console.log(`Using Passcode (bran): ${bran}`);

    const client = new SignifyClient(adminUrl, bran, tier, bootUrl);

    try {
        await client.boot();
        console.log('Client boot process initiated with KERIA agent.');

        await client.connect();
        const clientState = await client.state();

        console.log('  Client AID Prefix: ', clientState?.controller?.state?.i);
        console.log('  Agent AID Prefix:  ', clientState?.agent?.i);

        return { client, clientState };
    } catch (error) {
        console.error('Failed to initialize or connect client:', error);
        throw error;
    }
}

/**
 * Creates a new AID using the provided client.
 *
 * @param {SignifyClient} client - The initialized SignifyClient.
 * @param {string} alias - A human-readable alias for the AID.
 * @param {CreateIdentiferArgs} [identifierArgs=DEFAULT_IDENTIFIER_ARGS] - Configuration for the new AID.
 * @returns {Promise<{ aid: any; operation: Operation<T> }>} The created AID's inception event and the operation details.
 */
export async function createNewAID(
    client: SignifyClient,
    alias: string,
    identifierArgs: CreateIdentiferArgs = DEFAULT_IDENTIFIER_ARGS
): Promise<{ aid: any; operation: Operation<T> }> {
    console.log(`Initiating AID inception for alias: ${alias}`);
    try {
        const inceptionResult = await client.identifiers().create(alias, identifierArgs as any);
        const operationDetails = await inceptionResult.op();

        const completedOperation = await client
            .operations()
            .wait(operationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`AID creation failed: ${JSON.stringify(completedOperation.error)}`);
        }

        const newAidInceptionEvent = completedOperation.response;
        console.log(`Successfully created AID with prefix: ${newAidInceptionEvent?.i}`);

        await client.operations().delete(completedOperation.name);

        return { aid: newAidInceptionEvent, operation: completedOperation };
    } catch (error) {
        console.error(`Failed to create AID for alias "${alias}":`, error);
        throw error;
    }
}

/**
 * Assigns an end role for a given AID to the client's KERIA Agent AID.
 *
 * @returns {Promise<{ operation: Operation<T> }>} The operation details.
 */
export async function addEndRoleForAID(
    client: SignifyClient,
    aidAlias: string,
    role: string
): Promise<{ operation: Operation<T> }> {
    if (!client.agent?.pre) {
        throw new Error('Client agent prefix is not available.');
    }
    const agentAIDPrefix = client.agent.pre;

    console.log(`Assigning '${role}' role to KERIA Agent ${agentAIDPrefix} for AID alias ${aidAlias}`);
    try {
        const addRoleResult = await client
            .identifiers()
            .addEndRole(aidAlias, role, agentAIDPrefix);

        const operationDetails = await addRoleResult.op();

        const completedOperation = await client
            .operations()
            .wait(operationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        console.log(`Successfully assigned '${role}' role for AID alias ${aidAlias}.`);

        await client.operations().delete(completedOperation.name);

        return { operation: completedOperation };
    } catch (error) {
        console.error(`Failed to add end role for AID alias "${aidAlias}":`, error);
        throw error;
    }
}

/**
 * Generates an OOBI URL for a given AID and role.
 * The arguments for client.oobis().get() are passed directly.
 *
 * @returns {Promise<string>} The generated OOBI URL.
 */
export async function generateOOBI(
    client: SignifyClient,
    aidAlias: string,
    role: string = 'agent'
): Promise<string> {
    console.log(`Generating OOBI for AID alias ${aidAlias} with role ${role}`);
    try {
        const oobiResult = await client.oobis().get(aidAlias, role);
        if (!oobiResult?.oobis?.length) {
            throw new Error('No OOBI URL returned from KERIA agent.');
        }
        const oobiUrl = oobiResult.oobis[0];
        console.log(`Generated OOBI URL: ${oobiUrl}`);
        return oobiUrl;
    } catch (error) {
        console.error(`Failed to generate OOBI for AID alias "${aidAlias}":`, error);
        throw error;
    }
}

/**
 * Resolves an OOBI URL
 *
 * @returns {Promise<{ operation: Operation<T>; contacts?: Contact[] }>} The operation details and the resolved contact.
 */
export async function resolveOOBI(
    client: SignifyClient,
    oobiUrl: string,
    contactAlias?: string
): Promise<{ operation: Operation<T>; contacts?: Contact[] }> { 
    console.log(`Resolving OOBI URL: ${oobiUrl} with alias ${contactAlias}`);
    try {
        const resolveOperationDetails = await client.oobis().resolve(oobiUrl, contactAlias);
        const completedOperation = await client
            .operations()
            .wait(resolveOperationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`OOBI resolution failed: ${JSON.stringify(completedOperation.error)}`);
        }
        console.log(`Successfully resolved OOBI URL. Response:`, completedOperation.response ? "OK" : "No response data");

        const contact = await client.contacts().list(undefined, 'alias', contactAlias);

        if (contact) {
            console.log(`Contact "${contactAlias}" added/updated.`);
        } else {
            console.warn(`Contact "${contactAlias}" not found after OOBI resolution.`);
        }

        await client.operations().delete(completedOperation.name);
        
        return { operation: completedOperation, contact: contact };
    } catch (error) {
        console.error(`Failed to resolve OOBI URL "${oobiUrl}":`, error);
        throw error;
    }
}

/**
 * Generates challenge words for authentication.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {number} [strength=128] - The bit strength for the challenge (e.g., 128, 256).
 * @returns {Promise<string[]>} A promise that resolves to an array of challenge words.
 */
export async function generateChallengeWords(
    client: SignifyClient,
    strength: number = 128
): Promise<string[]> {
    console.log(`Generating ${strength}-bit challenge words...`);
    try {
        const challenge = await client.challenges().generate(strength);
        console.log('Generated challenge words:', challenge.words);
        return challenge.words;
    } catch (error) {
        console.error('Failed to generate challenge words:', error);
        throw error;
    }
}

/**
 * Responds to a challenge by signing the words and sending them to the challenger.
 * @param {SignifyClient} client - The SignifyClient instance of the responder.
 * @param {string} sourceAidAlias - The alias of the AID that is responding (signing).
 * @param {string} recipientAidPrefix - The AID prefix of the challenger (to whom the response is sent).
 * @param {string[]} challengeWords - The array of challenge words to sign.
 * @returns {Promise<void>} A promise that resolves when the response is sent.
 */
export async function respondToChallenge(
    client: SignifyClient,
    sourceAidAlias: string,
    recipientAidPrefix: string,
    challengeWords: string[]
): Promise<void> {
    console.log(`AID alias '${sourceAidAlias}' responding to challenge from AID '${recipientAidPrefix}'...`);
    try {
        await client.challenges().respond(sourceAidAlias, recipientAidPrefix, challengeWords);
        console.log('Challenge response sent.');
    } catch (error) {
        console.error('Failed to respond to challenge:', error);
        throw error;
    }
}

/**
 * Verifies a challenge response received from another AID.
 * @param {SignifyClient} client - The SignifyClient instance of the verifier.
 * @param {string} allegedSenderAidPrefix - The AID prefix of the AID that allegedly sent the response.
 * @param {string[]} originalChallengeWords - The original challenge words that were sent.
 * @returns {Promise<{ verified: boolean; said?: string; operation?: Operation<T> }>}
 * A promise that resolves to an object indicating if verification was successful,
 * the SAID of the signed exchange message, and the operation details.
 */
export async function verifyChallengeResponse(
    client: SignifyClient,
    allegedSenderAidPrefix: string,
    originalChallengeWords: string[]
): Promise<{ verified: boolean; said?: string; operation?: Operation<T> }> {
    console.log(`Verifying challenge response from AID '${allegedSenderAidPrefix}'...`);
    try {
        const verifyOperation = await client.challenges().verify(allegedSenderAidPrefix, originalChallengeWords);
        const completedOperation = await client
            .operations()
            .wait(verifyOperation, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            console.error('Challenge verification failed:', completedOperation.error);
            await client.operations().delete(completedOperation.name);
            return { verified: false, operation: completedOperation };
        }

        const said = completedOperation.response?.exn?.d;
        console.log(`Challenge response verified successfully. SAID of exn: ${said}`);
        
        await client.operations().delete(completedOperation.name);

        return { verified: true, said: said, operation: completedOperation };
    } catch (error) {
        console.error('Failed to verify challenge response:', error);
        throw error;
    }
}

/**
 * Marks a challenge for a contact as authenticated.
 * This is done after successful verification of a challenge response.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} contactAidPrefix - The AID prefix of the contact to mark as authenticated.
 * @param {string} signedChallengeSaid - The SAID of the signed challenge exchange message (exn).
 * @returns {Promise<void>} A promise that resolves when the contact is marked.
 */
export async function markChallengeAuthenticated(
    client: SignifyClient,
    contactAidPrefix: string,
    signedChallengeSaid: string
): Promise<void> {
    console.log(`Marking challenge for contact AID '${contactAidPrefix}' as authenticated with SAID '${signedChallengeSaid}'...`);
    try {
        await client.challenges().responded(contactAidPrefix, signedChallengeSaid);
        console.log(`Contact AID '${contactAidPrefix}' marked as authenticated.`);
    } catch (error) {
        console.error(`Failed to mark challenge as authenticated for contact AID '${contactAidPrefix}':`, error);
        throw error;
    }
}

export function createTimestamp() {
    return new Date().toISOString().replace('Z', '000+00:00');
}

/**
 * Creates a new credential registry for an AID.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} aidAlias - The alias of the AID creating the registry.
 * @param {string} registryName - A human-readable name for the registry.
 * @returns {Promise<{ registry: any; operation: Operation<any> }>} The created registry details and operation.
 */
export async function createCredentialRegistry(
    client: SignifyClient,
    aidAlias: string,
    registryName: string
): Promise<{ registrySaid: any; operation: Operation<any> }> {
    console.log(`Creating credential registry "${registryName}" for AID alias "${aidAlias}"...`);
    try {
        const createRegistryResult = await client
            .registries()
            .create({ name: aidAlias, registryName: registryName });

        const operationDetails = await createRegistryResult.op();
        const completedOperation = await client
            .operations()
            .wait(operationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`Credential registry creation failed: ${JSON.stringify(completedOperation.error)}`);
        }

        const registrySaid = completedOperation?.response?.anchor?.i;
        console.log(`Successfully created credential registry: ${registrySaid}`);
        
        await client.operations().delete(completedOperation.name);
        return { registrySaid, operation: completedOperation };
    } catch (error) {
        console.error(`Failed to create credential registry "${registryName}":`, error);
        throw error;
    }
}

/**
 * Retrieves a schema by its SAID.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} schemaSaid - The SAID of the schema to retrieve.
 * @returns {Promise<any>} The schema object.
 */
export async function getSchema(
    client: SignifyClient,
    schemaSaid: string
): Promise<any> {
    console.log(`Retrieving schema with SAID: ${schemaSaid}...`);
    try {
        const schema = await client.schemas().get(schemaSaid);
        console.log(`Successfully retrieved schema: ${schemaSaid}`);
        return schema;
    } catch (error) {
        console.error(`Failed to retrieve schema "${schemaSaid}":`, error);
        throw error;
    }
}

/**
 * Issues a new credential.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} issuerAidAlias - The alias of the issuing AID.
 * @param {string} registryIdentifier - The identifier (regk) of the registry.
 * @param {string} schemaSaid - The SAID of the credential's schema.
 * @param {string} holderAidPrefix - The prefix of the AID to whom the credential will be issued.
 * @param {any} credentialClaims - The claims/attributes of the credential.
 * @returns {Promise<{ credentialSad: any; credentialSaid: string; operation: Operation<any> }>} The issued credential's SAD, SAID, and operation.
 */
export async function issueCredential(
    client: SignifyClient,
    issuerAidAlias: string,
    registryIdentifier: string,
    schemaSaid: string,
    holderAidPrefix: string,
    credentialClaims: any,
    edges?: any,
    rules?: any,
    salt = false
): Promise<{ credentialSaid: string; operation: Operation<any> }> {
    console.log(`Issuing credential from AID "${issuerAidAlias}" to AID "${holderAidPrefix}"...`);
    try {
        const issueResult = await client
            .credentials()
            .issue(
                issuerAidAlias,
                {
                    ri: registryIdentifier,
                    s: schemaSaid,
                    u: salt ? new Salter({}).qb64 : undefined,
                    a: {
                        i: holderAidPrefix,
                        ...credentialClaims
                    },
                    e: edges,
                    r: rules
                });

        const operationDetails = await issueResult.op;
        const completedOperation = await client
            .operations()
            .wait(operationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`Credential issuance failed: ${JSON.stringify(completedOperation.error)}`);
        }
        console.log(completedOperation) // ************
        const credentialSad = completedOperation.response; // The full Self-Addressing Data (SAD) of the credential
        const credentialSaid = credentialSad?.ced?.d; // The SAID of the credential
        console.log(`Successfully issued credential with SAID: ${credentialSaid}`);

        await client.operations().delete(completedOperation.name);
        return { credentialSaid, operation: completedOperation };
    } catch (error) {
        console.error('Failed to issue credential:', error);
        throw error;
    }
}

/**
 * Submits an IPEX grant for a credential.
 * @param {SignifyClient} client - The SignifyClient instance of the issuer.
 * @param {string} senderAidAlias - The alias of the AID granting the credential.
 * @param {string} recipientAidPrefix - The AID prefix of the recipient (holder).
 * @param {any} acdc - The ACDC (credential).
 * @returns {Promise<{ operation: Operation<any> }>} The operation details.
 */
export async function ipexGrantCredential(
    client: SignifyClient,
    senderAidAlias: string,
    recipientAidPrefix: string,
    acdc: any
): Promise<{ operation: Operation<any> }> {
    console.log(`AID "${senderAidAlias}" granting credential to AID "${recipientAidPrefix}" via IPEX...`);
    try {
       
        const [grant, gsigs, gend] = await client.ipex().grant({
            senderName: senderAidAlias,
            acdc: new Serder(acdc?.sad),
            iss: new Serder(acdc?.iss),
            anc: new Serder(acdc?.anc),
            ancAttachment: acdc.ancatc,
            recipient: recipientAidPrefix,
            datetime: createTimestamp(),
        });

        const submitGrantOperationDetails = await client
            .ipex()
            .submitGrant(senderAidAlias, grant, gsigs, gend, [recipientAidPrefix]);
        
        const completedOperation = await client
            .operations()
            .wait(submitGrantOperationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`IPEX grant submission failed: ${JSON.stringify(completedOperation.error)}`);
        }

        console.log(`Successfully submitted IPEX grant from "${senderAidAlias}" to "${recipientAidPrefix}".`);
        await client.operations().delete(completedOperation.name);
        return { operation: completedOperation };
    } catch (error) {
        console.error('Failed to submit IPEX grant:', error);
        throw error;
    }
}

/**
 * Retrieves the state of a credential.
 * Includes retry logic as this might be called before the information has propagated.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} registryIdentifier - The registry identifier (regk).
 * @param {string} credentialSaid - The SAID of the credential.
 * @param {number} [retries=DEFAULT_RETRIES] - Number of retry attempts.
 * @param {number} [delayMs=DEFAULT_DELAY_MS] - Delay between retries in milliseconds.
 * @returns {Promise<any>} The credential state.
 */
export async function getCredentialState(
    client: SignifyClient,
    registryIdentifier: string,
    credentialSaid: string,
    retries: number = DEFAULT_RETRIES,
    delayMs: number = DEFAULT_DELAY_MS
): Promise<any> {
    console.log(`Querying credential state for SAID "${credentialSaid}" in registry "${registryIdentifier}"...`);
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const credentialState = await client.credentials().state(registryIdentifier, credentialSaid);
            console.log('Successfully retrieved credential state.');
            return credentialState;
        } catch (error: any) {
            console.warn(`[Attempt ${attempt}/${retries}] Failed to get credential state: ${error.message}`);
            if (attempt === retries) {
                console.error(`Max retries (${retries}) reached for getting credential state.`);
                throw error;
            }
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    // Should not be reached if retries > 0
    throw new Error('Failed to get credential state after all retries.');
}

/**
 * Waits for and retrieves a specific notification.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} expectedRoute - The expected route in the notification attributes (e.g., IPEX_GRANT_ROUTE).
 * @param {number} [retries=DEFAULT_RETRIES] - Number of retry attempts.
 * @param {number} [delayMs=DEFAULT_DELAY_MS] - Delay between retries in milliseconds.
 * @returns {Promise<any>} The first matching unread notification.
 */
export async function waitForAndGetNotification(
    client: SignifyClient,
    expectedRoute: string,
    retries: number = DEFAULT_RETRIES,
    delayMs: number = DEFAULT_DELAY_MS
): Promise<any> {
    console.log(`Waiting for notification with route "${expectedRoute}"...`);
    
    let notifications;
    
    // Retry loop to fetch notifications.
    for (let attempt = 1; attempt <= DEFAULT_RETRIES ; attempt++) {
        try{
            // List notifications, filtering for unread IPEX_GRANT_ROUTE messages.
            let allNotifications = await client.notifications().list()
            notifications = allNotifications.notes.filter(
                (n) => n.a.r === expectedRoute && n.r === false // n.r is 'read' status
            );
            if(notifications.length === 0){ 
                throw new Error("Notification not found yet."); // Throw error to trigger retry
            }
            return notifications;     
        }
        catch (error){    
             console.log(`[Retry] Grant notification not found on attempt #${attempt} of ${DEFAULT_RETRIES}`);
             if (attempt === DEFAULT_RETRIES) {
                 console.error(`[Retry] Max retries (${DEFAULT_RETRIES}) reached for grant notification.`);
                 throw error; 
             }
             console.log(`[Retry] Waiting ${DEFAULT_DELAY_MS}ms before next attempt...`);
             await new Promise(resolve => setTimeout(resolve, DEFAULT_DELAY_MS));
        }
    }
}

/**
 * Submits an IPEX admit (accepts a grant).
 * @param {SignifyClient} client - The SignifyClient instance of the holder.
 * @param {string} senderAidAlias - The alias of the AID admitting the grant.
 * @param {string} recipientAidPrefix - The AID prefix of the original grantor.
 * @param {string} grantSaid - The SAID of the grant being admitted.
 * @param {string} [message=''] - Optional message for the admit.
 * @returns {Promise<{ operation: Operation<any> }>} The operation details.
 */
export async function ipexAdmitGrant(
    client: SignifyClient,
    senderAidAlias: string,
    recipientAidPrefix: string,
    grantSaid: string,
    message: string = ''
): Promise<{ operation: Operation<any> }> {
    console.log(`AID "${senderAidAlias}" admitting IPEX grant "${grantSaid}" from AID "${recipientAidPrefix}"...`);
    try {
        const [admit, sigs, aend] = await client.ipex().admit({
            senderName: senderAidAlias,
            message: message,
            grantSaid: grantSaid,
            recipient: recipientAidPrefix,
            datetime: createTimestamp(),
        });

        const admitOperationDetails = await client
            .ipex()
            .submitAdmit(senderAidAlias, admit, sigs, aend, [recipientAidPrefix]);
        
        const completedOperation = await client
            .operations()
            .wait(admitOperationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`IPEX admit submission failed: ${JSON.stringify(completedOperation.error)}`);
        }
        console.log(`Successfully submitted IPEX admit for grant "${grantSaid}".`);
        await client.operations().delete(completedOperation.name);
        return { operation: completedOperation };
    } catch (error) {
        console.error('Failed to submit IPEX admit:', error);
        throw error;
    }
}

/**
 * Marks a notification as read.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} notificationId - The ID of the notification to mark.
 * @returns {Promise<void>}
 */
export async function markNotificationRead(
    client: SignifyClient,
    notificationId: string
): Promise<void> {
    console.log(`Marking notification "${notificationId}" as read...`);
    try {
        await client.notifications().mark(notificationId);
        console.log(`Notification "${notificationId}" marked as read.`);
    } catch (error) {
        console.error(`Failed to mark notification "${notificationId}" as read:`, error);
        throw error;
    }
}

/**
 * Deletes a notification.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} notificationId - The ID of the notification to delete.
 * @returns {Promise<void>}
 */
export async function deleteNotification(
    client: SignifyClient,
    notificationId: string
): Promise<void> {
    console.log(`Deleting notification "${notificationId}"...`);
    try {
        await client.notifications().delete(notificationId);
        console.log(`Notification "${notificationId}" deleted.`);
    } catch (error) {
        console.error(`Failed to delete notification "${notificationId}":`, error);
        throw error;
    }
}


//--------------------------------------------------------------------------------

// --- Credential Presentation Functions ---

/**
 * Submits an IPEX apply (presentation request).
 * @param {SignifyClient} client - The SignifyClient instance of the verifier.
 * @param {string} senderAidAlias - The alias of the AID applying for presentation.
 * @param {string} recipientAidPrefix - The AID prefix of the holder.
 * @param {string} schemaSaid - The SAID of the schema being requested.
 * @param {any} attributes - The attributes being requested for the credential.
 * @param {string} datetime - The timestamp for the apply.
 * @returns {Promise<{ operation: Operation<any>; applySaid: string }>} The operation details and SAID of the apply exn.
 */
export async function ipexApplyForCredential(
    client: SignifyClient,
    senderAidAlias: string,
    recipientAidPrefix: string,
    schemaSaid: string,
    attributes: any,
    datetime: string
): Promise<{ operation: Operation<any>; applySaid: string }> {
    console.log(`AID "${senderAidAlias}" applying for credential presentation from AID "${recipientAidPrefix}"...`);
    try {
        const [apply, sigs, _] = await client.ipex().apply({
            senderName: senderAidAlias,
            schemaSaid: schemaSaid,
            attributes: attributes,
            recipient: recipientAidPrefix,
            datetime: datetime,
        });
        
        const applySaid = new Serder(apply).said; // Get SAID of the apply message itself

        const applyOperationDetails = await client
            .ipex()
            .submitApply(senderAidAlias, apply, sigs, [recipientAidPrefix]);

        const completedOperation = await client
            .operations()
            .wait(applyOperationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`IPEX apply submission failed: ${JSON.stringify(completedOperation.error)}`);
        }
        console.log(`Successfully submitted IPEX apply with SAID "${applySaid}".`);
        await client.operations().delete(completedOperation.name);
        return { operation: completedOperation, applySaid };
    } catch (error) {
        console.error('Failed to submit IPEX apply:', error);
        throw error;
    }
}

/**
 * Finds matching credentials based on a filter.
 * @param {SignifyClient} client - The SignifyClient instance of the holder.
 * @param {any} filter - The filter object to apply (e.g., { '-s': schemaSaid, '-a-attributeName': value }).
 * @returns {Promise<any[]>} An array of matching credentials.
 */
export async function findMatchingCredentials(
    client: SignifyClient,
    filter: any
): Promise<any[]> {
    console.log('Finding matching credentials with filter:', filter);
    try {
        const matchingCredentials = await client.credentials().list({ filter });
        console.log(`Found ${matchingCredentials.length} matching credentials.`);
        return matchingCredentials;
    } catch (error) {
        console.error('Failed to find matching credentials:', error);
        throw error;
    }
}

/**
 * Submits an IPEX offer (presents a credential).
 * @param {SignifyClient} client - The SignifyClient instance of the holder.
 * @param {string} senderAidAlias - The alias of the AID offering the credential.
 * @param {string} recipientAidPrefix - The AID prefix of the verifier.
 * @param {any} acdcSad - The Self-Addressing Data (SAD) of the ACDC being offered.
 * @param {string} applySaid - The SAID of the IPEX apply message this offer is responding to.
 * @param {string} datetime - The timestamp for the offer.
 * @returns {Promise<{ operation: Operation<any> }>} The operation details.
 */
export async function ipexOfferCredential(
    client: SignifyClient,
    senderAidAlias: string,
    recipientAidPrefix: string,
    acdcSad: any, // This is the SAD of the credential to be offered
    applySaid: string,
    datetime: string
): Promise<{ operation: Operation<any> }> {
    console.log(`AID "${senderAidAlias}" offering credential to AID "${recipientAidPrefix}" in response to apply "${applySaid}"...`);
    try {
        const [offer, sigs, end] = await client.ipex().offer({
            senderName: senderAidAlias,
            recipient: recipientAidPrefix,
            acdc: new Serder(acdcSad), // The credential SAD needs to be wrapped in Serder
            applySaid: applySaid,
            datetime: datetime,
        });

        const offerOperationDetails = await client
            .ipex()
            .submitOffer(senderAidAlias, offer, sigs, end, [recipientAidPrefix]);
        
        const completedOperation = await client
            .operations()
            .wait(offerOperationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`IPEX offer submission failed: ${JSON.stringify(completedOperation.error)}`);
        }
        console.log(`Successfully submitted IPEX offer in response to apply "${applySaid}".`);
        await client.operations().delete(completedOperation.name);
        return { operation: completedOperation };
    } catch (error) {
        console.error('Failed to submit IPEX offer:', error);
        throw error;
    }
}

/**
 * Submits an IPEX agree (verifier agrees to the offered credential).
 * @param {SignifyClient} client - The SignifyClient instance of the verifier.
 * @param {string} senderAidAlias - The alias of the AID agreeing to the offer.
 * @param {string} recipientAidPrefix - The AID prefix of the holder who made the offer.
 * @param {string} offerSaid - The SAID of the IPEX offer message being agreed to.
 * @param {string} datetime - The timestamp for the agree.
 * @returns {Promise<{ operation: Operation<any> }>} The operation details.
 */
export async function ipexAgreeToOffer(
    client: SignifyClient,
    senderAidAlias: string,
    recipientAidPrefix: string,
    offerSaid: string,
    datetime: string
): Promise<{ operation: Operation<any> }> {
    console.log(`AID "${senderAidAlias}" agreeing to IPEX offer "${offerSaid}" from AID "${recipientAidPrefix}"...`);
    try {
        const [agree, sigs, _] = await client.ipex().agree({
            senderName: senderAidAlias,
            recipient: recipientAidPrefix,
            offerSaid: offerSaid,
            datetime: datetime,
        });

        const agreeOperationDetails = await client
            .ipex()
            .submitAgree(senderAidAlias, agree, sigs, [recipientAidPrefix]);

        const completedOperation = await client
            .operations()
            .wait(agreeOperationDetails, AbortSignal.timeout(DEFAULT_TIMEOUT_MS));

        if (completedOperation.error) {
            throw new Error(`IPEX agree submission failed: ${JSON.stringify(completedOperation.error)}`);
        }
        console.log(`Successfully submitted IPEX agree for offer "${offerSaid}".`);
        await client.operations().delete(completedOperation.name);
        return { operation: completedOperation };
    } catch (error) {
        console.error('Failed to submit IPEX agree:', error);
        throw error;
    }
}






















// --- Example Usage ---
export async function test() {
    try {
        await initializeSignify();

        // --- Client A (Alfred) Setup ---
        console.log('\n--- Initializing Client A (Alfred) ---');
        const { client: clientA, clientState: clientAState } = await initializeAndConnectClient(randomPasscode());
        const alfredClientAID = clientAState?.controller?.state?.i || 'Unknown Client AID A';
        const aidAAlias = 'alfredPrimaryAID';
        console.log('\n--- Creating AID for Alfred ---');
        const { aid: aidAObj} = await createNewAID(clientA, aidAAlias, DEFAULT_IDENTIFIER_ARGS);
        const aidAPrefix = aidAObj?.i || 'Unknown AID A Prefix';
        console.log(`Alfred's primary AID: ${aidAPrefix}`);
        console.log('\n--- Adding Agent End Role for Alfred ---');
        await addEndRoleForAID(clientA, aidAAlias, 'agent');
        console.log('\n--- Generating OOBI for Alfred ---');
        const alfredOOBI = await generateOOBI(clientA, aidAAlias, 'agent');

        // --- Client B (Betty) Setup ---
        console.log('\n\n--- Initializing Client B (Betty) ---');
        const { client: clientB, clientState: clientBState } = await initializeAndConnectClient(randomPasscode());
        const bettyClientAID = clientBState?.controller?.state?.i || 'Unknown Client AID B';
        const aidBAlias = 'bettyPrimaryAID';
        console.log('\n--- Creating AID for Betty ---');
        const { aid: aidBObj } = await createNewAID(clientB, aidBAlias, DEFAULT_IDENTIFIER_ARGS);
        const aidBPrefix = aidBObj?.i || 'Unknown AID B Prefix';
        console.log(`Betty's primary AID: ${aidBPrefix}`);
        console.log('\n--- Adding Agent End Role for Betty ---');
        await addEndRoleForAID(clientB, aidBAlias, 'agent');
        console.log('\n--- Generating OOBI for Betty ---');
        const bettyOOBI = await generateOOBI(clientB, aidBAlias, 'agent');

        // --- OOBI Resolution ---
        console.log('\n\n--- Betty resolving Alfred\'s OOBI ---');
        const contactAlfredAlias = 'AlfredsContactForBetty';
        await resolveOOBI(clientB, alfredOOBI, contactAlfredAlias);

        console.log('\n--- Alfred resolving Betty\'s OOBI ---');
        const contactBettyAlias = 'BettysContactForAlfred';
        await resolveOOBI(clientA, bettyOOBI, contactBettyAlias);

        // --- Challenge/Response: Alfred challenges Betty ---
        console.log("\n\n--- MUTUAL AUTHENTICATION ---");
        console.log("\n--- Alfred challenges Betty ---");

        // 1. Alfred generates challenge words for Betty
        const alfredChallengeForBetty = await generateChallengeWords(clientA);

        // (Assume words are securely transmitted out-of-band to Betty)

        // 2. Betty responds to Alfred's challenge
        console.log(`\nBetty (AID: ${aidBPrefix}) responding to Alfred's (AID: ${aidAPrefix}) challenge...`);
        await respondToChallenge(clientB, aidBAlias, aidAPrefix, alfredChallengeForBetty);

        // 3. Alfred verifies Betty's response
        console.log(`\nAlfred (AID: ${aidAPrefix}) verifying Betty's (AID: ${aidBPrefix}) response...`);
        const verificationBetty = await verifyChallengeResponse(clientA, aidBPrefix, alfredChallengeForBetty);

        // 4. Alfred marks Betty as authenticated if verification succeeded
        if (verificationBetty.verified && verificationBetty.said) {
            await markChallengeAuthenticated(clientA, aidBPrefix, verificationBetty.said);
            console.log(`Alfred has successfully authenticated Betty (AID: ${aidBPrefix}).`);
        } else {
            console.error(`Alfred failed to authenticate Betty (AID: ${aidBPrefix}).`);
        }

        // --- Challenge/Response: Betty challenges Alfred ---
        console.log("\n--- Betty challenges Alfred ---");

        // 1. Betty generates challenge words for Alfred
        const bettyChallengeForAlfred = await generateChallengeWords(clientB);

        // (Assume words are securely transmitted out-of-band to Alfred)

        // 2. Alfred responds to Betty's challenge
        console.log(`\nAlfred (AID: ${aidAPrefix}) responding to Betty's (AID: ${aidBPrefix}) challenge...`);
        await respondToChallenge(clientA, aidAAlias, aidBPrefix, bettyChallengeForAlfred);

        // 3. Betty verifies Alfred's response
        console.log(`\nBetty (AID: ${aidBPrefix}) verifying Alfred's (AID: ${aidAPrefix}) response...`);
        const verificationAlfred = await verifyChallengeResponse(clientB, aidAPrefix, bettyChallengeForAlfred);
        
        // 4. Betty marks Alfred as authenticated if verification succeeded
        if (verificationAlfred.verified && verificationAlfred.said) {
            await markChallengeAuthenticated(clientB, aidAPrefix, verificationAlfred.said);
            console.log(`Betty has successfully authenticated Alfred (AID: ${aidAPrefix}).`);
        } else {
            console.error(`Betty failed to authenticate Alfred (AID: ${aidAPrefix}).`);
        }

        console.log('\n\n--- Example scenario with mutual authentication completed! ---');
        console.log(`Alfred's Client AID: ${alfredClientAID}, Primary AID: ${aidAPrefix}`);
        console.log(`Betty's Client AID: ${bettyClientAID}, Primary AID: ${aidBPrefix}`);

        // You can inspect contacts to see authentication status
        const alfredsContacts = await clientA.contacts().list();
        console.log("\nAlfred's contacts:", JSON.stringify(alfredsContacts, null, 2));
        const bettysContacts = await clientB.contacts().list();
        console.log("\nBetty's contacts:", JSON.stringify(bettysContacts, null, 2));
    } catch (error) {
        console.error('\n--- An error occurred in the main example: ---', error);
    }
}
