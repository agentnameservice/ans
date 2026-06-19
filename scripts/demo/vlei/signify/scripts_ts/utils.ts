import {
    ready,
    SignifyClient,
    Tier,
    CreateIdentiferArgs,
    State,
    Operation,
    Contact,
    Salter,
    Serder
} from 'npm:signify-ts@0.3.0-rc1';

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
  static readonly BRIGHT_BLUE = '\x1b[94m';
  
  // Background colors
  static readonly BG_GREEN = '\x1b[42m';
  static readonly BG_YELLOW = '\x1b[43m';
  static readonly BG_BLUE = '\x1b[44m';
  
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

export function prContinue(): void {
  const message = "  You can continue ✅  ";
  console.log(`\n${Ansi.BOLD}${Ansi.BG_GREEN}${Ansi.BRIGHT_BLACK}${message}${Ansi.RESET}\n\n`);
}

// Helper function for sleeping
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
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

    console.log('Connecting client with provided passcode (bran) [redacted].');

    const client = new SignifyClient(adminUrl, bran, tier, bootUrl);

    try {
        await client.boot();
        console.log('Client boot process initiated with KERIA agent.');

        await client.connect();
        const clientState = await client.state();

        console.log('  Client AID Prefix: ', clientState?.controller?.state?.i);
        console.log('  Agent AID Prefix:  ', clientState?.agent?.i);

        return { client, clientState: clientState as unknown as State };
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
 * @returns {Promise<{ aid: any; operation: Operation }>} The created AID's inception event and the operation details.
 */
export async function createNewAID(
    client: SignifyClient,
    alias: string,
    identifierArgs: CreateIdentiferArgs = DEFAULT_IDENTIFIER_ARGS
): Promise<{ aid: any; operation: Operation }> {
    console.log(`Initiating AID inception for alias: ${alias}`);
    try {
        const inceptionResult = await client.identifiers().create(alias, identifierArgs as any);
        const operationDetails = await inceptionResult.op();

        const completedOperation = await client
            .operations()
            .wait(operationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

        if (completedOperation.error) {
            throw new Error(`AID creation failed: ${JSON.stringify(completedOperation.error)}`);
        }

        const newAidInceptionEvent = completedOperation.response as any;
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
 * @returns {Promise<{ operation: Operation }>} The operation details.
 */
export async function addEndRoleForAID(
    client: SignifyClient,
    aidAlias: string,
    role: string
): Promise<{ operation: Operation }> {
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
            .wait(operationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

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
 * @returns {Promise<{ operation: Operation; contacts?: Contact[] }>} The operation details and the resolved contact.
 */
export async function resolveOOBI(
    client: SignifyClient,
    oobiUrl: string,
    contactAlias?: string
): Promise<{ operation: Operation; contacts?: Contact[] }> {
    console.log(`Resolving OOBI URL: ${oobiUrl} with alias ${contactAlias}`);
    try {
        const resolveOperationDetails = await client.oobis().resolve(oobiUrl, contactAlias);
        const completedOperation = await client
            .operations()
            .wait(resolveOperationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

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
        
        return { operation: completedOperation, contacts: contact };
    } catch (error) {
        console.error(`Failed to resolve OOBI URL "${oobiUrl}":`, error);
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
            .wait(operationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

        if (completedOperation.error) {
            throw new Error(`Credential registry creation failed: ${JSON.stringify(completedOperation.error)}`);
        }

        const registrySaid = (completedOperation?.response as any)?.anchor?.i;
        console.log(`Successfully created credential registry: ${registrySaid}`);
        
        await client.operations().delete(completedOperation.name);
        return { registrySaid, operation: completedOperation };
    } catch (error) {
        console.error(`Failed to create credential registry "${registryName}":`, error);
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
            .wait(operationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

        if (completedOperation.error) {
            throw new Error(`Credential issuance failed: ${JSON.stringify(completedOperation.error)}`);
        }
        const credentialSad = completedOperation.response as any; // The full Self-Addressing Data (SAD) of the credential
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
            .wait(submitGrantOperationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

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
 * Waits for and retrieves a specific notification.
 * @param {SignifyClient} client - The SignifyClient instance.
 * @param {string} expectedRoute - The expected route in the notification attributes (e.g., IPEX_GRANT_ROUTE).
 * @returns {Promise<any>} The first matching unread notification.
 */
export async function waitForAndGetNotification(
    client: SignifyClient,
    expectedRoute: string
): Promise<any> {
    console.log(`Waiting for notification with route "${expectedRoute}"...`);
    
    let notifications;
    
    // Retry loop to fetch notifications.
    for (let attempt = 1; attempt <= DEFAULT_RETRIES ; attempt++) {
        try{
            // List notifications, filtering for unread IPEX_GRANT_ROUTE messages.
            let allNotifications = await client.notifications().list()
            notifications = allNotifications.notes.filter(
                (n: any) => n.a.r === expectedRoute && n.r === false // n.r is 'read' status
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
            .wait(admitOperationDetails, { signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS) });

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
