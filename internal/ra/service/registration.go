// Package service contains the RA application-layer services. Services
// orchestrate domain aggregates and port adapters; they hold no state of
// their own and are safe for concurrent use.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/event"
)

// OutboxEnqueuer is the subset of the SQLite OutboxStore the
// RegistrationService depends on. Kept narrow on purpose: a test can
// substitute a fake without pulling in a real DB handle, and a future
// cloud-adapter (SNS, Kafka) can implement Enqueue without claiming
// the rest of the OutboxStore surface.
//
// `schemaVersion` identifies which envelope shape the RA serialized
// the payload for ("V1" or "V2") so the outbox worker can POST to
// the matching TL ingest lane.
//
// When the caller is inside a `port.UnitOfWork.Run`, the active
// transaction is threaded through `ctx`; the SQLite implementation
// picks it up automatically. No explicit `*sql.Tx` parameter — that
// would leak SQL details into the port.
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, eventType, agentID, schemaVersion string, payload []byte, earliestAttempt time.Time) (int64, error)
}

// RegisterRequest is the command input for RegisterAgent. It is the
// domain-side representation of the registration request body; V1
// and V2 HTTP handlers both populate this shape.
//
// `SchemaVersion` selects which TL lane the resulting event flows
// to: "V2" (default) stamps the outbox row to route to
// `/v2/internal/agents/event` with a V2 AGENT_REGISTRATION event;
// "V1" stamps it to route to `/v1/internal/agents/event` with a V1
// AGENT_REGISTERED event. Empty treated as "V2" for backwards
// compatibility with callers predating the V1 lane.
type RegisterRequest struct {
	OwnerID     string
	AnsName     domain.AnsName
	DisplayName string
	Description string
	Endpoints   []domain.AgentEndpoint
	// IdentityCSRPEM is optional. When supplied, the RA issues an
	// identity certificate from it at verify-acme (the identity cert
	// is never BYOC). When empty, the agent registers without an
	// identity certificate and can never add one later — it must
	// register a new version instead.
	IdentityCSRPEM string
	// The server certificate can arrive in two shapes. Exactly one
	// must be set (both set or neither set → 422):
	//
	//   - ServerCsrPEM: caller submits a CSR; the service validates
	//     it against the agent FQDN, opens a certificate order via
	//     the configured `ServerCertificateIssuer` port, and the
	//     order is finalized at verify-acme. Leaf + chain are stored
	//     as an issued server cert.
	//
	//   - ServerCertificatePEM + ServerCertificateChainPEM: BYOC.
	//     Caller supplies a cert already signed by a public or
	//     private CA; the validator checks chain + FQDN match.
	//
	// Matches the reference `AgentRegistrationRequest` shape
	// (api-spec.yaml:1158-1179).
	ServerCsrPEM              string
	ServerCertificatePEM      string
	ServerCertificateChainPEM string
	SchemaVersion             string

	// DiscoveryProfiles is the set of DNS record families the RA emits
	// in dnsRecordsProvisioned and tells the operator to publish.
	// Each element is one of domain.ValidDiscoveryProfiles(); typical
	// values are {ANS_TXT} (default), {ANS_DNSAID}, or the
	// {ANS_DNSAID, ANS_TXT} transition union. Empty/nil normalizes to
	// domain.DefaultDiscoveryProfiles(); any invalid element surfaces
	// as INVALID_DISCOVERY_PROFILE before the aggregate is created.
	DiscoveryProfiles []domain.DiscoveryProfile
}

// RegisterResponse is returned to the HTTP handler after a successful
// registration. The handler serializes this plus the required DNS
// records to produce the 202 RegistrationPending body.
//
// Note: `CAChainPEM` is intentionally absent — it's not part of the
// V2 RegistrationPending schema (spec/api-spec-v2.yaml §1167).
// Clients fetch the identity certificate chain separately via
// GET /v2/ans/agents/{agentId}/certificates/identity once that endpoint
// lands.
type RegisterResponse struct {
	Registration *domain.AgentRegistration
	DNSRecords   []domain.ExpectedDNSRecord
}

// OutboxPayload is the JSON shape written into the outbox_events
// row's payload_json column. It's what the future RA → TL HTTP client
// worker will POST as the body plus the X-Signature header.
//
// Invariant — on retries the worker MUST replay these bytes
// byte-for-byte: the dedup key in the TL is SHA-256 of the canonical
// inner event, and the producer signature is computed over those same
// bytes, so regenerating either on retry would both break dedup and
// invalidate the signature.
type OutboxPayload struct {
	// InnerEventCanonical is the JCS-canonical bytes of the producer
	// event the TL will re-canonicalize and verify against. The worker
	// POSTs these raw — no re-serialization.
	InnerEventCanonical json.RawMessage `json:"innerEventCanonical"`
	// ProducerSignature is the detached JWS over those bytes,
	// produced with the RA's signing key. Sent as the X-Signature
	// header.
	ProducerSignature string `json:"producerSignature"`
}

// registrationChallengeWindow is how long the operator has to publish
// a domain-control challenge artifact and call verify-acme before the
// registration's challenge expires.
const registrationChallengeWindow = 24 * time.Hour

// RegistrationService is the aggregate-level service for the POST and
// verify-* endpoints.
//
// `uow` is the transaction boundary for multi-aggregate writes
// (RegisterAgent, VerifyACME, VerifyDNS, Revoke each touch ≥2
// stores). When the caller hits one of those methods we open a
// single transaction via uow.Run and route every store call through
// the scoped context so any partial failure rolls the whole batch
// back. Implementations live in the storage adapter — SQLite uses
// sqlx.Tx, cloud adapters can use TransactWriteItems-style atomic
// batches.
type RegistrationService struct {
	agents            port.AgentStore
	endpoints         port.EndpointStore
	certs             port.CertificateStore
	byoc              port.ByocCertificateStore
	renewals          port.RenewalStore
	validator         port.CertificateValidator
	identityCA        port.IdentityCertificateAuthority
	serverCA          port.ServerCertificateIssuer // optional; nil = CSR path rejected
	bus               port.EventBus
	outbox            OutboxEnqueuer
	uow               port.UnitOfWork
	dnsVerifier       port.DNSVerifier
	discoveryRegistry port.ProfileRegistry
	// httpChallenge verifies HTTP-01 challenge artifacts. Optional —
	// when nil, HTTP-01 challenges simply never verify and the gate
	// relies on DNS-01. Production configs wire the default adapter.
	httpChallenge port.HTTPChallengeVerifier
	// signer is the KeyManager + keyID + raID tuple used to sign
	// outbox events. When nil, events are still persisted but without
	// a signature — this is only valid for tests; production configs
	// must wire a real signer.
	signer *EventSigner
	clock  func() time.Time
}

// EventSigner bundles the dependencies the RA needs to produce a
// producer signature on outbox events.
type EventSigner struct {
	KeyManager port.KeyManager
	KeyID      string
	RaID       string
}

// NewRegistrationService constructs a RegistrationService. Dependencies
// are injected per SOLID; tests substitute fakes.
//
// discoveryRegistry is required at construction and the constructor
// panics on nil — a missing registry would silently emit zero
// `dnsRecordsProvisioned[]` and accept any DNS state at verify-dns
// (trust-root corruption masquerading as graceful degradation), so
// fail-loud at construction is the only correct policy. Construction
// runs at process start, never on a request path, so the no-panics-in-
// request-paths rule (CLAUDE.md) is upheld. Production builds wire the
// bundled ANS-family registry in cmd/ans-ra/main.go via
// registry.New(ans.TXTProfile{}, ans.DNSAIDProfile{}); tests build the same
// registry through service.NewDefaultProfileRegistry. There is no
// optional builder.
func NewRegistrationService(
	agents port.AgentStore,
	endpoints port.EndpointStore,
	certs port.CertificateStore,
	byoc port.ByocCertificateStore,
	renewals port.RenewalStore,
	validator port.CertificateValidator,
	identityCA port.IdentityCertificateAuthority,
	bus port.EventBus,
	outbox OutboxEnqueuer,
	uow port.UnitOfWork,
	discoveryRegistry port.ProfileRegistry,
) *RegistrationService {
	if discoveryRegistry == nil {
		panic("service.NewRegistrationService: discoveryRegistry is required (nil interface — wire registry.New(...) at construction)")
	}
	return &RegistrationService{
		agents:            agents,
		endpoints:         endpoints,
		certs:             certs,
		byoc:              byoc,
		renewals:          renewals,
		validator:         validator,
		identityCA:        identityCA,
		bus:               bus,
		outbox:            outbox,
		uow:               uow,
		discoveryRegistry: discoveryRegistry,
		clock:             time.Now,
	}
}

// WithSigner attaches a KeyManager-backed event signer. Production
// builds must call this — unsigned outbox events will be rejected by
// the TL with NO_PRODUCER_SIGNATURE.
func (s *RegistrationService) WithSigner(sig EventSigner) *RegistrationService {
	s.signer = &sig
	return s
}

// WithServerCertificateIssuer wires the certificate issuer used for
// server CSRs submitted at registration or renewal time. Orders are
// created at submission (relaying the issuer's domain-control
// challenges to the operator) and finalized at verify-acme. When nil
// (or never called), the service rejects `serverCsrPEM` submissions
// with SERVER_CA_DISABLED — operators deploy only the BYOC path.
func (s *RegistrationService) WithServerCertificateIssuer(issuer port.ServerCertificateIssuer) *RegistrationService {
	s.serverCA = issuer
	return s
}

// WithHTTPChallengeVerifier wires the verifier used to check HTTP-01
// challenge artifacts during verify-acme. When nil (or never called),
// HTTP-01 challenges never verify and the challenge gate relies on
// DNS-01 alone.
func (s *RegistrationService) WithHTTPChallengeVerifier(v port.HTTPChallengeVerifier) *RegistrationService {
	s.httpChallenge = v
	return s
}

// WithDNSVerifier wires the port.DNSVerifier used by VerifyDNS. When
// nil (or never called) verify-dns treats DNS as correct — useful
// for local-dev and tests; production configs must wire a real
// verifier.
func (s *RegistrationService) WithDNSVerifier(v port.DNSVerifier) *RegistrationService {
	s.dnsVerifier = v
	return s
}

// RegisterAgent implements the V2 registration flow:
//  1. Validate the request shape via domain constructors.
//  2. Check ANS name uniqueness.
//  3. Validate the BYOC server certificate (if provided).
//  4. Validate the identity CSR.
//  5. Issue the identity certificate and store it.
//  6. Persist the registration aggregate in a single transaction
//     together with its endpoints, CSR, and BYOC cert.
//  7. Enqueue an AgentRegistered event in the outbox (same transaction).
//  8. Publish domain events in-process for local handlers.
//  9. Return the registration + required DNS records + CA chain.
func (s *RegistrationService) RegisterAgent(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	now := s.clock()

	// Uniqueness check before heavy work.
	exists, err := s.agents.ExistsByAnsName(ctx, req.AnsName)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.NewConflictError(
			"ANS_NAME_TAKEN",
			fmt.Sprintf("ANS name %q is already registered", req.AnsName),
		)
	}

	// Validate identity CSR shape (optional) BEFORE the server-cert
	// intake: resolveServerCertInput opens a certificate order with the
	// configured issuer (a network round-trip for an ACME provider,
	// counting against its order rate limits), so a request that will
	// fail on a malformed identity CSR should be rejected with a cheap
	// local 422 first, never after burning a provider order. When
	// supplied, signing is deferred to verify-acme and the CSR row
	// stays PENDING until then; when omitted, the agent registers
	// without an identity certificate.
	var identityCSR *domain.AgentCSR
	if req.IdentityCSRPEM != "" {
		if err := s.validator.ValidateIdentityCSR(ctx, req.IdentityCSRPEM, req.AnsName.String()); err != nil {
			return nil, domain.NewValidationError("INVALID_IDENTITY_CSR", err.Error())
		}
		csr := domain.NewIdentityCSR(uuid.NewString(), req.IdentityCSRPEM, now)
		identityCSR = &csr
	}

	// Server certificate intake: exactly one of CSR / BYOC, plus the
	// certificate order whose challenges ride in the 202 response. For
	// the CSR path this opens the provider order, so it runs only
	// after the cheap local validations above have passed.
	in, err := s.resolveServerCertInput(ctx, req, now)
	if err != nil {
		return nil, err
	}
	byocCert, pendingServerCSR, order := in.byocCert, in.serverCSR, in.order

	// Build aggregates.
	agentID := uuid.NewString()

	reg, err := domain.NewRegistration(
		agentID, req.OwnerID, req.AnsName, req.DisplayName, req.Description,
		req.Endpoints, byocCert, identityCSR, now,
	)
	if err != nil {
		return nil, err
	}
	reg.ServerCSR = pendingServerCSR
	reg.CertOrder = order

	if err := applyDiscoveryProfiles(reg, req); err != nil {
		return nil, err
	}

	// Persist the aggregate + CSR rows + BYOC cert (if any) atomically.
	// Each Save participates in the same transaction via the scoped
	// txCtx the UnitOfWork hands fn — partial failure rolls the whole
	// batch back so a crash mid-chain can never leave an agent row
	// without its endpoints, identity CSR, or server cert.
	//
	// No signed certs yet: verify-acme signs the identity CSR and
	// the server CSR (CSR path); BYOC is already a cert and doesn't
	// need signing here.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.agents.Save(txCtx, reg); err != nil {
			return err
		}
		if err := s.endpoints.Save(txCtx, &domain.AgentEndpoints{
			AgentID: reg.AgentID, Endpoints: reg.Endpoints,
		}); err != nil {
			return err
		}
		if reg.IdentityCSR != nil {
			if err := s.certs.SaveCSR(txCtx, reg.AgentID, reg.IdentityCSR); err != nil {
				return err
			}
		}
		if reg.ServerCSR != nil {
			if err := s.certs.SaveCSR(txCtx, reg.AgentID, reg.ServerCSR); err != nil {
				return err
			}
		}
		if byocCert != nil {
			if err := s.byoc.Save(txCtx, reg.AgentID, byocCert); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Publish in-process events AFTER the commit. The bus is
	// fire-and-forget for cross-cutting handlers (audit, metrics);
	// publishing inside the transaction would mean a downstream
	// subscriber that takes a long time, errors, or blocks could
	// roll back state that's already durable.
	for _, ev := range reg.ClearEvents() {
		if err := s.bus.Publish(ctx, ev); err != nil {
			return nil, err
		}
	}

	// Register-time 202 carries NO `dnsRecords[]`. The only DNS
	// action the operator can take before verify-acme is installing
	// the ACME challenge TXT record, which lives in `challenges[]`.
	// Production DNS records (TRUST / BADGE / DISCOVERY / TLSA)
	// don't appear until after verify-acme issues certs — the TLSA
	// fingerprint can't exist before the server cert does.
	return &RegisterResponse{
		Registration: reg,
		DNSRecords:   nil,
	}, nil
}

// serverCertInput is the resolved server-certificate intake for a
// registration: exactly one of byocCert / serverCSR is set, and order
// carries the domain-control challenges relayed in the 202 response.
type serverCertInput struct {
	byocCert  *domain.ByocServerCertificate
	serverCSR *domain.AgentCSR
	order     domain.CertificateOrder
}

// resolveServerCertInput validates the server-certificate request
// shape and produces the certificate order. Exactly one of CSR /
// BYOC:
//
//   - CSR path: validate the CSR, then open a certificate order via
//     the configured issuer (`CreateOrder`) — the relayed challenge
//     tokens are the provider's own (self-issued by the in-process
//     CA, provider-minted for ACME CAs like Let's Encrypt). Actual
//     issuance is deferred to verify-acme: at registration time
//     domain control isn't proven yet, so a cert handed out here
//     wouldn't mean anything. The issued cert is stored as a BYOC
//     cert downstream because the domain model doesn't distinguish
//     "we signed it" from "the operator brought their own"; the
//     issuer DN is the audit trail.
//   - BYOC path: validate the operator's cert. No certificate is
//     being issued, but domain control must still be proven, so the
//     RA self-issues a validation order.
//   - Neither: 422 (identity-cert-only registration not allowed).
//   - Both:    422 (ambiguous).
//
// Either way the domain owner publishes the challenge artifacts
// themselves — ANS never touches their DNS or web server.
func (s *RegistrationService) resolveServerCertInput(
	ctx context.Context, req RegisterRequest, now time.Time,
) (serverCertInput, error) {
	csrSet := req.ServerCsrPEM != ""
	byocSet := req.ServerCertificatePEM != ""
	if csrSet == byocSet {
		return serverCertInput{}, domain.NewValidationError(
			"INVALID_SERVER_CERT_INPUT",
			"exactly one of serverCsrPEM or serverCertificatePEM must be provided",
		)
	}

	if byocSet {
		v, err := s.validator.ValidateServerCertificate(ctx,
			req.ServerCertificatePEM, req.ServerCertificateChainPEM, req.AnsName.FQDN())
		if err != nil {
			return serverCertInput{}, domain.NewCertificateError("INVALID_SERVER_CERT", err.Error())
		}
		dns01, http01, err := generateChallengeTokens()
		if err != nil {
			return serverCertInput{}, domain.NewInternalError(
				"CHALLENGE_GEN_FAILED", "generate ACME challenge", err,
			)
		}
		return serverCertInput{
			byocCert: &domain.ByocServerCertificate{
				LeafCertificatePEM:      v.LeafPEM,
				ChainCertificatesPEM:    v.ChainPEM,
				SubjectCommonName:       v.CN,
				SubjectAlternativeNames: v.SANs,
				IssuerDN:                v.IssuerDN,
				ValidFromTimestamp:      v.ValidFrom,
				ValidToTimestamp:        v.ValidTo,
				Fingerprint:             v.Fingerprint,
			},
			order: domain.NewSelfIssuedOrder(dns01, http01, now.Add(registrationChallengeWindow)),
		}, nil
	}

	if s.serverCA == nil {
		return serverCertInput{}, domain.NewValidationError(
			"SERVER_CA_DISABLED",
			"serverCsrPEM submitted but no server CA is configured — either configure one or use serverCertificatePEM (BYOC)",
		)
	}
	if err := s.validator.ValidateServerCSR(ctx, req.ServerCsrPEM, req.AnsName.FQDN()); err != nil {
		return serverCertInput{}, domain.NewValidationError("INVALID_SERVER_CSR", err.Error())
	}
	created, err := s.serverCA.CreateOrder(ctx, req.AnsName.FQDN())
	if err != nil {
		return serverCertInput{}, domain.NewInternalError(
			"CERT_ORDER_FAILED", "create certificate order", err,
		)
	}
	order := *created
	// Clamp the challenge window to the registration's own deadline
	// when the provider's order outlives it — relaying an expiry the
	// registration flow won't honor would mislead the operator.
	if deadline := now.Add(registrationChallengeWindow); order.ExpiresAt.IsZero() || deadline.Before(order.ExpiresAt) {
		order.ExpiresAt = deadline
	}
	srvCSR := domain.NewServerCSR(uuid.NewString(), req.ServerCsrPEM, now)
	return serverCertInput{serverCSR: &srvCSR, order: order}, nil
}

// baseInnerEvent populates the fields every event carries about its
// agent: ansId, ansName, eventType, the agent host/name/version
// block, raId (if the RA is configured with a signer), and the
// issued/timestamp pair (RFC3339, UTC).
//
// Callers layer attestations on top — different transitions carry
// different attestation payloads per reference behavior.
func (s *RegistrationService) baseInnerEvent(reg *domain.AgentRegistration, et event.Type, now time.Time) *event.Event {
	raID := ""
	if s.signer != nil {
		raID = s.signer.RaID
	}
	return &event.Event{
		AnsID:     reg.AgentID,
		AnsName:   reg.AnsName.String(),
		EventType: et,
		Agent: &event.Agent{
			Host:    reg.FQDN(),
			Name:    reg.Details.DisplayName,
			Version: reg.AnsName.Version().String(),
		},
		RaID:      raID,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		Timestamp: now.UTC().Format(time.RFC3339),
	}
}

// signAndMarshalPayload JCS-canonicalizes the inner event, produces
// the producer's detached JWS over the canonical bytes, and returns
// the {innerEventCanonical, producerSignature} pair as the outbox
// row's payload_json.
//
// Same invariant as buildOutboxPayload: bytes are computed once here
// and must be replayed verbatim by the (future) outbox worker on
// retries — the TL deduplicates on SHA-256(innerEventCanonical).
func (s *RegistrationService) signAndMarshalPayload(ctx context.Context, inner *event.Event, now time.Time) ([]byte, error) {
	innerCanonical, err := event.CanonicalizeEvent(inner)
	if err != nil {
		return nil, fmt.Errorf("canonicalize inner event: %w", err)
	}
	var producerSig string
	if s.signer != nil {
		producerSig, err = anscrypto.SignDetachedJWS(
			ctx, s.signer.KeyManager, s.signer.KeyID,
			anscrypto.JWSProtectedHeader{
				Typ:       "JWT",
				Timestamp: now.Unix(),
				RAID:      s.signer.RaID,
			},
			innerCanonical,
		)
		if err != nil {
			return nil, fmt.Errorf("sign outbox event: %w", err)
		}
	}
	return json.Marshal(OutboxPayload{
		InnerEventCanonical: json.RawMessage(innerCanonical),
		ProducerSignature:   producerSig,
	})
}

// enqueueTLEvent is the single chokepoint for writing a signed event
// to the outbox. Every lifecycle-transition method calls this; if
// future work needs to add a new event type, it goes through the same
// path so retry semantics stay invariant.
func (s *RegistrationService) enqueueTLEvent(ctx context.Context, eventTypeTag string, reg *domain.AgentRegistration, inner *event.Event, now time.Time) error {
	if s.outbox == nil {
		return nil
	}
	payload, err := s.signAndMarshalPayload(ctx, inner, now)
	if err != nil {
		return err
	}
	// V2 callers route through this path; the schema_version column
	// is stamped with `event.SchemaVersion` ("V2"). V1 callers route
	// through `enqueueTLEventV1` in v1event.go, which stamps
	// `eventv1.SchemaVersion` ("V1"). The outbox worker reads that
	// column to pick which TL ingest URL each row POSTs to.
	if _, err := s.outbox.Enqueue(ctx, eventTypeTag, reg.AgentID, event.SchemaVersion, payload, now); err != nil {
		return err
	}
	return nil
}
