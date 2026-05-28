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

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/event"
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
	// IdentityCSRPEM is always required — the identity cert is
	// ALWAYS issued by the RA (never BYOC).
	IdentityCSRPEM string
	// The server certificate can arrive in two shapes. Exactly one
	// must be set (both set or neither set → 422):
	//
	//   - ServerCsrPEM: caller submits a CSR; the service validates
	//     it against the agent FQDN and asks the configured
	//     `ServerCertificateAuthority` port to sign it. Leaf + chain
	//     are stored as an issued server cert.
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
	agents      port.AgentStore
	endpoints   port.EndpointStore
	certs       port.CertificateStore
	byoc        port.ByocCertificateStore
	renewals    port.RenewalStore
	validator   port.CertificateValidator
	identityCA  port.IdentityCertificateAuthority
	serverCA    port.ServerCertificateAuthority // optional; nil = CSR path rejected
	bus         port.EventBus
	outbox      OutboxEnqueuer
	uow         port.UnitOfWork
	dnsVerifier port.DNSVerifier
	// tlPublicBaseURL is the externally-reachable Transparency Log URL
	// used in _ans-badge DNS records (e.g. "https://tl.example.org").
	tlPublicBaseURL string
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
) *RegistrationService {
	return &RegistrationService{
		agents:     agents,
		endpoints:  endpoints,
		certs:      certs,
		byoc:       byoc,
		renewals:   renewals,
		validator:  validator,
		identityCA: identityCA,
		bus:        bus,
		outbox:     outbox,
		uow:        uow,
		clock:      time.Now,
	}
}

// WithSigner attaches a KeyManager-backed event signer. Production
// builds must call this — unsigned outbox events will be rejected by
// the TL with NO_PRODUCER_SIGNATURE.
func (s *RegistrationService) WithSigner(sig EventSigner) *RegistrationService {
	s.signer = &sig
	return s
}

// WithServerCertificateAuthority wires the server CA used to sign
// server CSRs submitted at registration or renewal time. When nil
// (or never called), the service rejects `serverCsrPEM` submissions
// with SERVER_CA_DISABLED — operators deploy only the BYOC path.
func (s *RegistrationService) WithServerCertificateAuthority(ca port.ServerCertificateAuthority) *RegistrationService {
	s.serverCA = ca
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

// WithTLPublicBaseURL sets the externally-reachable Transparency Log
// URL used in _ans-badge DNS TXT records. Without this, badge records
// fall back to the agent's own endpoint URL.
func (s *RegistrationService) WithTLPublicBaseURL(publicBaseURL string) *RegistrationService {
	s.tlPublicBaseURL = publicBaseURL
	return s
}

// TLPublicBaseURL returns the configured public TL base URL.
func (s *RegistrationService) TLPublicBaseURL() string {
	return s.tlPublicBaseURL
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

	// Server certificate: exactly one of CSR / BYOC.
	//
	// - CSR path: validate + call ServerCertificateAuthority to sign.
	//   The issued cert is stored as a BYOC cert downstream because
	//   the domain model doesn't distinguish "we signed it" from
	//   "the operator brought their own"; both end up in the
	//   ByocServerCertificate aggregate. The issuer DN differs (our
	//   self-signed root vs the operator's public CA), which is the
	//   audit trail.
	// - BYOC path: validator checks the cert.
	// - Neither: 422 (we don't allow identity-cert-only registration).
	// - Both:    422 (ambiguous).
	csrSet := req.ServerCsrPEM != ""
	byocSet := req.ServerCertificatePEM != ""
	if csrSet == byocSet {
		return nil, domain.NewValidationError(
			"INVALID_SERVER_CERT_INPUT",
			"exactly one of serverCsrPEM or serverCertificatePEM must be provided",
		)
	}

	// Validate BYOC cert / server CSR input shape. Actual cert
	// issuance (identity cert sign + CSR-path server cert sign)
	// is deferred to verify-acme — at registration time we haven't
	// proven domain control yet, so a cert handed out at register
	// time wouldn't mean anything, and producing the TLSA record
	// before the server cert exists would leave the 202 response
	// shape incoherent.
	var byocCert *domain.ByocServerCertificate
	var pendingServerCSR *domain.AgentCSR
	switch {
	case byocSet:
		v, err := s.validator.ValidateServerCertificate(ctx,
			req.ServerCertificatePEM, req.ServerCertificateChainPEM, req.AnsName.FQDN())
		if err != nil {
			return nil, domain.NewCertificateError("INVALID_SERVER_CERT", err.Error())
		}
		byocCert = &domain.ByocServerCertificate{
			LeafCertificatePEM:      v.LeafPEM,
			ChainCertificatesPEM:    v.ChainPEM,
			SubjectCommonName:       v.CN,
			SubjectAlternativeNames: v.SANs,
			IssuerDN:                v.IssuerDN,
			ValidFromTimestamp:      v.ValidFrom,
			ValidToTimestamp:        v.ValidTo,
			Fingerprint:             v.Fingerprint,
		}
	case csrSet:
		if s.serverCA == nil {
			return nil, domain.NewValidationError(
				"SERVER_CA_DISABLED",
				"serverCsrPEM submitted but no server CA is configured — either configure one or use serverCertificatePEM (BYOC)",
			)
		}
		if err := s.validator.ValidateServerCSR(ctx, req.ServerCsrPEM, req.AnsName.FQDN()); err != nil {
			return nil, domain.NewValidationError("INVALID_SERVER_CSR", err.Error())
		}
		srvCSR := domain.NewServerCSR(uuid.NewString(), req.ServerCsrPEM, now)
		pendingServerCSR = &srvCSR
	}

	// Validate identity CSR shape. Signing is deferred to
	// verify-acme; the CSR row stays PENDING until then.
	if err := s.validator.ValidateIdentityCSR(ctx, req.IdentityCSRPEM, req.AnsName.String()); err != nil {
		return nil, domain.NewValidationError("INVALID_IDENTITY_CSR", err.Error())
	}

	// Build aggregates.
	agentID := uuid.NewString()
	csrID := uuid.NewString()
	csr := domain.NewIdentityCSR(csrID, req.IdentityCSRPEM, now)

	reg, err := domain.NewRegistration(
		agentID, req.OwnerID, req.AnsName, req.DisplayName, req.Description,
		req.Endpoints, byocCert, &csr, now,
	)
	if err != nil {
		return nil, err
	}
	reg.ServerCSR = pendingServerCSR

	// Generate the ACME DNS-01 challenge token + expiry. The only
	// DNS action the operator should take before verify-acme.
	dns01, _, err := generateChallengeTokens()
	if err != nil {
		return nil, domain.NewInternalError(
			"CHALLENGE_GEN_FAILED", "generate ACME challenge", err,
		)
	}
	reg.ACMEChallenge = domain.ACMEChallenge{
		DNS01Token: dns01,
		ExpiresAt:  now.Add(24 * time.Hour),
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
		if err := s.certs.SaveCSR(txCtx, reg.AgentID, reg.IdentityCSR); err != nil {
			return err
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
