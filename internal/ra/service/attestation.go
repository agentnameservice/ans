package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/godaddy/ans/internal/adapter/tlclient"
	"github.com/godaddy/ans/internal/crypto/cose"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

const (
	// DefaultAttestationTTL is the lifetime stamped onto an
	// AttestationPayload's `exp` claim when the operator hasn't
	// configured a non-default TTL. Matches the `Cache-Control:
	// public, max-age=3600` the handler emits — the HTTP cache and
	// the COSE expiry expire together, so a proxy can't serve a
	// stale attestation past its cryptographic lifetime.
	DefaultAttestationTTL = 1 * time.Hour

	// AttestationMediaType is the Content-Type returned to clients.
	// Generic application/cose (not application/scitt-receipt+cose):
	// this is a bundled attestation, not a SCITT receipt.
	AttestationMediaType = "application/cose"
)

// Sentinel errors the handler maps to spec-defined HTTP status codes
// (api-spec-v2.yaml § /ans/agents/{agentId}/attestation). Distinct
// from tlclient's sentinels so the handler doesn't need to import
// tlclient just to errors.Is on its surface. Wrapped underlying TL
// errors are preserved for diagnostic logging.
var (
	ErrAttestationAgentNotFound   = errors.New("attestation: agent not found")
	ErrAttestationAgentRevoked    = errors.New("attestation: agent revoked")
	ErrAttestationLeafUncommitted = errors.New("attestation: tl leaf not yet covered by checkpoint")
	ErrAttestationTLNotReachable  = errors.New("attestation: tl is not reachable")
)

// AttestationTLClient is the narrow seam over tlclient that the
// service depends on. Kept as an interface so a unit test can
// substitute a hand-rolled stub without standing up the real HTTP
// client (and so a future swap to a streaming or gRPC TL transport
// doesn't ripple through the service).
type AttestationTLClient interface {
	GetReceipt(ctx context.Context, agentID string) ([]byte, *tlclient.MerkleProof, error)
}

// AttestationServiceConfig is the static configuration the service
// needs to mint signed attestations.
type AttestationServiceConfig struct {
	// Issuer is the RA's origin URL — written into the payload's
	// `iss` field and into the protected header's CWT issuer claim
	// (label 15, sub-claim 1). Verifiers use it to correlate an
	// attestation to a specific RA instance.
	Issuer string
	// TLLogURL is the publicly-reachable base URL of the TL the RA
	// posts events to — written into payload.tl.log_url so verifiers
	// can independently fetch the TL's /root-keys to verify the
	// embedded receipt.
	TLLogURL string
	// KeyHash is the 4-byte SPKI hash of the RA producer key. Goes
	// into the COSE protected header as the `kid` so verifiers can
	// resolve the right TL-published producer key in O(1).
	KeyHash []byte
	// Signer wraps the RA producer KeyManager key into a cose.Signer.
	// Same key that signs the inner producer event in every outbox
	// row — that property is what lets verifiers verify the outer
	// attestation and the embedded inner producer signature against
	// the same advertised pubkey.
	Signer cose.Signer
	// TTL is the lifetime of each attestation. Zero → DefaultAttestationTTL.
	TTL time.Duration
	// TrustScheme is the optional TRAIN trust-scheme DNS name. When
	// empty, the field is omitted from the wire (spec calls this
	// out as the only optional top-level field).
	TrustScheme string
}

// AttestationService produces signed agent-attestation COSE_Sign1
// objects. Holds no per-request state — safe for concurrent use.
type AttestationService struct {
	agents port.AgentStore
	certs  port.CertificateStore
	byoc   port.ByocCertificateStore
	tl     AttestationTLClient
	cfg    AttestationServiceConfig
	now    func() time.Time
}

// NewAttestationService validates the configuration up front so a
// misconfigured RA fails at startup, not on the first attestation
// request hours later.
func NewAttestationService(
	agents port.AgentStore,
	certs port.CertificateStore,
	byoc port.ByocCertificateStore,
	tl AttestationTLClient,
	cfg AttestationServiceConfig,
) (*AttestationService, error) {
	if agents == nil {
		return nil, errors.New("attestation: AgentStore required")
	}
	if certs == nil {
		return nil, errors.New("attestation: CertificateStore required")
	}
	if byoc == nil {
		return nil, errors.New("attestation: ByocCertificateStore required")
	}
	if tl == nil {
		return nil, errors.New("attestation: TLClient required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("attestation: Signer required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("attestation: Issuer required")
	}
	if cfg.TLLogURL == "" {
		return nil, errors.New("attestation: TLLogURL required")
	}
	if len(cfg.KeyHash) != 4 {
		return nil, fmt.Errorf("attestation: KeyHash must be 4 bytes (got %d)", len(cfg.KeyHash))
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultAttestationTTL
	}
	return &AttestationService{
		agents: agents,
		certs:  certs,
		byoc:   byoc,
		tl:     tl,
		cfg:    cfg,
		now:    func() time.Time { return time.Now().UTC() },
	}, nil
}

// WithClock overrides the clock — test-only.
func (s *AttestationService) WithClock(fn func() time.Time) *AttestationService {
	s.now = fn
	return s
}

// Generate produces the signed attestation bytes for agentID.
//
// Flow:
//  1. Look up the agent. 404 on miss; 410 on revoked.
//  2. Resolve latest valid identity + server certs; compute SPKI
//     hashes for each.
//  3. Fetch the SCITT receipt + inclusion proof from the TL. Map
//     503-class errors to ErrAttestationLeafUncommitted /
//     ErrAttestationTLNotReachable so the handler can preserve the
//     spec's two distinct 503 codes.
//  4. Build the AttestationPayload value (validated by the domain
//     constructor — every field is load-bearing).
//  5. CBOR-encode the payload, then sign via cose.Sign1 against the
//     RA producer key.
//
// The output is the binary COSE_Sign1 the handler returns verbatim
// with Content-Type: application/cose.
func (s *AttestationService) Generate(ctx context.Context, agentID string) ([]byte, error) {
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrAttestationAgentNotFound
		}
		return nil, fmt.Errorf("attestation: load agent: %w", err)
	}
	if reg.Status == domain.StatusRevoked {
		return nil, ErrAttestationAgentRevoked
	}

	now := s.now()
	idSPKI, err := s.identitySPKIHash(ctx, agentID, now)
	if err != nil {
		return nil, err
	}
	serverSPKI, err := s.serverSPKIHash(ctx, agentID, now)
	if err != nil {
		return nil, err
	}

	receiptBytes, proof, err := s.tl.GetReceipt(ctx, agentID)
	if err != nil {
		switch {
		case errors.Is(err, tlclient.ErrTLLeafUncommitted):
			return nil, ErrAttestationLeafUncommitted
		case errors.Is(err, tlclient.ErrTLAgentNotFound):
			return nil, ErrAttestationAgentNotFound
		case errors.Is(err, tlclient.ErrTLNotReachable):
			return nil, ErrAttestationTLNotReachable
		default:
			return nil, fmt.Errorf("attestation: fetch receipt: %w", err)
		}
	}

	payload := domain.AttestationPayload{
		Issuer:                 s.cfg.Issuer,
		Subject:                reg.AnsName.AgentHost(),
		IssuedAt:               now.Unix(),
		ExpiresAt:              now.Add(s.cfg.TTL).Unix(),
		IdentityCertSPKISHA256: idSPKI,
		ServerCertSPKISHA256:   serverSPKI,
		DNS:                    s.dnsSection(reg, serverSPKI),
		TL: domain.AttestationTL{
			LogURL:   s.cfg.TLLogURL,
			LeafHash: proof.LeafHash,
			TreeSize: proof.TreeSize,
			Receipt:  receiptBytes,
		},
		TrustScheme: s.cfg.TrustScheme,
	}
	validated, err := domain.NewAttestationPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("attestation: validate payload: %w", err)
	}

	payloadBytes, err := cose.MarshalDeterministic(validated)
	if err != nil {
		return nil, fmt.Errorf("attestation: encode payload: %w", err)
	}

	// Protected header — same shape SCITT receipts use, minus the
	// VDS / VDP labels (those describe a transparency-log proof; an
	// attestation isn't one).
	protected := map[int]any{
		labelAlg: algES256,
		labelKID: s.cfg.KeyHash,
		labelCWTClaims: map[int]any{
			cwtIss: s.cfg.Issuer,
			cwtIat: now.Unix(),
		},
	}
	return cose.Sign1(ctx, s.cfg.Signer, protected, nil, payloadBytes)
}

// identitySPKIHash returns SHA-256(SubjectPublicKeyInfo) of the
// agent's latest valid identity certificate. Surfaces an explicit
// error rather than a zero hash when no valid cert exists — that's
// a 500-class condition (the agent shouldn't be reachable at this
// path without certs in place), but we want operators to see why.
func (s *AttestationService) identitySPKIHash(ctx context.Context, agentID string, now time.Time) ([]byte, error) {
	certs, err := s.certs.FindIdentityCertificatesByAgent(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("attestation: load identity certs: %w", err)
	}
	for _, c := range certs {
		if c.IsValid(now) {
			h, err := spkiSHA256FromPEM(c.CertificatePEM)
			if err != nil {
				return nil, fmt.Errorf("attestation: identity SPKI: %w", err)
			}
			return h, nil
		}
	}
	return nil, errors.New("attestation: no valid identity certificate for agent")
}

// serverSPKIHash returns SHA-256(SPKI) of the agent's latest valid
// server cert. BYOC and CSR-issued certs both land in the BYOC
// store (see lifecycle.go's signServerCSRForVerifyACME), so a
// single FindLatestValidByAgentID covers both.
func (s *AttestationService) serverSPKIHash(ctx context.Context, agentID string, now time.Time) ([]byte, error) {
	cert, err := s.byoc.FindLatestValidByAgentID(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("attestation: load server cert: %w", err)
	}
	if cert == nil || !cert.IsValid(now) {
		return nil, errors.New("attestation: no valid server certificate for agent")
	}
	h, err := spkiSHA256FromPEM(cert.LeafCertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("attestation: server SPKI: %w", err)
	}
	return h, nil
}

// dnsSection assembles the AttestationDNS sub-struct.
//
// VerifiedAt uses the registration's effective timestamp (last
// renewal, or registration if never renewed) — the moment the RA
// last confirmed DNS records were in place. Real-time DNS
// re-verification at attestation-fetch time is out of scope for
// this PR; a follow-up can persist the verifier's per-record results
// and use the actual witness timestamp.
//
// TLSARecords carries the wire-format TLSA record the agent is
// expected to publish for its server cert: usage=3 (DANE-EE),
// selector=1 (SPKI), matching=1 (SHA-256). The wire RDATA is the
// 3-byte header followed by the 32-byte SHA-256 hash — 35 bytes
// total. We synthesize it locally from the server cert SPKI we
// already computed; a verifier comparing it against a live DNS
// query (with DNSSEC) will find equality on a correctly-configured
// zone.
//
// DNSSECValidated stays false until the DNS verification result is
// persisted on the registration record (today it only lands in the
// outbox event payload). A future migration on RegistrationDetails
// will carry it through.
func (s *AttestationService) dnsSection(reg *domain.AgentRegistration, serverSPKI []byte) domain.AttestationDNS {
	tlsa := append([]byte{0x03, 0x01, 0x01}, serverSPKI...)
	return domain.AttestationDNS{
		VerifiedAt:      reg.Details.EffectiveTimestamp().Unix(),
		TLSARecords:     [][]byte{tlsa},
		DNSSECValidated: false,
	}
}

// spkiSHA256FromPEM extracts SHA-256(SubjectPublicKeyInfo) from a
// PEM-encoded X.509 certificate. The RawSubjectPublicKeyInfo field
// gives us the DER bytes exactly as they appear in the certificate,
// matching DANE-EE matching-type-1 (RFC 6698 §2.1.2).
func spkiSHA256FromPEM(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return h[:], nil
}

// COSE header label constants — duplicated from internal/tl/receipt
// rather than imported so the attestation service doesn't depend on
// the receipt package. Label values are IANA-pinned (RFC 8152 +
// RFC 8392); they don't drift.
const (
	labelAlg       = 1
	labelKID       = 4
	labelCWTClaims = 15
	algES256       = -7
	cwtIss         = 1
	cwtIat         = 6
)
