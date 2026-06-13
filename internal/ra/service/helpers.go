package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// loadServerCert returns the agent's latest valid server certificate,
// or (nil, nil) when none is on file. A genuinely-absent cert
// (ErrNotFound) is normal — CSR-path registrations may not have one
// yet, and ComputeRequiredDNSRecords simply omits the TLSA record.
//
// Any OTHER store error is propagated. Callers fold this cert into
// terminal, immutable artifacts — the TLSA record an operator
// publishes, and the serverCerts[] of the signed AGENT_REGISTERED leaf
// in the append-only log. Swallowing a transient store failure (busy
// timeout, I/O) would silently drop the cert and emit a permanently
// wrong attestation from a recoverable fault, so absence and failure
// must never be conflated here.
func (s *RegistrationService) loadServerCert(
	ctx context.Context, agentID string,
) (*domain.ByocServerCertificate, error) {
	cert, err := s.byoc.FindLatestValidByAgentID(ctx, agentID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil //nolint:nilnil // (nil, nil) signals "no server cert on file"; callers distinguish via the nil pointer and skip the TLSA record
		}
		return nil, err
	}
	return cert, nil
}

// serialFromCertPEM parses the certificate and returns its serial as
// lowercase hex — the same encoding issuers report at signing time.
// Fallback for stored certificates persisted before serial tracking
// landed (migration 007); rows written since carry the serial
// directly.
func serialFromCertPEM(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("service: cert PEM has no CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("service: parse certificate: %w", err)
	}
	return fmt.Sprintf("%x", cert.SerialNumber), nil
}

// fingerprintOf returns the SHA-256 fingerprint of the DER certificate
// inside the given PEM string, formatted as `SHA256:<lowercase-hex>`.
// The `SHA256:` prefix matches the algorithm-prefixed form the
// attestation shape uses (see internal/tl/event/event.go
// CertificateInfo.Fingerprint), so verifiers never have to guess
// which digest was used.
func fingerprintOf(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", errors.New("service: cert PEM has no block")
	}
	if block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("service: PEM type %q is not CERTIFICATE", block.Type)
	}
	sum := sha256.Sum256(block.Bytes)
	return "SHA256:" + hex.EncodeToString(sum[:]), nil
}

// agentCertExpiry returns the effective `expiresAt` value for a
// lifecycle event: the earliest valid `notAfter` across all attested
// agent certs (identity + server). Formatted as RFC3339 UTC. Returns
// "" when no cert is attested — callers can decide whether to surface
// that case (e.g., post-revocation events may have no live certs).
//
// Required at the event level by the reference TL spec
// (`payload.producer.event.expiresAt`); the badge service derives
// WARNING / EXPIRED transitions from this value.
func agentCertExpiry(stored []*domain.StoredCertificate, byoc *domain.ByocServerCertificate, now time.Time) string {
	var earliest time.Time
	for _, c := range stored {
		if c == nil || !c.IsValid(now) {
			continue
		}
		t := c.ExpirationTimestamp
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if byoc != nil {
		t := byoc.ValidToTimestamp
		if !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return ""
	}
	return earliest.UTC().Format(time.RFC3339)
}

// metadataHashesFromEndpoints builds the per-protocol metadata-hash
// map the AGENT_ACTIVE attestation carries. The RA validates that
// each endpoint's declared MetadataHash matches the metadata
// document it pointed at; by the time we reach the verify-dns
// transition, those hashes are trustworthy and we simply echo them
// into the attestation keyed by protocol name.
//
// If no endpoint declared a hash, we return nil — JSON omitempty
// on MetadataHashes keeps the field out of the emitted JCS entirely.
func metadataHashesFromEndpoints(eps []domain.AgentEndpoint) map[string]string {
	var out map[string]string
	for _, ep := range eps {
		if ep.MetadataHash == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		// Multiple endpoints of the same protocol collapse to the
		// first non-empty hash we see; subsequent duplicates are
		// typically identical anyway (same protocol, same metadata
		// document).
		key := string(ep.Protocol)
		if _, ok := out[key]; !ok {
			out[key] = ep.MetadataHash
		}
	}
	return out
}
