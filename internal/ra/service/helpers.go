package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// applyDiscoveryProfiles resolves the set of DNS record families the
// registration emits and stores it on the aggregate, normalizing the
// V2 request's discoveryProfiles field defensively at the API boundary.
//
// V1 lane is pinned to {ANS_TXT} regardless of the request: V1
// callers predate the Consolidated Approach and their tooling expects
// the original `_ans` TXT shape. V1 has no discoveryProfiles field on
// the wire, so this branch is the only path V1 registrations take.
//
// V2 normalization:
//   - Field absent (nil slice) → defaults to DefaultDiscoveryProfiles()
//     ({ANS_TXT}). The spec doesn't list discoveryProfiles in
//     `required`, so omission is legal and the server picks the stable
//     ANS_TXT default; operators opt into ANS_DNSAID explicitly.
//   - Field present but empty (`"discoveryProfiles": []`) → also
//     normalizes to DefaultDiscoveryProfiles(), same as omission. The
//     spec's `minItems: 1` is the canonical client contract; the server
//     does not reject a client that sends an empty array anyway.
//   - Duplicate elements → silently deduped, first occurrence wins. The
//     spec's `uniqueItems: true` is the canonical client contract; a
//     duplicate carries no extra meaning, so we normalize rather than
//     reject.
//   - Invalid element (not in ValidDiscoveryProfiles()) → 422
//     INVALID_DISCOVERY_PROFILE. An unrecognized value can't be
//     normalized away — it names a family the RA can't emit, so the
//     caller must fix it.
//
// The handler-side conversion (toDomainDiscoveryProfiles) preserves
// the nil-vs-empty distinction, but both nil and empty normalize to the
// default here so the distinction no longer changes the outcome.
//
// V1 detection routes through isV1Lane (lifecycle.go) so a future
// schema-version evolution updates one site, not several. The error
// message references ValidDiscoveryProfiles() so adding a third profile
// is a one-place change.
func applyDiscoveryProfiles(reg *domain.AgentRegistration, req RegisterRequest) error {
	if isV1Lane(req.SchemaVersion) {
		reg.DiscoveryProfiles = []domain.DiscoveryProfile{domain.DiscoveryProfileANSTXT}
		return nil
	}
	if len(req.DiscoveryProfiles) == 0 {
		reg.DiscoveryProfiles = domain.DefaultDiscoveryProfiles()
		return nil
	}
	seen := make(map[domain.DiscoveryProfile]struct{}, len(req.DiscoveryProfiles))
	out := make([]domain.DiscoveryProfile, 0, len(req.DiscoveryProfiles))
	for _, s := range req.DiscoveryProfiles {
		if !s.IsValid() {
			return domain.NewValidationError(
				"INVALID_DISCOVERY_PROFILE",
				fmt.Sprintf("discoveryProfiles element %q is not one of %s",
					string(s),
					strings.Join(domain.ValidDiscoveryProfiles(), ", ")),
			)
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	reg.DiscoveryProfiles = out
	return nil
}

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
// landed (migration 009); rows written since carry the serial
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
// map the AGENT_REGISTERED attestation carries.
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
