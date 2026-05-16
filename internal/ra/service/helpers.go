package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
)

// hashAgentCardContent canonicalizes the raw JSON bytes per
// RFC 8785 (JCS) and returns the SHA-256 hex-lowercase digest.
// The output format matches the wire format the AIM expects for
// attestations.metadataHashes.capabilitiesHash.
//
// JCS canonicalization fails on malformed JSON; the caller surfaces
// that as an INVALID_AGENT_CARD_CONTENT validation error.
func hashAgentCardContent(content []byte) (string, error) {
	canonical, err := anscrypto.Canonicalize(content)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// applyDNSRecordStyle resolves the DNS-record-style for the new
// registration and stores it on the aggregate.
//
// V1 lane is pinned to "legacy" regardless of the request: V1 callers
// predate the Consolidated Approach and their tooling expects the
// original `_ans` TXT shape. V1 has no dnsRecordStyle field on the
// wire, so this branch is the only path V1 registrations take.
// V2 callers honor req.DNSRecordStyle: empty normalizes to
// DefaultDNSRecordStyle (consolidated); invalid values surface as
// INVALID_DNS_RECORD_STYLE.
func applyDNSRecordStyle(reg *domain.AgentRegistration, req RegisterRequest) error {
	switch {
	case req.SchemaVersion == "V1":
		reg.DNSRecordStyle = domain.DNSRecordStyleLegacy
	case req.DNSRecordStyle == "":
		reg.DNSRecordStyle = domain.DefaultDNSRecordStyle
	case !req.DNSRecordStyle.IsValid():
		return domain.NewValidationError(
			"INVALID_DNS_RECORD_STYLE",
			fmt.Sprintf("dnsRecordStyle %q is not one of consolidated, legacy, both", string(req.DNSRecordStyle)),
		)
	default:
		reg.DNSRecordStyle = req.DNSRecordStyle
	}
	return nil
}

// applyAgentCardContentHash hashes the optional agentCardContent
// the operator submitted on the V2 registration request and stores
// the digest on the aggregate per ANS_SPEC.md §A.1. Empty content
// is a no-op (the spec-conformant "no Trust Card body submitted"
// path leaves CapabilitiesHash empty so the activation flow omits
// the metadataHashes.capabilitiesHash key).
//
// Malformed JSON surfaces as INVALID_AGENT_CARD_CONTENT rather than
// silently dropping the digest.
func applyAgentCardContentHash(reg *domain.AgentRegistration, content []byte) error {
	if len(content) == 0 {
		return nil
	}
	hashHex, err := hashAgentCardContent(content)
	if err != nil {
		return domain.NewValidationError(
			"INVALID_AGENT_CARD_CONTENT",
			fmt.Sprintf("agentCardContent could not be canonicalized: %v", err),
		)
	}
	reg.CapabilitiesHash = hashHex
	return nil
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
