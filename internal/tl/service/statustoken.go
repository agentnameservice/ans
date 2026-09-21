package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/agentnameservice/ans/internal/domain"
	"time"

	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	"github.com/agentnameservice/ans/internal/tl/receipt"
)

// ErrStatusTokenNotIssued is returned when a status token is requested
// for an agent in a terminal state (EXPIRED or REVOKED). Matches the
// reference's 410 Gone semantics (swagger.yaml §297) — the handler
// maps this to HTTP 410.
var ErrStatusTokenNotIssued = errors.New("tl: status tokens are not issued for terminal-state agents")

// StatusToken is the wire representation returned to the handler:
// raw COSE_Sign1 bytes + content type. Matches the shape used by
// ReceiptService.Receipt so the handler layer can stream either
// artifact through the same write path.
type StatusToken struct {
	Bytes       []byte
	ContentType string
}

// StatusTokenService generates signed status tokens by reading the
// agent's latest event from the log, extracting the fingerprints
// and metadata hashes, and asking the injected generator to sign.
//
// Mirrors the reference's status-token controller (receipt/status.go
// + controller/receipt/controller.go in the reference) — the token
// payload fields and terminal-state gating match byte-for-byte.
type StatusTokenService struct {
	log       *LogService
	generator receipt.StatusTokenGenerator
}

// NewStatusTokenService constructs a StatusTokenService.
func NewStatusTokenService(log *LogService, generator receipt.StatusTokenGenerator) *StatusTokenService {
	return &StatusTokenService{log: log, generator: generator}
}

// ForAgent issues a signed status token for the agent's current
// lifecycle state. Pulls the latest event to populate the token's
// identity/cert/metadata fields — so verifiers don't need a
// round-trip to the badge endpoint to fill in those slots.
//
// Returns:
//   - ErrStatusTokenNotIssued (→ 410 Gone) when the agent is in a
//     terminal lifecycle state. The reference uses 410 to tell
//     AHPs/verifiers to stop fetching tokens for this agent.
//   - domain.ErrNotFound (→ 404) when no events exist for agentID.
//   - Other errors propagate unchanged for the handler's 500 path.
func (s *StatusTokenService) ForAgent(ctx context.Context, agentID string) (*StatusToken, error) {
	rec, err := s.log.LatestEventByAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}

	wrapper, err := parseEnvelopeWrapper(rec.RawEvent)
	if err != nil {
		return nil, err
	}
	now := s.log.nowFn()
	status := string(currentAgentStatus(rec, wrapper.certExpiresAt(), now, 30*24*time.Hour))
	if isTerminal(status) {
		return nil, ErrStatusTokenNotIssued
	}

	claims, err := buildStatusClaimsAt(rec, status, now)
	if err != nil {
		return nil, fmt.Errorf("status-token: build claims: %w", err)
	}
	// Legacy leaves can carry expiresAt without per-certificate dates.
	if expiry := wrapper.certExpiresAt(); !expiry.IsZero() &&
		(claims.ValidUntil.IsZero() || expiry.Before(claims.ValidUntil)) {
		claims.ValidUntil = expiry
	}
	bytes, err := s.generator.GenerateStatusToken(ctx, claims)
	if err != nil {
		return nil, fmt.Errorf("status-token: generate: %w", err)
	}
	return &StatusToken{
		Bytes:       bytes,
		ContentType: receipt.StatusTokenMediaType,
	}, nil
}

// isTerminal returns true for statuses that should NOT receive status
// tokens — the reference uses 410 Gone for these. REVOKED and
// EXPIRED are the terminal set; DEPRECATED is not terminal (the
// agent is still reachable, just scheduled for rotation).
func isTerminal(status string) bool {
	return status == "REVOKED" || status == "EXPIRED"
}

// buildStatusClaims extracts the cert fingerprints + metadata hashes
// from the event's attestation block. The attestation shape is the
// one defined in `internal/tl/event/event.go` — identityCerts[],
// serverCerts[], metadataHashes{}, dnsRecordsProvisioned[].
//
// `rec.RawEvent` is the JCS-canonical *outer envelope* bytes
// (`{payload:{logId, producer:{event, keyId, signature}}, schemaVersion,
// signature}`), so attestations live at
// `payload.producer.event.attestations`. Drilling that path manually
// here keeps the function schema-agnostic — it does the same job for
// V1 and V2 envelopes.
func buildStatusClaimsAt(rec *sqlitetl.EventRecord, status string, now time.Time) (*receipt.StatusTokenClaims, error) {
	var env map[string]any
	if err := json.Unmarshal([]byte(rec.RawEvent), &env); err != nil {
		return nil, fmt.Errorf("unmarshal raw_event: %w", err)
	}
	claims := &receipt.StatusTokenClaims{
		AgentID: rec.AgentID,
		ANSName: rec.AnsName,
		Status:  status,
	}
	attest := drillAttestations(env)
	if attest == nil {
		// No attestations yet (e.g., PENDING_VALIDATION events) —
		// valid: the token still asserts identity + status.
		return claims, nil
	}
	// Attestation cert-list shape is schema-dependent:
	//   V2 → `identityCerts[]` / `serverCerts[]` (unified arrays).
	//   V1 → `validIdentityCerts[]` / `validServerCerts[]` (rotation arrays)
	// Prefer V2; fall back to V1.
	var expiry time.Time
	var err error
	claims.ValidIdentityCerts, expiry, err = currentCertFingerprints(certFamily(attest, "identityCerts", "validIdentityCerts", "identityCert"), now)
	if err != nil {
		return nil, err
	}
	claims.ValidUntil = expiry
	claims.ValidServerCerts, expiry, err = currentCertFingerprints(certFamily(attest, "serverCerts", "validServerCerts", "serverCert"), now)
	if err != nil {
		return nil, err
	}
	if !expiry.IsZero() && (claims.ValidUntil.IsZero() || expiry.Before(claims.ValidUntil)) {
		claims.ValidUntil = expiry
	}
	claims.MetadataHashes = extractMetadataHashes(attest["metadataHashes"])
	return claims, nil
}

func certFamily(attest map[string]any, current, legacy, singleton string) any {
	if value, ok := attest[current]; ok {
		return value
	}
	if value, ok := attest[legacy]; ok {
		return value
	}
	if value, ok := attest[singleton]; ok {
		return []any{value}
	}
	return nil
}

// currentCertFingerprints removes expired overlap certificates and returns the
// earliest remaining expiry. A token authorizing several certificates must
// expire before any of those certificates does, even when replacements remain.
func currentCertFingerprints(v any, now time.Time) ([]receipt.CertFingerprint, time.Time, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, time.Time{}, nil
	}
	var out []receipt.CertFingerprint
	var earliest time.Time
	seen := make(map[string]bool, len(arr))
	for _, el := range arr {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}
		fp, _ := m["fingerprint"].(string)
		ct, _ := m["type"].(string)
		if fp == "" || seen[fp] {
			continue
		}
		if raw, ok := m["notAfter"]; ok {
			value, _ := raw.(string)
			expiry, err := domain.ParseAttestedExpiry(value)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("invalid certificate notAfter: %w", err)
			}
			if expiry.IsZero() {
				seen[fp] = true
				out = append(out, receipt.CertFingerprint{Fingerprint: fp, CertType: ct})
				continue
			}
			if !now.Before(expiry) {
				continue
			}
			if earliest.IsZero() || expiry.Before(earliest) {
				earliest = expiry
			}
		}
		seen[fp] = true
		out = append(out, receipt.CertFingerprint{Fingerprint: fp, CertType: ct})
	}
	return out, earliest, nil
}

// drillAttestations walks the standard envelope nesting
// (`payload → producer → event → attestations`) and returns the
// attestation map, or nil at any missing step. Each cast guards on
// the JSON-decoded `any` shape so a malformed envelope doesn't panic.
func drillAttestations(env map[string]any) map[string]any {
	payload, ok := env["payload"].(map[string]any)
	if !ok {
		return nil
	}
	producer, ok := payload["producer"].(map[string]any)
	if !ok {
		return nil
	}
	evt, ok := producer["event"].(map[string]any)
	if !ok {
		return nil
	}
	attest, _ := evt["attestations"].(map[string]any)
	return attest
}

// extractMetadataHashes turns {"MCP": "SHA256:..."} into a map.
// Returns nil for missing or non-map values so the CBOR encoder
// omits the field entirely (payload stays small).
func extractMetadataHashes(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok && s != "" {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
