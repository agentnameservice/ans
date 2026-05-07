package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	"github.com/godaddy/ans/internal/tl/event"
	"github.com/godaddy/ans/internal/tl/receipt"
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

	status := deriveAgentStatus(rec)
	if isTerminal(status) {
		return nil, ErrStatusTokenNotIssued
	}

	claims, err := buildStatusClaims(rec, status)
	if err != nil {
		return nil, fmt.Errorf("status-token: build claims: %w", err)
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

// deriveAgentStatus maps the TL's latest event for an agent into the
// wire-format agent status the token carries. Single-terminal-event
// model (matches V1 and reference):
//
//	AGENT_REGISTERED → ACTIVE
//	AGENT_RENEWED    → ACTIVE
//	AGENT_REVOKED    → REVOKED
//	AGENT_DEPRECATED → DEPRECATED
//
// WARNING and EXPIRED are NOT event-driven — the TL derives them at
// read time from the attested cert expiry. Callers of deriveAgentStatus
// must apply that expiry check on top when they need the badge-visible
// status.
//
// Derived from the event type rather than looking up a registration
// row because the TL is the authoritative source of truth for what
// the log has witnessed — a status token asserting "this agent is
// ACTIVE" must mean "the TL has seen an AGENT_REGISTERED event that
// isn't superseded by a later revocation".
func deriveAgentStatus(rec *sqlitetl.EventRecord) string {
	switch event.Type(rec.EventType) {
	case event.TypeAgentRevoked:
		return "REVOKED"
	case event.TypeAgentRegistered, event.TypeAgentRenewed:
		return "ACTIVE"
	case event.TypeAgentDeprecated:
		return "DEPRECATED"
	default:
		// Unknown event types pass through verbatim — the token
		// generator surfaces them so operator logs show the unexpected
		// value rather than silently mapping to a wrong status.
		return rec.EventType
	}
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
func buildStatusClaims(rec *sqlitetl.EventRecord, status string) (*receipt.StatusTokenClaims, error) {
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
	claims.ValidIdentityCerts = extractCertFingerprints(attest["identityCerts"])
	claims.ValidServerCerts = extractCertFingerprints(attest["serverCerts"])
	claims.MetadataHashes = extractMetadataHashes(attest["metadataHashes"])
	return claims, nil
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

// extractCertFingerprints pulls the {fingerprint, type} pairs out of
// the attestation's identityCerts[] or serverCerts[] arrays. Invalid
// entries are skipped silently — a malformed event shouldn't block
// token issuance for a still-healthy agent.
func extractCertFingerprints(v any) []receipt.CertFingerprint {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]receipt.CertFingerprint, 0, len(arr))
	for _, el := range arr {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}
		fp, _ := m["fingerprint"].(string)
		ct, _ := m["type"].(string)
		if fp == "" {
			continue
		}
		out = append(out, receipt.CertFingerprint{Fingerprint: fp, CertType: ct})
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
