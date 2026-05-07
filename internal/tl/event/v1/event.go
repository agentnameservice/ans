// Package v1 defines the V1 event envelope served by this ans-tl.
//
// Byte-for-byte compatible with the reference TL's V1 event type
// hierarchy. V1 is the schema the reference RA has been emitting
// since launch and continues to emit for backwards-compatibility on
// the `/v1/agents/*` RA routes. V2 (the neighbouring
// `internal/tl/event` package) is our evolution of it, emitted from
// the `/v2/ans/agents/*` RA routes.
//
// Key structural differences from V2:
//
//   - `identityCert` / `serverCert` are singleton objects; the
//     rotation-window arrays are `validIdentityCerts[]` /
//     `validServerCerts[]`, present only during overlap windows.
//   - `dnsRecordsProvisioned` is a `map[string]string` (name → value);
//     multi-record-per-type state is lossy here.
//   - `eventType` enum is `[AGENT_DEPRECATED, AGENT_REGISTERED,
//     AGENT_RENEWED, AGENT_REVOKED]` — no intermediate
//     `AGENT_REGISTRATION` / `DOMAIN_VALIDATION` / `AGENT_ACTIVE`
//     events; the V1 RA emits a single `AGENT_REGISTERED` when the
//     registration fully completes.
//
// Both V1 and V2 share the same outer-envelope JSON shape (`payload`
// + `schemaVersion` + `signature` + `status`) — the TL badge/audit
// read path doesn't care which version it's serving, it echoes the
// stored envelope bytes with a `schemaVersion` flag telling clients
// what `payload.producer.event` looks like.
package v1

import (
	"errors"
	"fmt"
	"time"
)

// SchemaVersion pins the envelope label for V1 events. Producer +
// ingest paths check this exactly; JCS is byte-precise so the
// capitalisation matters.
const SchemaVersion = "V1"

// Type classifies a V1 lifecycle event. Values match the reference
// V1 eventType enum — no intermediate transitions, only the four
// terminal states.
type Type string

// The V1 event-type enum — exactly four terminal lifecycle states
// the reference RA emits. V2 has richer intermediate states
// (AGENT_REGISTRATION, DOMAIN_VALIDATION, AGENT_ACTIVE, …) but V1
// producers only emit the final outcome.
const (
	TypeAgentDeprecated Type = "AGENT_DEPRECATED"
	TypeAgentRegistered Type = "AGENT_REGISTERED"
	TypeAgentRenewed    Type = "AGENT_RENEWED"
	TypeAgentRevoked    Type = "AGENT_REVOKED"
)

// Valid reports whether t is one of the four V1 enum values.
func (t Type) Valid() bool {
	switch t {
	case TypeAgentDeprecated, TypeAgentRegistered, TypeAgentRenewed, TypeAgentRevoked:
		return true
	default:
		return false
	}
}

// Envelope is the top-level V1 structure appended to the Merkle tree.
// Field order + JSON tags match the reference V1 envelope exactly so
// JCS bytes round-trip byte-for-byte against reference-signed
// envelopes.
type Envelope struct {
	Payload       *Payload `json:"payload,omitempty"`
	SchemaVersion string   `json:"schemaVersion,omitempty"`
	Signature     string   `json:"signature,omitempty"` // TL attestation (detached JWS)
	Status        string   `json:"status,omitempty"`
}

// Payload wraps the producer-signed event with a TL-assigned logId.
// Identical shape to V2.
//
// Field order in this struct is chosen for memory alignment on
// 64-bit architectures (pointer first); JCS sorts JSON keys
// lexically so the on-wire order is unaffected by Go field order.
type Payload struct {
	Producer *Producer `json:"producer"`
	LogID    string    `json:"logId"`
}

// Producer records the event together with the producer's identity
// and its detached-JWS attestation over the inner Event.
type Producer struct {
	Event     *Event `json:"event"`
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// Event is the producer-authored V1 payload. Matches the reference
// V1 event struct field-for-field.
type Event struct {
	AnsID                string        `json:"ansId"`
	AnsName              string        `json:"ansName"`
	EventType            Type          `json:"eventType"`
	Agent                *Agent        `json:"agent,omitempty"`
	Attestations         *Attestations `json:"attestations,omitempty"`
	ExpiresAt            string        `json:"expiresAt,omitempty"`
	IssuedAt             string        `json:"issuedAt,omitempty"`
	RaID                 string        `json:"raId,omitempty"`
	RenewalStatus        string        `json:"renewalStatus,omitempty"`
	RevocationReasonCode string        `json:"revocationReasonCode,omitempty"`
	RevokedAt            string        `json:"revokedAt,omitempty"`
	Timestamp            string        `json:"timestamp"` // RFC3339, required
}

// Agent identifies which agent the event refers to. Same shape
// as V2's Agent.
type Agent struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	ProviderID string `json:"providerId,omitempty"`
}

// Attestations is the V1 evidence shape. Differs from V2 in THREE
// spots:
//
//  1. `identityCert` / `serverCert` are singleton fields (V2 has
//     arrays instead).
//  2. `validIdentityCerts[]` / `validServerCerts[]` are the V1
//     rotation-window arrays (V2 consolidates into the unified
//     arrays above).
//  3. `dnsRecordsProvisioned` is a `map[string]string` (name → data)
//     — a lossy representation when an agent publishes more than one
//     record of the same type (e.g. two `_ans` TXT records). V2's
//     typed-array representation preserves that correctly.
//
// Field order here is chosen for memory alignment (maps + slices +
// pointers first, then the scalar tail); JCS sorts JSON keys
// lexically so on-wire order is unaffected by Go declaration order.
type Attestations struct {
	DNSRecordsProvisioned map[string]string         `json:"dnsRecordsProvisioned,omitempty"`
	MetadataHashes        map[string]string         `json:"metadataHashes,omitempty"`
	IdentityCert          *CertificateInfo          `json:"identityCert,omitempty"`
	ServerCert            *CertificateInfo          `json:"serverCert,omitempty"`
	DomainValidation      string                    `json:"domainValidation,omitempty"`
	ValidIdentityCerts    []CertificateInfoExtended `json:"validIdentityCerts,omitempty"`
	ValidServerCerts      []CertificateInfoExtended `json:"validServerCerts,omitempty"`
}

// CertificateInfo describes one certificate by fingerprint + type.
// V1-shaped — no `notAfter` on the base type; the rotation-array
// entries use CertificateInfoExtended when expiry matters.
type CertificateInfo struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	CertType    string `json:"type,omitempty"`
}

// CertificateInfoExtended adds an expiry timestamp for use in the
// rotation arrays.
type CertificateInfoExtended struct {
	Fingerprint string `json:"fingerprint"`
	CertType    string `json:"type"`
	NotAfter    string `json:"notAfter,omitempty"`
}

// Validate checks the inner event for the minimum fields the TL
// needs to index, dedup, and build a producer signature over. Does
// NOT check wrapper fields (logId, producer key, etc.) — those are
// owned by `Envelope.Validate`. Mirrors `event.Event.Validate` on
// the V2 side so the ingest codec can call both uniformly.
func (e *Event) Validate() error {
	if e == nil {
		return errors.New("event/v1: nil event")
	}
	if e.AnsID == "" {
		return errors.New("event/v1: event.ansId required")
	}
	if e.AnsName == "" {
		return errors.New("event/v1: event.ansName required")
	}
	if !e.EventType.Valid() {
		return fmt.Errorf("event/v1: invalid eventType %q", e.EventType)
	}
	if e.Timestamp == "" {
		return errors.New("event/v1: event.timestamp required")
	}
	if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
		return fmt.Errorf("event/v1: event.timestamp not RFC3339: %w", err)
	}
	return nil
}

// Validate checks the minimum fields the TL needs to index, dedup,
// and sign the envelope. Does NOT verify the producer signature.
func (e *Envelope) Validate() error {
	if e == nil {
		return errors.New("event/v1: nil envelope")
	}
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("event/v1: schemaVersion must be %q, got %q",
			SchemaVersion, e.SchemaVersion)
	}
	if e.Payload == nil {
		return errors.New("event/v1: payload required")
	}
	if e.Payload.LogID == "" {
		return errors.New("event/v1: payload.logId required")
	}
	if e.Payload.Producer == nil {
		return errors.New("event/v1: payload.producer required")
	}
	if e.Payload.Producer.Event == nil {
		return errors.New("event/v1: payload.producer.event required")
	}
	return e.Payload.Producer.Event.Validate()
}
