package v1

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	anscrypto "github.com/godaddy/ans/internal/crypto"
)

// BuildEnvelope is the single chokepoint for V1 envelope construction
// on the TL side of the boundary. The TL receives an Event + producer
// signature + producer keyId; it assigns logId and wraps.
//
// Structurally identical to the V2 BuildEnvelope — only the inner
// event shape differs.
func BuildEnvelope(logID string, inner *Event, producerKeyID, producerSignature string) *Envelope {
	return &Envelope{
		SchemaVersion: SchemaVersion,
		Payload: &Payload{
			LogID: logID,
			Producer: &Producer{
				Event:     inner,
				KeyID:     producerKeyID,
				Signature: producerSignature,
			},
		},
	}
}

// CanonicalizeEvent JCS-canonicalizes a V1 producer Event. Used by
// the producer before signing and by the TL to verify the producer
// signature — both sides MUST run the same canonicalization or
// signatures drift.
func CanonicalizeEvent(inner *Event) ([]byte, error) {
	return canonicalize(inner)
}

// SigningInput returns the JCS-canonical bytes of the envelope while
// its outer Signature is empty. These are the bytes the TL's
// attestation signer signs.
func (e *Envelope) SigningInput() ([]byte, error) {
	if e.Signature != "" {
		return nil, errors.New("event/v1: SigningInput called on already-signed envelope")
	}
	return canonicalize(e)
}

// LeafBytes returns the JCS-canonical bytes of the fully signed
// envelope — the bytes Tessera appends to the Merkle tree. The
// envelope's outer Signature MUST be populated before calling this.
func (e *Envelope) LeafBytes() ([]byte, error) {
	if e.Signature == "" {
		return nil, errors.New("event/v1: LeafBytes called on unsigned envelope")
	}
	return canonicalize(e)
}

// LeafHash returns the RFC 6962 §2.1 leaf hash:
//
//	SHA-256(0x00 || JCS(signed envelope))
//
// Same formula as V2 — schema-version-agnostic hashing, Tessera
// doesn't care which inner event shape it wrapped.
func (e *Envelope) LeafHash() ([32]byte, error) {
	leaf, err := e.LeafBytes()
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// canonicalize is the shared json.Marshal + JCS wrapper, duplicated
// from the v2 package so this package has zero cross-imports back
// into the parent (avoids an import cycle if the v2 package ever
// depends on v1 for a compat shim).
func canonicalize(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("event/v1: marshal: %w", err)
	}
	out, err := anscrypto.Canonicalize(body)
	if err != nil {
		return nil, fmt.Errorf("event/v1: canonicalize: %w", err)
	}
	return out, nil
}

// AgentID, AnsName, etc. — accessor shortcuts that mirror the V2
// Envelope's method set so a future EnvelopeAccessor interface
// (handling both V1 and V2 behind one type) can be added without
// reworking call sites.

// AgentID returns inner.AnsID or "" if the envelope is partially filled.
func (e *Envelope) AgentID() string {
	if inner := e.innerEvent(); inner != nil {
		return inner.AnsID
	}
	return ""
}

// AnsName returns inner.AnsName or "".
func (e *Envelope) AnsName() string {
	if inner := e.innerEvent(); inner != nil {
		return inner.AnsName
	}
	return ""
}

// AgentFQDN returns inner.Agent.Host or "".
func (e *Envelope) AgentFQDN() string {
	if inner := e.innerEvent(); inner != nil && inner.Agent != nil {
		return inner.Agent.Host
	}
	return ""
}

// EventType returns the event type as a string (so the shared
// sqlite_tl store can index without a per-version type assertion).
func (e *Envelope) EventType() string {
	if inner := e.innerEvent(); inner != nil {
		return string(inner.EventType)
	}
	return ""
}

// Timestamp returns inner.Timestamp or "".
func (e *Envelope) Timestamp() string {
	if inner := e.innerEvent(); inner != nil {
		return inner.Timestamp
	}
	return ""
}

// LogID returns Payload.LogID or "".
func (e *Envelope) LogID() string {
	if e.Payload != nil {
		return e.Payload.LogID
	}
	return ""
}

// ProducerKeyID returns Payload.Producer.KeyID or "".
func (e *Envelope) ProducerKeyID() string {
	if e.Payload != nil && e.Payload.Producer != nil {
		return e.Payload.Producer.KeyID
	}
	return ""
}

// ProducerSignature returns Payload.Producer.Signature or "".
func (e *Envelope) ProducerSignature() string {
	if e.Payload != nil && e.Payload.Producer != nil {
		return e.Payload.Producer.Signature
	}
	return ""
}

// Version returns the on-wire schemaVersion tag ("V1"). Version-
// agnostic consumers (sqlite_tl.EventStore, badge/audit handlers)
// read this to decide how to present the envelope; the rest of the
// byte shape is shared with V2 at the wrapper level.
func (e *Envelope) Version() string { return e.SchemaVersion }

func (e *Envelope) innerEvent() *Event {
	if e.Payload != nil && e.Payload.Producer != nil {
		return e.Payload.Producer.Event
	}
	return nil
}
