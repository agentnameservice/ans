// Package identity defines the Transparency Log event family for
// Verified Identities — the "who" behind an agent. Identity events
// ride the same producer lane, the same envelope wrapper shape, and
// the same Merkle tree as agent events; what differs is the inner
// event payload (keyed by identityId instead of ansId) and the
// closed eventType vocabulary.
//
// Shape is a contract: sealed events are append-only-forever, so the
// five tokens and the payload fields below must not change once a
// real TL has sealed them. The canonicalization and leaf-hash rules
// are identical to the agent envelope (JCS + RFC 6962 §2.1) — one
// log, one set of verifier rules.
//
// Cross-lane guard: an identity event posted to an agent ingest lane
// fails the agent codec's closed enum (and lacks ansId); an agent
// event posted to the identity lane fails this package's closed enum
// (and lacks identityId). Both reject with 422 INVALID_EVENT, so the
// V1 lane stays frozen and the two V2 families cannot cross.
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

// SchemaVersion pins the envelope version. Identity events are part
// of the V2 surface (the V2 event-set amendment adds the five
// IDENTITY_* tokens); the V1 lane never carries them.
const SchemaVersion = "V2"

// Type classifies an identity lifecycle event. The set is closed —
// adding a token is a spec amendment, not a code change.
type Type string

// The identity event family. Every IDENTITY_* event — proofs,
// rotations, revocations, and links — seals on the identity stream
// (read-indexed by identityId). An identity operation never writes
// to an agent's stream; propagation to linked agents is a read-time
// join.
const (
	// TypeIdentityVerified — first successful control proof. Seals
	// every proven key self-verifyingly (public key + signed proof).
	TypeIdentityVerified Type = "IDENTITY_VERIFIED"

	// TypeIdentityUpdated — a rotation (PUT + verify-control)
	// completed. One event total, regardless of linked-agent count.
	TypeIdentityUpdated Type = "IDENTITY_UPDATED"

	// TypeIdentityRevoked — the identity was revoked by its owner.
	// Terminal. Linked agents reflect it at the next read.
	TypeIdentityRevoked Type = "IDENTITY_REVOKED"

	// TypeIdentityLinked — a batch of the owner's agents was linked.
	// One event carries the whole batch in ansIds[].
	TypeIdentityLinked Type = "IDENTITY_LINKED"

	// TypeIdentityUnlinked — an association ended. The event is the
	// history; the link rows elsewhere are merely caches.
	TypeIdentityUnlinked Type = "IDENTITY_UNLINKED"
)

// IsValid reports whether t is a recognized identity event type.
func (t Type) IsValid() bool {
	switch t {
	case TypeIdentityVerified,
		TypeIdentityUpdated,
		TypeIdentityRevoked,
		TypeIdentityLinked,
		TypeIdentityUnlinked:
		return true
	default:
		return false
	}
}

// isLink reports whether t is one of the two association events.
func (t Type) isLink() bool {
	return t == TypeIdentityLinked || t == TypeIdentityUnlinked
}

// isProof reports whether t seals a control proof (and therefore
// must carry the proven key set).
func (t Type) isProof() bool {
	return t == TypeIdentityVerified || t == TypeIdentityUpdated
}

// Envelope is the top-level structure appended to the Merkle tree —
// the same wrapper shape as the agent envelope (payload /
// schemaVersion / signature / status) with an identity inner event.
type Envelope struct {
	Payload       *Payload `json:"payload,omitempty"`
	SchemaVersion string   `json:"schemaVersion,omitempty"`
	Signature     string   `json:"signature,omitempty"` // TL attestation (detached JWS)
	Status        string   `json:"status,omitempty"`
}

// Payload wraps the producer's signed event with a TL-assigned logId.
type Payload struct {
	LogID    string    `json:"logId"`
	Producer *Producer `json:"producer"`
}

// Producer records the event together with the producer's identity
// and its detached-JWS attestation over the inner Event.
type Producer struct {
	Event     *Event `json:"event"`
	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// Event is the producer-authored identity event payload. The RA
// JCS-canonicalizes this and signs it; the resulting detached JWS
// lands in Producer.Signature.
type Event struct {
	// AnsIDs carries the linked agents' ids on IDENTITY_LINKED /
	// IDENTITY_UNLINKED — the whole batch in one event. Forbidden on
	// the proof/revocation types: those events never name agents.
	AnsIDs []string `json:"ansIds,omitempty"`

	EventType Type `json:"eventType"`

	// IdentityID is the stream key — the RA-assigned UUIDv7 of the
	// VerifiedIdentity aggregate. Required on every identity event.
	IdentityID string `json:"identityId"`

	// Kind is the identifier kind ("did:web" | "did:key" | "lei").
	Kind string `json:"kind"`

	// Keys is the proven key set — one entry per key the registrant
	// proved possession of. Required (non-empty) on the proof events;
	// self-verifying: each entry quotes the DID document's
	// verification method VERBATIM alongside the registrant's proof.
	Keys []ProvenKey `json:"keys,omitempty"`

	// PreviousValue records the pre-rotation identifier value on
	// IDENTITY_UPDATED.
	PreviousValue string `json:"previousValue,omitempty"`

	// ProofMethod names the control-proof mechanism
	// ("did-web-sig" | "did-key-sig" | "lei-vlei-acdc").
	ProofMethod string `json:"proofMethod,omitempty"`

	// ProviderID is the owning principal — the WHO's owner, parallel
	// to the agent event's agent.providerId.
	ProviderID string `json:"providerId,omitempty"`

	RaID      string `json:"raId,omitempty"`
	RevokedAt string `json:"revokedAt,omitempty"`
	Timestamp string `json:"timestamp"` // RFC3339, required

	// Value is the canonical identifier
	// (e.g. "did:web:identity.acme-corp.com").
	Value string `json:"value"`

	VerifiedAt string `json:"verifiedAt,omitempty"`
}

// ProvenKey is one key the registrant proved possession of, sealed
// self-verifyingly: any third party reads the key material out of
// VerificationMethod, verifies SignedProof against it, then confirms
// the payload decodes to an IdentityProofInput binding this
// identityId + identifier + purpose — offline, without trusting the
// RA.
//
// VerificationMethod is quoted EXACTLY as the DID document served it
// — id, type, controller, and the key material in whichever
// representation the document used (publicKeyJwk, or
// publicKeyMultibase for Multikey documents) — member-for-member,
// values untouched. Nothing derived, re-encoded, or normalized
// enters a seal: the envelope is JCS-canonicalized for signing like
// every event, and JCS preserves member values exactly, so the
// quoted material survives intact. Thumbprints are compute-at-read
// conveniences (anyone can derive RFC 7638 from the sealed source);
// they are never part of the sealed contract.
//
// The lei kind is the one deliberate exception: it seals the
// subject AID + a key thumbprint only — there is no
// document to quote, the ACDC is PII, and KERI's KEL is already the
// authoritative key history. Seal verbatim what has no other
// tamper-evident home; commit minimally where one exists.
type ProvenKey struct {
	// VerificationMethod is the DID document's verification-method
	// object, verbatim.
	VerificationMethod json.RawMessage `json:"verificationMethod"`

	// SignedProof is the compact JWS the registrant submitted over
	// the served IdentityProofInput.
	SignedProof string `json:"signedProof"`
}

// ID extracts the verification-method id from the sealed verbatim
// object — the read-side accessor index/joins use.
func (k ProvenKey) ID() string {
	var vm struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(k.VerificationMethod, &vm); err != nil {
		return ""
	}
	return vm.ID
}

// Validate returns nil if the envelope has the minimum fields the TL
// requires to index, de-dupe, and sign the event. It does NOT verify
// the producer signature — that's handled upstream.
func (e *Envelope) Validate() error {
	if e == nil {
		return errors.New("identityevent: nil envelope")
	}
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("identityevent: schemaVersion must be %q, got %q", SchemaVersion, e.SchemaVersion)
	}
	if e.Payload == nil {
		return errors.New("identityevent: payload required")
	}
	if e.Payload.LogID == "" {
		return errors.New("identityevent: payload.logId required")
	}
	if e.Payload.Producer == nil {
		return errors.New("identityevent: payload.producer required")
	}
	p := e.Payload.Producer
	if p.KeyID == "" {
		return errors.New("identityevent: payload.producer.keyId required")
	}
	if p.Signature == "" {
		return errors.New("identityevent: payload.producer.signature required")
	}
	return p.Event.Validate()
}

// Validate enforces the per-type required-field matrix:
//
//	all types       — identityId, kind, value, RFC3339 timestamp
//	VERIFIED/UPDATED — non-empty keys[] (each with thumbprint +
//	                   verificationMethodId), verifiedAt, providerId
//	REVOKED          — revokedAt
//	LINKED/UNLINKED  — non-empty ansIds[]
//	non-link types   — ansIds[] forbidden (identity facts never name agents)
func (ev *Event) Validate() error {
	if ev == nil {
		return errors.New("identityevent: producer.event required")
	}
	if !ev.EventType.IsValid() {
		return fmt.Errorf("identityevent: invalid eventType %q", ev.EventType)
	}
	if ev.IdentityID == "" {
		return errors.New("identityevent: identityId required")
	}
	if ev.Kind == "" {
		return errors.New("identityevent: kind required")
	}
	if ev.Value == "" {
		return errors.New("identityevent: value required")
	}
	if ev.Timestamp == "" {
		return errors.New("identityevent: timestamp required")
	}
	if _, err := time.Parse(time.RFC3339, ev.Timestamp); err != nil {
		return fmt.Errorf("identityevent: timestamp must be RFC3339: %w", err)
	}
	if ev.EventType.isLink() {
		if len(ev.AnsIDs) == 0 {
			return fmt.Errorf("identityevent: %s requires non-empty ansIds", ev.EventType)
		}
		for i, id := range ev.AnsIDs {
			if id == "" {
				return fmt.Errorf("identityevent: ansIds[%d] is empty", i)
			}
		}
	} else if len(ev.AnsIDs) > 0 {
		return fmt.Errorf("identityevent: ansIds forbidden on %s", ev.EventType)
	}
	if ev.EventType.isProof() {
		if err := ev.validateProofFields(); err != nil {
			return err
		}
	}
	if ev.EventType == TypeIdentityRevoked && ev.RevokedAt == "" {
		return errors.New("identityevent: IDENTITY_REVOKED requires revokedAt")
	}
	return nil
}

// validateProofFields enforces the proof-event requirements: a
// non-empty sealed key set (each entry a verbatim verification
// method carrying an id, plus the registrant's proof), verifiedAt,
// and the owning providerId.
func (ev *Event) validateProofFields() error {
	if len(ev.Keys) == 0 {
		return fmt.Errorf("identityevent: %s requires non-empty keys", ev.EventType)
	}
	for i, k := range ev.Keys {
		if len(k.VerificationMethod) == 0 {
			return fmt.Errorf("identityevent: keys[%d].verificationMethod required", i)
		}
		if k.ID() == "" {
			return fmt.Errorf("identityevent: keys[%d].verificationMethod must be an object with an id", i)
		}
		if k.SignedProof == "" {
			return fmt.Errorf("identityevent: keys[%d].signedProof required", i)
		}
	}
	if ev.VerifiedAt == "" {
		return fmt.Errorf("identityevent: %s requires verifiedAt", ev.EventType)
	}
	if ev.ProviderID == "" {
		return fmt.Errorf("identityevent: %s requires providerId", ev.EventType)
	}
	return nil
}

// SigningInput returns the JCS-canonical bytes of the envelope while
// its outer Signature is still empty — the bytes the TL's attestation
// signer signs. Errors if already signed (signing twice would
// invalidate the prior signature's domain).
func (e *Envelope) SigningInput() ([]byte, error) {
	if e.Signature != "" {
		return nil, errors.New("identityevent: SigningInput called on already-signed envelope")
	}
	return canonicalize(e)
}

// LeafBytes returns the JCS-canonical bytes of the fully signed
// envelope — the bytes Tessera appends to the Merkle tree.
func (e *Envelope) LeafBytes() ([]byte, error) {
	if e.Signature == "" {
		return nil, errors.New("identityevent: LeafBytes called on unsigned envelope")
	}
	return canonicalize(e)
}

// LeafHash returns the RFC 6962 §2.1 leaf hash of the envelope:
// SHA-256(0x00 || LeafBytes()). Identical rule to the agent envelope
// — one tree, one hash discipline.
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

// canonicalize is the shared json.Marshal + JCS wrapper.
func canonicalize(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("identityevent: marshal: %w", err)
	}
	return anscrypto.Canonicalize(body)
}

// BuildEnvelope is the single chokepoint for identity-envelope
// construction on the TL side: the TL receives an Event + producer
// signature + producer keyId; it assigns logId and wraps.
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

// CanonicalizeEvent JCS-canonicalizes a producer Event — the byte
// sequence the RA signs and the TL re-canonicalizes to verify that
// signature. Exposed so both sides of the RA ↔ TL boundary share the
// exact same canonicalization.
func CanonicalizeEvent(inner *Event) ([]byte, error) {
	return canonicalize(inner)
}

// ----- event.View / event.Signable conformance -----
//
// The shared ingest pipeline and the SQLite mirror operate on the
// version-agnostic event.View surface. Identity envelopes implement
// it with empty agent-side accessors (an identity event names no
// single agent) and expose the identity-side fields through the
// optional capability methods IdentityID / LinkedAgentIDs, which the
// store discovers by type assertion.

// Version returns the on-wire schemaVersion tag ("V2").
func (e *Envelope) Version() string { return e.SchemaVersion }

// LogID returns the TL-assigned logId, or "".
func (e *Envelope) LogID() string {
	if e.Payload != nil {
		return e.Payload.LogID
	}
	return ""
}

// AgentID returns "" — identity events are not keyed by a single
// agent; linked agents are exposed via LinkedAgentIDs.
func (e *Envelope) AgentID() string { return "" }

// AnsName returns "" — identity events carry no ANS name.
func (e *Envelope) AnsName() string { return "" }

// AgentFQDN returns "" — identity events carry no agent host.
func (e *Envelope) AgentFQDN() string { return "" }

// EventType returns the inner event's type as a string.
func (e *Envelope) EventType() string {
	if ev := e.innerEvent(); ev != nil {
		return string(ev.EventType)
	}
	return ""
}

// Timestamp returns the producer's RFC3339 timestamp.
func (e *Envelope) Timestamp() string {
	if ev := e.innerEvent(); ev != nil {
		return ev.Timestamp
	}
	return ""
}

// ProducerKeyID returns the kid used by the producer to sign.
func (e *Envelope) ProducerKeyID() string {
	if e.Payload != nil && e.Payload.Producer != nil {
		return e.Payload.Producer.KeyID
	}
	return ""
}

// ProducerSignature returns the detached JWS the producer signed.
func (e *Envelope) ProducerSignature() string {
	if e.Payload != nil && e.Payload.Producer != nil {
		return e.Payload.Producer.Signature
	}
	return ""
}

// IdentityID returns the inner event's identityId — the identity
// stream key the SQLite mirror indexes by.
func (e *Envelope) IdentityID() string {
	if ev := e.innerEvent(); ev != nil {
		return ev.IdentityID
	}
	return ""
}

// LinkedAgentIDs returns the ansIds named by a link event (nil for
// the proof/revocation types). The mirror fans these into the
// agent-side read-join index.
func (e *Envelope) LinkedAgentIDs() []string {
	if ev := e.innerEvent(); ev != nil {
		return ev.AnsIDs
	}
	return nil
}

func (e *Envelope) innerEvent() *Event {
	if e == nil || e.Payload == nil || e.Payload.Producer == nil {
		return nil
	}
	return e.Payload.Producer.Event
}
