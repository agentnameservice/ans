package event

// View is the version-agnostic surface an envelope exposes to code
// that persists, indexes, or echoes events without caring about the
// inner shape. Both `*event.Envelope` (V2) and `*v1.Envelope` (V1)
// implement it so the SQLite store, ingest handler, and badge/audit
// read handlers can work uniformly.
//
// Keeping this an interface (rather than two parallel store
// functions) means adding a future V3 just needs new types that
// satisfy View — no new store/handler code.
type View interface {
	// Version returns the on-wire `schemaVersion` label (V1 / V2).
	// Matches the value stored in tl_events.schema_version and
	// echoed in TransparencyLog.schemaVersion at query time.
	Version() string

	// LogID returns the TL-assigned logId (UUIDv7) attached at ingest.
	LogID() string

	// AgentID / AnsName / AgentFQDN / EventType / Timestamp index
	// the event on the read side. Shape-agnostic at the wrapper
	// level; the inner event differs between V1 and V2 but these
	// accessors reach down through the envelope consistently.
	AgentID() string
	AnsName() string
	AgentFQDN() string
	EventType() string
	Timestamp() string

	// ProducerKeyID / ProducerSignature expose the detached JWS the
	// producer signed over the inner event — used by the TL's
	// ingest-time verifier and echoed into the TransparencyLog
	// response for client-side validation.
	ProducerKeyID() string
	ProducerSignature() string
}

// Signable is View plus the write-side methods needed to build a
// Merkle leaf. Implemented by both `*event.Envelope` (V2) and
// `*v1.Envelope` (V1). Split from View so the read path
// (sqlite_tl.EventStore) only sees what it needs — a wider
// interface there would force unneeded coupling between persistence
// and envelope-construction code.
//
// The caller owns the lifecycle: Validate first, populate outer
// Signature, then LeafBytes/LeafHash for the canonical-on-the-wire
// bytes the log stores.
type Signable interface {
	View

	// Validate checks structural invariants (schemaVersion tag,
	// inner event present, required fields populated). Does NOT
	// verify the producer signature; that's a separate concern.
	Validate() error

	// SigningInput returns the JCS-canonical bytes of the envelope
	// while its outer Signature is still empty. These are the bytes
	// the TL's attestation signer signs. Errors if the envelope is
	// already signed (a misuse guard — signing twice would invalidate
	// the prior signature's domain).
	SigningInput() ([]byte, error)

	// LeafBytes returns the JCS-canonical bytes of the *fully
	// signed* envelope — the bytes Tessera stores as a leaf. Errors
	// if the outer Signature is still empty.
	LeafBytes() ([]byte, error)

	// LeafHash returns the RFC 6962 §2.1 leaf hash
	// (SHA-256(0x00 || LeafBytes())). Version-agnostic — Tessera
	// doesn't care which inner event shape was wrapped.
	LeafHash() ([32]byte, error)
}
