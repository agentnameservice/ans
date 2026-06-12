// Package project turns a single ANS feed event (feed.EventItem) into
// zero or more ARD catalog entries — the Finder's discovery records.
//
// It is pure: no I/O, no clock, no network. FromEvent is the only
// exported entry point. Output is deterministic for a given input, so
// the projection can be golden-tested byte-for-byte.
//
// The package enforces two security chokepoints (see sanitize.go):
//   - every emitted string passes one control-/bidi-character stripper;
//   - every emitted URL passes one validateEmittedURL gate bound to the
//     event's attested host.
//
// The lifecycle split is the package's safety rule (see project.go):
// REVOKED/DEPRECATED events mint identity-only tombstones that never
// pass through label minting or URL policy, so a malformed display
// field can never block a revocation from taking effect.
package project

// Entry is the wire shape of an ARD catalog entry the Finder emits
// (ARDS §4.2). Field names and `omitempty` choices match
// spec/api-spec-finder-v1.yaml `CatalogEntry`. Standard encoding/json
// marshaling (HTML-escaped) applies; this is not a JCS-canonical type.
//
// For an Active entry exactly one of URL or Data is set (ARDS §3.4); the
// Finder always emits URL. Tombstones are carried in ProjectedEntry, not
// Entry, and never reach the wire.
type Entry struct {
	Identifier    string            `json:"identifier"`
	DisplayName   string            `json:"displayName"`
	Type          string            `json:"type"`
	URL           string            `json:"url,omitempty"`
	Data          map[string]any    `json:"data,omitempty"`
	Description   string            `json:"description,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Version       string            `json:"version,omitempty"`
	UpdatedAt     string            `json:"updatedAt,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	TrustManifest *TrustManifest    `json:"trustManifest,omitempty"`
}

// TrustManifest carries verifiable identity and trust metadata
// (ARDS §5.1). The Finder emits the agent's verified host as an https
// FQDN identity plus a single ANS-Registration attestation.
type TrustManifest struct {
	Identity     string        `json:"identity"`
	IdentityType string        `json:"identityType,omitempty"`
	Attestations []Attestation `json:"attestations,omitempty"`
}

// Attestation is one verifiable claim (ARDS §5.2). The Finder's
// ANS-Registration attestation points at the agent's SCITT receipt on
// the Transparency Log; it carries no Digest (the receipt is an
// inclusion proof of the latest event, not a digest of this entry).
type Attestation struct {
	Type      string `json:"type"`
	URI       string `json:"uri"`
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest,omitempty"`
}

// Lifecycle is the projected disposition of an event.
type Lifecycle string

const (
	// LifecycleActive marks an entry that should be discoverable.
	LifecycleActive Lifecycle = "ACTIVE"
	// LifecycleRevoked marks a tombstone from an AGENT_REVOKED event.
	LifecycleRevoked Lifecycle = "REVOKED"
	// LifecycleDeprecated marks a tombstone from an AGENT_DEPRECATED event.
	LifecycleDeprecated Lifecycle = "DEPRECATED"
)

// ProjectedEntry wraps a wire Entry with index-side bookkeeping that
// never reaches the search/explore wire. The wrapper fields carry
// per-registration keys (AgentID/AnsName/LogID) the index uses to apply
// tombstones and detect divergence, plus ExpiresAt for PR 3's
// serve-time expiry policy (no AGENT_EXPIRED event exists).
//
// For a tombstone (Lifecycle REVOKED/DEPRECATED) only the wrapper fields
// and the Entry's identity fields are meaningful; the Entry carries no
// url/data/display metadata.
type ProjectedEntry struct {
	Entry
	Lifecycle Lifecycle `json:"-"`
	AgentID   string    `json:"-"`
	AnsName   string    `json:"-"`
	LogID     string    `json:"-"`
	ExpiresAt string    `json:"-"`
}

// SkipKind classifies why an event or endpoint produced no entry. The
// kinds let PR 3 alert on the ones that signal a contract surprise
// (UnknownEventType, UnknownProtocol) versus the ones that are routine
// publisher-data issues (MissingLabel, InvalidURL).
type SkipKind string

const (
	// SkipUnknownEventType marks an event whose eventType is outside the
	// known enum. Alertable: the producer's enum may have grown. It is a
	// Skip, never a structural error — an error would wedge ingestion at
	// the cursor.
	SkipUnknownEventType SkipKind = "UnknownEventType"
	// SkipMissingLabel marks an Active event whose displayName produced
	// no URN label (empty/sanitized-away). One Skip per event.
	SkipMissingLabel SkipKind = "MissingLabel"
	// SkipUnknownProtocol marks an endpoint whose protocol token is not
	// recognized. One Skip per endpoint. Alertable.
	SkipUnknownProtocol SkipKind = "UnknownProtocol"
	// SkipInvalidURL marks an endpoint dropped because its emitted URL
	// failed policy (fail-closed; no fallback rescue). One Skip per
	// endpoint.
	SkipInvalidURL SkipKind = "InvalidURL"
)

// Skip records one reason a projection produced fewer entries than its
// input endpoints, with enough detail to log or alert. Detail is for
// operators; it is never emitted on the discovery wire.
type Skip struct {
	Kind   SkipKind
	Detail string
}

// Projection is the result of projecting one event: the entries it
// produced (Active entries fan out one per includable endpoint;
// tombstones are a single entry) plus any Skips for survivors that fell
// out. Entries is never nil after a successful FromEvent (it may be
// empty).
type Projection struct {
	Entries []ProjectedEntry
	Skipped []Skip
}
