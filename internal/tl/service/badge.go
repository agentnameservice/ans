package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
)

// BadgeStatus is the real-time lifecycle label surfaced on the badge
// endpoint, derived from the agent's most recent event plus its
// declared expiry (if any).
type BadgeStatus string

const (
	BadgeActive     BadgeStatus = "ACTIVE"
	BadgeDeprecated BadgeStatus = "DEPRECATED"
	BadgeRevoked    BadgeStatus = "REVOKED"
	BadgeExpired    BadgeStatus = "EXPIRED"
	BadgeWarning    BadgeStatus = "WARNING"
	BadgeUnknown    BadgeStatus = "UNKNOWN"
)

// TransparencyLog is the reference-shaped badge / audit-entry
// response. Matches the reference TL swagger's TransparencyLog
// schema field-for-field so external verifiers built against the
// reference consume ours unchanged.
//
// All fields except `payload` are nullable/optional; `payload` is
// the payload piece of the envelope (logId + producer{event,
// keyId, signature}) — the bytes that are byte-identical to what
// the RA signed. `signature` is the outer TL attestation JWS.
//
// Per spec, `expiresAt` lives on the inner event
// (`payload.producer.event.expiresAt`), not on this wrapper. The TL
// still uses the inner `expiresAt` to derive the read-time `status`
// transitions (WARNING / EXPIRED), but it is not echoed at the root —
// callers parse it out of `payload` themselves.
type TransparencyLog struct {
	MerkleProof   *MerkleProof `json:"merkleProof,omitempty"`
	Payload       any          `json:"payload"`
	SchemaVersion string       `json:"schemaVersion,omitempty"`
	Signature     string       `json:"signature,omitempty"`
	Status        BadgeStatus  `json:"status,omitempty"`

	// Identities is the computed read-time join of the agent's
	// currently-linked verified identities — populated on the agent
	// badge only (never on audit entries, never sealed). The handler
	// composes it from the IdentityBadgeService so this service stays
	// single-purpose. Covered by the TL's response signature, not by
	// any seal: link facts live on the identity stream.
	Identities []*LinkedIdentityView `json:"identities,omitempty"`

	// IdentitiesTotal counts every visible link when Identities is
	// present — the badge embeds at most a small safety cap of
	// entries (§5.6.1); the standalone, paginated
	// /v1/agents/{agentId}/identities route is the overflow target.
	IdentitiesTotal int `json:"identitiesTotal,omitempty"`

	// IdentitiesUnavailable is set when the identities join could not
	// be computed (design §5.6.3: join failure is explicit, never
	// silent) — an absent/empty identities[] always means "no visible
	// links", never "the join failed".
	IdentitiesUnavailable bool `json:"identitiesUnavailable,omitempty"`

	// Keys / KeysLogID are the identity badge's computed quote of the
	// CURRENT proven key set (design §5.6.3 "computed views carry the
	// keys"): the verification methods verbatim from the latest
	// sealed proof event, with KeysLogID pointing at that seal (fetch
	// it for the signedProof evidence). Populated on the identity
	// badge only — never on audit entries — and omitted when the
	// identity is REVOKED (the keys are no longer attested).
	Keys      []json.RawMessage `json:"keys,omitempty"`
	KeysLogID string            `json:"keysLogId,omitempty"`
}

// BadgeService computes the badge from the latest mirrored event
// and builds the Merkle inclusion proof against the latest
// checkpoint.
type BadgeService struct {
	log           *LogService
	warningWindow time.Duration
}

// NewBadgeService constructs a BadgeService with a 30-day warning window.
func NewBadgeService(log *LogService) *BadgeService {
	return &BadgeService{log: log, warningWindow: 30 * 24 * time.Hour}
}

// Get returns the full TransparencyLog view of an agent's most
// recent event. Merkle proof is omitted (nil) if the latest
// checkpoint doesn't yet cover the leaf — clients can retry shortly
// after the next checkpoint tick.
func (s *BadgeService) Get(ctx context.Context, agentID string) (*TransparencyLog, error) {
	rec, err := s.log.LatestEventByAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	return s.buildTransparencyLog(ctx, rec)
}

// StatusOf returns only the agent's read-time badge status — the
// latest-event read plus the cheap envelope parse, WITHOUT building
// a Merkle inclusion proof (no checkpoint read, no tile walk). The
// identity reverse join needs the agent-liveness conjunct of the
// §5.6.3 visibility predicate but discards the proof, so calling the
// full Get() per linked agent was O(total) wasted proof builds.
func (s *BadgeService) StatusOf(ctx context.Context, agentID string) (BadgeStatus, error) {
	rec, err := s.log.LatestEventByAgent(ctx, agentID)
	if err != nil {
		return "", err
	}
	wrapper, err := parseEnvelopeWrapper(rec.RawEvent)
	if err != nil {
		return "", err
	}
	return s.statusFromRecord(rec, wrapper.certExpiresAt()), nil
}

// buildTransparencyLog assembles a TransparencyLog from a stored
// event record. Used by both Get (latest event) and Audit (each
// record in the page).
//
// Schema-version-agnostic: we don't try to parse the envelope into a
// concrete Go type (that would require picking V1 or V2 at compile
// time). Instead we parse the outer wrapper generically — fields
// every version shares: `payload`, `schemaVersion`, `signature` —
// and pass `payload` through as opaque JSON. Clients read
// `schemaVersion` and parse `payload.producer.event` accordingly.
func (s *BadgeService) buildTransparencyLog(ctx context.Context, rec *sqlitetl.EventRecord) (*TransparencyLog, error) {
	wrapper, err := parseEnvelopeWrapper(rec.RawEvent)
	if err != nil {
		return nil, err
	}

	proof, perr := BuildMerkleProof(ctx, s.log.log, rec)
	if perr != nil && !errors.Is(perr, ErrProofLeafNotCovered) {
		// Proof-builder failed for a reason other than "not yet
		// covered". Log at the handler layer if needed; here we
		// swallow and return no proof. A real verifier will notice
		// the missing proof field and either retry or fail.
		proof = nil
	}

	// `payload` is the middle piece of the envelope — logId +
	// producer{event, keyId, signature}. Everything under
	// `payload.producer.event` is what the RA signed. Matches the
	// reference TL's V1 transparency-log payload shape byte-for-byte,
	// and carries through for V2 envelopes unchanged.
	schema := rec.SchemaVersion
	if schema == "" {
		schema = wrapper.SchemaVersion
	}
	// `exp` is read out of the inner event payload to compute the
	// read-time `status` transitions (WARNING / EXPIRED). Per spec
	// the wire field lives on `payload.producer.event.expiresAt`, not
	// on the wrapper, so we don't surface it here — callers that
	// need the raw value parse `payload` themselves.
	exp := wrapper.certExpiresAt()
	return &TransparencyLog{
		MerkleProof:   proof,
		Payload:       wrapper.Payload,
		SchemaVersion: schema,
		Signature:     wrapper.Signature,
		Status:        s.statusFromRecord(rec, exp),
	}, nil
}

// statusFromRecord derives the badge status from the stored event
// record's event_type column + the effective cert expiry drilled out
// of the envelope attestations. Terminal transitions come from the
// event type (AGENT_REVOKED, AGENT_DEPRECATED); WARNING / EXPIRED
// come from `now` vs `certExpiresAt` and carry no corresponding
// event.
func (s *BadgeService) statusFromRecord(rec *sqlitetl.EventRecord, certExpiresAt time.Time) BadgeStatus {
	switch rec.EventType {
	case "AGENT_REVOKED":
		return BadgeRevoked
	case "AGENT_DEPRECATED":
		return BadgeDeprecated
	}
	if !certExpiresAt.IsZero() {
		now := time.Now().UTC()
		switch {
		case !now.Before(certExpiresAt):
			return BadgeExpired
		case certExpiresAt.Sub(now) < s.warningWindow:
			return BadgeWarning
		}
	}
	return BadgeActive
}

// Audit returns paginated event history for an agent — each entry
// is a full TransparencyLog-shaped record matching the reference
// swagger.yaml §TransparencyLogAudit.records.
//
// Building a Merkle proof for every historical entry is O(N) on the
// page size since each proof walks the tree for a different leaf;
// that's acceptable for reasonable page sizes (default 50, max 200).
// For larger audits a streaming shape is future work.
func (s *BadgeService) Audit(ctx context.Context, agentID string, limit, offset int) ([]*TransparencyLog, error) {
	recs, err := s.log.EventsByAgent(ctx, agentID, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]*TransparencyLog, 0, len(recs))
	for _, rec := range recs {
		tl, err := s.buildTransparencyLog(ctx, rec)
		if err != nil {
			return nil, err
		}
		out = append(out, tl)
	}
	return out, nil
}
