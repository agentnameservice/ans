package service

import (
	"context"
	"encoding/json"
	"errors"

	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	"github.com/agentnameservice/ans/internal/domain"
)

// Identity badge statuses. Identities have a two-state read-time
// status (unlike agents, which derive WARNING/EXPIRED from attested
// cert expiry): the stream either ends in a revocation or it doesn't.
const (
	// BadgeVerified — the identity's control proof stands.
	BadgeVerified BadgeStatus = "VERIFIED"
	// BadgeIdentityRevoked — the identity stream ends in
	// IDENTITY_REVOKED. (BadgeRevoked already names the agent label;
	// identities share the wire value.)
	BadgeIdentityRevoked BadgeStatus = "REVOKED"
)

// LinkedIdentityView is one entry of the computed identities[] join
// on the agent badge (and the /v1/agents/{agentId}/identities view).
// Everything here is computed at query time from the identity stream
// — never stored on, or sealed into, the agent. The view is covered
// by the TL's response signature, not by any seal.
type LinkedIdentityView struct {
	IdentityID     string `json:"identityId"`
	Kind           string `json:"kind"`
	Value          string `json:"value"`
	IdentityStatus string `json:"identityStatus"` // VERIFIED | REVOKED — reflects the identity stream NOW

	// Keys quotes the identity's CURRENT proven key set verbatim
	// from the latest sealed proof event (IDENTITY_VERIFIED /
	// IDENTITY_UPDATED) — the verification methods exactly as sealed,
	// member-for-member (§5.6.3 "computed views carry the keys"): a
	// verifier checks operator signatures from the badge alone, no
	// audit walk. Methods only — the signedProof evidence lives in
	// the seal at KeysLogID, one hop away. Omitted when the identity
	// is REVOKED: the keys are no longer attested (the entry itself
	// stays visible with identityStatus REVOKED while the link and
	// agent are live).
	Keys []json.RawMessage `json:"keys,omitempty"`

	// KeysLogID points at the sealed proof event Keys is quoted from
	// — fetch it for the signedProofs / offline evidence.
	KeysLogID string `json:"keysLogId,omitempty"`

	// LinkedAt is the producer timestamp of the sealed
	// IDENTITY_LINKED event that bound this agent.
	LinkedAt string `json:"linkedAt,omitempty"`

	// LinkLogID points at the sealed IDENTITY_LINKED entry on the
	// identity stream — fetch it for link evidence.
	LinkLogID string `json:"linkLogId,omitempty"`
}

// LinkedAgentView is one entry of the reverse join — the agents an
// identity currently links to (GET /v1/identities/{id}/agents).
type LinkedAgentView struct {
	AnsID    string `json:"ansId"`
	LinkedAt string `json:"linkedAt,omitempty"`
	// AgentStatus is the linked agent's own computed badge status —
	// a link is *effective* only while both ends are live, and this
	// field is how a reader checks the agent end in the same hop.
	AgentStatus BadgeStatus `json:"agentStatus,omitempty"`
}

// IdentityBadgeService serves the identity read surface: the identity
// badge, audit chain, and the computed joins in both directions. It
// reuses the agent badge's TransparencyLog response shape — audits
// stay audits, one format.
type IdentityBadgeService struct {
	log   *LogService
	badge *BadgeService
}

// NewIdentityBadgeService constructs an IdentityBadgeService. The
// BadgeService is used for the reverse join's per-agent status (a
// link is effective only while both ends are live).
func NewIdentityBadgeService(log *LogService, badge *BadgeService) *IdentityBadgeService {
	return &IdentityBadgeService{log: log, badge: badge}
}

// Get returns the TransparencyLog view of an identity's most recent
// event — the identity badge — plus the computed current attestation
// (§5.6.3 "latest entry ≠ current attestation"): the latest entry may
// be a link/unlink/revocation carrying no key material, so the badge
// quotes the current proven key set verbatim from the latest sealed
// proof event, with keysLogId pointing at that seal. Keys are omitted
// when the identity is REVOKED — no longer attested.
func (s *IdentityBadgeService) Get(ctx context.Context, identityID string) (*TransparencyLog, error) {
	rec, err := s.log.LatestEventByIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}
	tl, err := s.buildTransparencyLog(ctx, rec)
	if err != nil {
		return nil, err
	}
	status, err := s.identityStatus(ctx, identityID, rec.EventType)
	if err != nil {
		return nil, err
	}
	tl.Status = status
	if tl.Status == BadgeVerified {
		proof, err := s.log.LatestProofByIdentity(ctx, identityID)
		if err != nil {
			return nil, err
		}
		_, _, keys := proofSummary(proof.RawEvent)
		tl.Keys = keys
		tl.KeysLogID = proof.LogID
	}
	return tl, nil
}

// identityStatus derives the identity's read-time status with the
// TERMINAL rule: REVOKED iff ANY IDENTITY_REVOKED exists on the
// stream, not merely when it is the tail. The RA's seal spans a
// network round trip, so a racing operation's event can land after
// the revocation leaf — a late leaf must never flip a revoked
// identity's public answer back to VERIFIED. Sound because no
// legitimate flow appends to a revoked identity's stream (every RA
// write op gates on the REVOKED row; re-registration mints a new
// identityId), so the fast path (latest event already REVOKED)
// covers the common case and the EXISTS query the race.
func (s *IdentityBadgeService) identityStatus(ctx context.Context, identityID, latestEventType string) (BadgeStatus, error) {
	if identityStatusFromEventType(latestEventType) == BadgeIdentityRevoked {
		return BadgeIdentityRevoked, nil
	}
	revoked, err := s.log.IdentityRevoked(ctx, identityID)
	if err != nil {
		return "", err
	}
	if revoked {
		return BadgeIdentityRevoked, nil
	}
	return BadgeVerified, nil
}

// Audit returns the identity's full event chain, paginated, in the
// exact same audit envelope as the agent audit — no bespoke format.
func (s *IdentityBadgeService) Audit(ctx context.Context, identityID string, limit, offset int) ([]*TransparencyLog, error) {
	recs, err := s.log.EventsByIdentity(ctx, identityID, limit, offset)
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

// buildTransparencyLog assembles the response for one identity-stream
// record: parsed envelope wrapper + Merkle proof + computed status.
func (s *IdentityBadgeService) buildTransparencyLog(ctx context.Context, rec *sqlitetl.EventRecord) (*TransparencyLog, error) {
	wrapper, err := parseEnvelopeWrapper(rec.RawEvent)
	if err != nil {
		return nil, err
	}
	proof, perr := BuildMerkleProof(ctx, s.log.log, rec)
	if perr != nil && !errors.Is(perr, ErrProofLeafNotCovered) {
		proof = nil
	}
	schema := rec.SchemaVersion
	if schema == "" {
		schema = wrapper.SchemaVersion
	}
	return &TransparencyLog{
		MerkleProof:   proof,
		Payload:       wrapper.Payload,
		SchemaVersion: schema,
		Signature:     wrapper.Signature,
		Status:        identityStatusFromEventType(rec.EventType),
	}, nil
}

// identityStatusFromEventType derives the identity's read-time
// status from its latest event. REVOKED is terminal — the RA seals
// no identity events after a revocation — so "latest event is
// IDENTITY_REVOKED" is exactly "the identity is revoked", the same
// latest-event discipline the agent badge uses for AGENT_REVOKED.
func identityStatusFromEventType(eventType string) BadgeStatus {
	if eventType == string(sqlitetlIdentityRevoked) {
		return BadgeIdentityRevoked
	}
	return BadgeVerified
}

// sqlitetlIdentityRevoked mirrors identityevent.TypeIdentityRevoked
// without importing the event package for one string.
const sqlitetlIdentityRevoked = "IDENTITY_REVOKED"

// LinkedIdentitiesForAgent computes the identities[] join for an
// agent badge under the §5.6.3 visibility predicate — link LINKED ∧
// agent live — given the agent's already-computed badge status (the
// caller has it; recomputing here would double the Merkle work).
// A terminal agent's view is empty: its links are no longer visible.
// Revoked IDENTITIES, by contrast, stay in the list with
// identityStatus REVOKED and no keys — a verifier must see that the
// who behind a still-linked agent was revoked, not have the fact
// silently vanish (the attestation rule withholds only the keys).
func (s *IdentityBadgeService) LinkedIdentitiesForAgent(ctx context.Context, ansID string, agentStatus BadgeStatus) ([]*LinkedIdentityView, error) {
	if !agentLive(agentStatus) {
		return []*LinkedIdentityView{}, nil
	}
	states, err := s.log.LinkStatesByAgent(ctx, ansID)
	if err != nil {
		return nil, err
	}
	out := make([]*LinkedIdentityView, 0, len(states))
	for _, st := range states {
		if !st.Linked() {
			continue
		}
		view, err := s.linkedIdentityView(ctx, st)
		if err != nil {
			return nil, err
		}
		out = append(out, view)
	}
	return out, nil
}

// agentLive is the agent conjunct of the §5.6.3 visibility predicate:
// ACTIVE and DEPRECATED are live (a deprecated agent still serves
// during migration); WARNING is live too — it is the ACTIVE overlay
// for an expiring attested cert, not a lifecycle exit. REVOKED,
// EXPIRED, and UNKNOWN are not live.
func agentLive(status BadgeStatus) bool {
	switch status {
	case BadgeActive, BadgeDeprecated, BadgeWarning:
		return true
	default:
		return false
	}
}

// linkedIdentityView decorates one live link with the identity's
// current state: latest event (status), latest proof (kind/value +
// the verbatim keys[] + keysLogId — withheld when REVOKED), and the
// sealed link event (linkedAt + linkLogId).
func (s *IdentityBadgeService) linkedIdentityView(ctx context.Context, st *sqlitetl.LinkState) (*LinkedIdentityView, error) {
	view := &LinkedIdentityView{IdentityID: st.IdentityID}

	linkRec, err := s.log.EventByLeafIndex(ctx, st.LeafIndex)
	if err != nil {
		return nil, err
	}
	view.LinkLogID = linkRec.LogID
	view.LinkedAt = innerTimestamp(linkRec.RawEvent)

	latest, err := s.log.LatestEventByIdentity(ctx, st.IdentityID)
	if err != nil {
		return nil, err
	}
	status, err := s.identityStatus(ctx, st.IdentityID, latest.EventType)
	if err != nil {
		return nil, err
	}
	view.IdentityStatus = string(status)

	proof, err := s.log.LatestProofByIdentity(ctx, st.IdentityID)
	if err != nil {
		return nil, err
	}
	kind, value, keys := proofSummary(proof.RawEvent)
	view.Kind = kind
	view.Value = value
	if view.IdentityStatus == string(BadgeVerified) {
		view.Keys = keys
		view.KeysLogID = proof.LogID
	}
	return view, nil
}

// LinkedAgentsForIdentity computes the reverse join: the agents this
// identity currently links to, each with its own computed badge
// status so a reader checks both ends of the link in one response.
func (s *IdentityBadgeService) LinkedAgentsForIdentity(ctx context.Context, identityID string) ([]*LinkedAgentView, error) {
	// 404 on an unknown identity (parity with the badge route) —
	// otherwise every random id would return an empty 200 list.
	if _, err := s.log.LatestEventByIdentity(ctx, identityID); err != nil {
		return nil, err
	}
	states, err := s.log.LinkStatesByIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}
	out := make([]*LinkedAgentView, 0, len(states))
	for _, st := range states {
		if !st.Linked() {
			continue
		}
		// Visibility predicate (§5.6.3): only live agents appear in
		// any "current" view — a terminal agent's link history stays
		// recoverable from the audit chain. Not-found is a liveness
		// answer (the agent lane still seals via the async outbox, so
		// a just-activated agent's leaf can lag); any OTHER failure
		// propagates — join failure is explicit, never silent.
		//
		// StatusOf (not badge.Get): this view carries only
		// ansId/linkedAt/agentStatus, so building a Merkle proof per
		// agent here would be discarded work. Pagination stays at the
		// handler after this walk because the agent-liveness filter
		// needs each agent's latest event (not in the link index), so
		// a SQL LIMIT couldn't preserve an accurate total or full
		// pages; the per-agent cost is now one indexed read, not a
		// checkpoint read + tile walk.
		agentStatus, err := s.badge.StatusOf(ctx, st.AnsID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !agentLive(agentStatus) {
			continue
		}
		view := &LinkedAgentView{AnsID: st.AnsID, AgentStatus: agentStatus}
		if linkRec, err := s.log.EventByLeafIndex(ctx, st.LeafIndex); err == nil {
			view.LinkedAt = innerTimestamp(linkRec.RawEvent)
		}
		out = append(out, view)
	}
	return out, nil
}

// LinkHistoryForAgent returns the link/unlink events that ever named
// this agent, in the standard audit envelope — the
// /v1/agents/{agentId}/identities/history view. No bespoke format:
// each record is the same TransparencyLog shape as every audit entry,
// filtered through the agent index.
func (s *IdentityBadgeService) LinkHistoryForAgent(ctx context.Context, ansID string, limit, offset int) ([]*TransparencyLog, error) {
	recs, err := s.log.LinkEventsByAgent(ctx, ansID, limit, offset)
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

// innerTimestamp drills the producer timestamp out of a stored
// envelope without binding to a concrete inner-event type.
func innerTimestamp(rawEvent string) string {
	var w struct {
		Payload struct {
			Producer struct {
				Event struct {
					Timestamp string `json:"timestamp"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(rawEvent), &w); err != nil {
		return ""
	}
	return w.Payload.Producer.Event.Timestamp
}

// proofSummary drills kind, value, and the proven verification
// methods out of a stored proof event (IDENTITY_VERIFIED /
// IDENTITY_UPDATED). The methods are returned as the RAW sealed
// bytes, untouched — the computed views quote sealed material
// verbatim, never re-encode it (the seal-verbatim rule extends to
// the quote). The signedProof member stays behind in the seal.
func proofSummary(rawEvent string) (string, string, []json.RawMessage) {
	var w struct {
		Payload struct {
			Producer struct {
				Event struct {
					Kind  string `json:"kind"`
					Value string `json:"value"`
					Keys  []struct {
						VerificationMethod json.RawMessage `json:"verificationMethod"`
					} `json:"keys"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(rawEvent), &w); err != nil {
		return "", "", nil
	}
	ev := w.Payload.Producer.Event
	methods := make([]json.RawMessage, 0, len(ev.Keys))
	for _, k := range ev.Keys {
		if len(k.VerificationMethod) > 0 {
			methods = append(methods, k.VerificationMethod)
		}
	}
	return ev.Kind, ev.Value, methods
}
