package service

import (
	"context"
	"encoding/json"
	"errors"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
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

	// ProvenKeyIDs names the identity's current proven key set — the
	// verification-method ids from the latest proof event
	// (post-rotation). The full verbatim verification methods live in
	// the sealed event; thumbprints are compute-at-read conveniences
	// derivable from that sealed source.
	ProvenKeyIDs []string `json:"provenKeyIds,omitempty"`

	// LinkedAt is the producer timestamp of the sealed
	// IDENTITY_LINKED event that bound this agent.
	LinkedAt string `json:"linkedAt,omitempty"`

	// LinkLogID points at the sealed IDENTITY_LINKED entry on the
	// identity stream — fetch it for link evidence.
	LinkLogID string `json:"linkLogId,omitempty"`

	// IdentityLogID points at the latest identity-stream entry —
	// fetch it (or the audit) for the identity evidence/history.
	IdentityLogID string `json:"identityLogId,omitempty"`
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
// event — the identity badge.
func (s *IdentityBadgeService) Get(ctx context.Context, identityID string) (*TransparencyLog, error) {
	rec, err := s.log.LatestEventByIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}
	return s.buildTransparencyLog(ctx, rec)
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
// agent badge: every identity whose latest link/unlink fact naming
// this agent is LINKED, decorated with that identity's current
// stream state. Revoked identities stay in the list with
// identityStatus REVOKED — the rotation/revocation visibility on
// every linked badge is the point of the read-time join.
func (s *IdentityBadgeService) LinkedIdentitiesForAgent(ctx context.Context, ansID string) ([]*LinkedIdentityView, error) {
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

// linkedIdentityView decorates one live link with the identity's
// current state: latest event (status + identityLogId), latest proof
// (kind/value/thumbprints), and the sealed link event (linkedAt +
// linkLogId).
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
	view.IdentityLogID = latest.LogID
	view.IdentityStatus = string(identityStatusFromEventType(latest.EventType))

	proof, err := s.log.LatestProofByIdentity(ctx, st.IdentityID)
	if err != nil {
		return nil, err
	}
	kind, value, keyIDs := proofSummary(proof.RawEvent)
	view.Kind = kind
	view.Value = value
	view.ProvenKeyIDs = keyIDs
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
		view := &LinkedAgentView{AnsID: st.AnsID}
		if linkRec, err := s.log.EventByLeafIndex(ctx, st.LeafIndex); err == nil {
			view.LinkedAt = innerTimestamp(linkRec.RawEvent)
		}
		if agentTL, err := s.badge.Get(ctx, st.AnsID); err == nil {
			view.AgentStatus = agentTL.Status
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

// proofSummary drills kind, value, and the proven verification-method
// ids out of a stored proof event (IDENTITY_VERIFIED /
// IDENTITY_UPDATED). The ids come from the sealed verbatim
// verification methods.
func proofSummary(rawEvent string) (string, string, []string) {
	var w struct {
		Payload struct {
			Producer struct {
				Event struct {
					Kind  string `json:"kind"`
					Value string `json:"value"`
					Keys  []struct {
						VerificationMethod struct {
							ID string `json:"id"`
						} `json:"verificationMethod"`
					} `json:"keys"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(rawEvent), &w); err != nil {
		return "", "", nil
	}
	ev := w.Payload.Producer.Event
	ids := make([]string, 0, len(ev.Keys))
	for _, k := range ev.Keys {
		if k.VerificationMethod.ID != "" {
			ids = append(ids, k.VerificationMethod.ID)
		}
	}
	return ev.Kind, ev.Value, ids
}
