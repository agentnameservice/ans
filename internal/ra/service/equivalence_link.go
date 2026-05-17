// Package service: equivalence-link emission.
//
// Implements the RA-side handler for the EQUIVALENCE_LINK event type
// schema in internal/tl/event. An operator running multiple agents
// under different anchor profiles (FQDN + LEI, FQDN + did:web, etc.)
// asserts that two of those registrations refer to the same operator
// by emitting one link event into the Transparency Log.
//
// Authorization model. The simplest defensible auth shape: the same
// authenticated operator must own both registrations on this RA. The
// caller's identity arrives through the existing ownership middleware
// (which gates the path-{agentId} primary registration), and this
// service performs a second ownership check on the linked agent. A
// future amendment may admit federated link events that span two RAs
// with two distinct producer signatures, in which case the Envelope
// schema grows a cosigner block; for now, both registrations live on
// this RA and the RA's existing producer key signs the single envelope.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/tl/event"
)

// LinkEquivalenceInput collects what the handler needs to pass into
// the service layer. Both agent IDs are RA-issued UUIDs; rationale is
// the operator's plain-language reason a downstream verifier will see
// in the TL-sealed event.
type LinkEquivalenceInput struct {
	OwnerID        string // authenticated operator (from ownership middleware)
	PrimaryAgentID string // {agentId} from the request path
	LinkedAgentID  string // body field linkedAnsId
	Rationale      string // optional free-text justification
}

// LinkEquivalenceResult is what the handler returns to the caller.
type LinkEquivalenceResult struct {
	PrimaryAgentID    string
	PrimaryAnsName    string
	LinkedAgentID     string
	LinkedAnsName     string
	LinkedAnchorType  string
	LinkedAnchorValue string
	Rationale         string
	Timestamp         string
}

// LinkEquivalence emits one EQUIVALENCE_LINK event linking two
// registrations the caller owns on this RA. Returns 403-shaped
// validation errors on auth failures, 404-shaped on missing linked
// agent, 422 on a self-link attempt or non-ACTIVE linked agent.
func (s *RegistrationService) LinkEquivalence(
	ctx context.Context, in LinkEquivalenceInput,
) (*LinkEquivalenceResult, error) {
	if in.OwnerID == "" {
		return nil, domain.NewValidationError("MISSING_OWNER", "owner id is required")
	}
	if in.PrimaryAgentID == "" {
		return nil, domain.NewValidationError("MISSING_PRIMARY_AGENT_ID", "primary agentId is required")
	}
	if in.LinkedAgentID == "" {
		return nil, domain.NewValidationError("MISSING_LINKED_AGENT_ID", "linkedAnsId is required")
	}
	if in.PrimaryAgentID == in.LinkedAgentID {
		return nil, domain.NewValidationError(
			"EQUIVALENCE_SELF_LINK",
			"primary and linked agents must differ; cannot link a registration to itself",
		)
	}

	// The ownership middleware has already loaded primary by path id,
	// confirmed primary.OwnerID matches the caller, and would have
	// returned 403 before we got here. We re-fetch primary anyway
	// because the service path is also reachable from internal callers
	// that bypass the middleware (admin tooling, future federation).
	primary, err := s.agents.FindByAgentID(ctx, in.PrimaryAgentID)
	if err != nil {
		return nil, err
	}
	if primary == nil {
		return nil, domain.NewValidationError(
			"AGENT_NOT_FOUND",
			fmt.Sprintf("primary agent %s not found", in.PrimaryAgentID),
		)
	}
	if primary.OwnerID != in.OwnerID {
		return nil, domain.NewValidationError(
			"NOT_AUTHORIZED",
			"caller does not own the primary registration",
		)
	}

	linked, err := s.agents.FindByAgentID(ctx, in.LinkedAgentID)
	if err != nil {
		return nil, err
	}
	if linked == nil {
		return nil, domain.NewValidationError(
			"LINKED_AGENT_NOT_FOUND",
			fmt.Sprintf("linked agent %s not found on this RA", in.LinkedAgentID),
		)
	}
	if linked.OwnerID != in.OwnerID {
		// Returning a not-found-shaped error preserves the existence-
		// hiding posture the read endpoints use; the caller cannot
		// probe for agents owned by other operators.
		return nil, domain.NewValidationError(
			"LINKED_AGENT_NOT_FOUND",
			fmt.Sprintf("linked agent %s not found on this RA", in.LinkedAgentID),
		)
	}
	if linked.Status != domain.StatusActive {
		return nil, domain.NewValidationError(
			"LINKED_AGENT_NOT_ACTIVE",
			fmt.Sprintf("linked agent %s is not ACTIVE (status=%s)", in.LinkedAgentID, linked.Status),
		)
	}

	now := s.now()
	inner := s.equivalenceInnerEvent(primary, linked, in.Rationale, now)
	if err := inner.Validate(); err != nil {
		// Belt-and-suspenders: the inner-event validator is the schema
		// gate. Surfacing the failure here keeps the misshapen event
		// off the outbox.
		return nil, domain.NewValidationError("INVALID_EVENT", err.Error())
	}

	if err := s.enqueueTLEvent(ctx, string(event.TypeEquivalenceLink), primary, inner, now); err != nil {
		return nil, fmt.Errorf("enqueue equivalence link: %w", err)
	}

	return &LinkEquivalenceResult{
		PrimaryAgentID:    primary.AgentID,
		PrimaryAnsName:    primary.AnsName.String(),
		LinkedAgentID:     linked.AgentID,
		LinkedAnsName:     linked.AnsName.String(),
		LinkedAnchorType:  anchorTypeFromRegistration(linked),
		LinkedAnchorValue: anchorValueFromRegistration(linked),
		Rationale:         in.Rationale,
		Timestamp:         now.UTC().Format(time.RFC3339),
	}, nil
}

// equivalenceInnerEvent builds the TL inner event for a link. Unlike
// baseInnerEvent, this builder leaves Agent and Attestations nil and
// populates Equivalence per the EQUIVALENCE_LINK schema. The emitted
// shape passes internal/tl/event.Validate's link-event branch.
func (s *RegistrationService) equivalenceInnerEvent(
	primary, linked *domain.AgentRegistration, rationale string, now time.Time,
) *event.Event {
	raID := ""
	if s.signer != nil {
		raID = s.signer.RaID
	}
	return &event.Event{
		AnsID:     primary.AgentID,
		AnsName:   primary.AnsName.String(),
		EventType: event.TypeEquivalenceLink,
		// No Agent block: the linked event documents an existing
		// registration relationship, not an agent's own facts.
		// No Attestations: domain-control proofs apply per
		// registration, not per link.
		Equivalence: &event.EquivalenceLink{
			LinkedAnsID:            linked.AgentID,
			LinkedAnsName:          linked.AnsName.String(),
			LinkedAnchorType:       anchorTypeFromRegistration(linked),
			LinkedAnchorResolvedID: anchorValueFromRegistration(linked),
			Rationale:              rationale,
		},
		RaID:      raID,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		Timestamp: now.UTC().Format(time.RFC3339),
	}
}

// anchorTypeFromRegistration recovers the anchor profile id that
// produced this registration. Plan G persists AnchorClaim on the
// aggregate when present; pre-Plan-G rows surface as nil and
// register implicitly under FQDN, so the absence is treated as fqdn.
func anchorTypeFromRegistration(reg *domain.AgentRegistration) string {
	if reg.AnchorClaim != nil && reg.AnchorClaim.AnchorType != "" {
		return string(reg.AnchorClaim.AnchorType)
	}
	return "fqdn"
}

// anchorValueFromRegistration recovers the canonical anchor input.
// For FQDN the value is the agent host; for did:* / lei the value is
// the resolved id stored on the AnchorClaim aggregate.
func anchorValueFromRegistration(reg *domain.AgentRegistration) string {
	if reg.AnchorClaim != nil && reg.AnchorClaim.ResolvedID != "" {
		return reg.AnchorClaim.ResolvedID
	}
	return reg.AgentHost
}

// now returns the service's current time. Wraps the tested clock
// accessor so equivalenceInnerEvent stays a pure function.
func (s *RegistrationService) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}
