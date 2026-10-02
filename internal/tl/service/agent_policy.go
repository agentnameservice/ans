package service

import (
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/event"
)

// Agent events project onto the shared registration state machine. Renewal is
// the one non-transition: it replaces evidence while the agent remains ACTIVE.
func agentEventTransitionAllowed(previous, incoming string) bool {
	var current domain.RegistrationStatus
	switch previous {
	case string(event.TypeAgentRegistered), string(event.TypeAgentRenewed):
		current = domain.StatusActive
	case string(event.TypeAgentDeprecated):
		current = domain.StatusDeprecated
	default:
		return false
	}
	switch incoming {
	case string(event.TypeAgentRenewed):
		return current == domain.StatusActive
	case string(event.TypeAgentDeprecated):
		return current.CanTransitionTo(domain.StatusDeprecated)
	case string(event.TypeAgentRevoked):
		return current.CanTransitionTo(domain.StatusRevoked)
	default:
		return false
	}
}
