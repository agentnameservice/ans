package port

import (
	"context"

	"github.com/agentnameservice/ans/internal/domain"
)

// EventHandler processes a single domain event. A non-nil error causes
// the bus implementation to apply its retry policy (or log and discard,
// depending on the adapter).
type EventHandler func(ctx context.Context, event domain.Event) error

// EventBus delivers domain events from producers (services) to consumers
// (other services, TL client, outbound integrations). Subscriptions are
// registered at startup; Publish is called by aggregates after state
// transitions.
//
// Semantics:
//   - Publish is at-least-once.
//   - Handlers for the same event type are called in registration order.
//   - The bus must NOT panic on handler errors; it logs and continues.
type EventBus interface {
	// Publish delivers the event to all handlers registered for its type.
	// Returns an error only if the bus itself is broken (e.g., shut down);
	// per-handler errors are surfaced through the adapter's logging.
	Publish(ctx context.Context, event domain.Event) error

	// Subscribe registers a handler for a specific event type.
	// Subscriptions made after Close are rejected.
	Subscribe(eventType domain.EventType, handler EventHandler) error
}
