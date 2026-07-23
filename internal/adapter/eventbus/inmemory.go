// Package eventbus provides EventBus implementations.
package eventbus

import (
	"context"
	"errors"
	"sync"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// ErrClosed indicates the bus has been shut down.
var ErrClosed = errors.New("eventbus: closed")

// InMemoryBus is an in-process event bus. Handlers registered for an
// event type run synchronously in the Publish caller's goroutine in
// registration order. Handler errors are logged and do not abort other
// handlers; use async outbox patterns for durability across processes.
//
// This adapter suits single-instance deployments (local dev, small
// single-binary production setups). For multi-instance clustering,
// swap in a NATS / Kafka / RabbitMQ adapter implementing port.EventBus.
type InMemoryBus struct {
	mu       sync.RWMutex
	handlers map[domain.EventType][]port.EventHandler
	closed   bool
	logger   zerolog.Logger
}

// NewInMemoryBus constructs a bus with the given logger.
func NewInMemoryBus(logger zerolog.Logger) *InMemoryBus {
	return &InMemoryBus{
		handlers: make(map[domain.EventType][]port.EventHandler),
		logger:   logger,
	}
}

// Publish delivers the event to all handlers registered for its type.
func (b *InMemoryBus) Publish(ctx context.Context, event domain.Event) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return ErrClosed
	}
	// Copy the handler slice so long-running handlers don't block
	// subsequent Subscribe() calls.
	handlers := append([]port.EventHandler(nil), b.handlers[event.Type()]...)
	b.mu.RUnlock()

	for _, h := range handlers {
		if err := h(ctx, event); err != nil {
			b.logger.Error().
				Err(err).
				Str("event_type", string(event.Type())).
				Str("agent_id", event.AgentID()).
				Msg("eventbus handler failed")
		}
	}
	return nil
}

// Subscribe registers a handler for the given event type.
func (b *InMemoryBus) Subscribe(eventType domain.EventType, handler port.EventHandler) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	b.handlers[eventType] = append(b.handlers[eventType], handler)
	return nil
}

// Close prevents further Publish or Subscribe calls.
func (b *InMemoryBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}
