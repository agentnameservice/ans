package eventbus

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// silentLogger discards all log output so tests aren't noisy.
func silentLogger() zerolog.Logger { return zerolog.New(io.Discard) }

// stubEvent is a minimal Event implementation for tests.
type stubEvent struct {
	t  domain.EventType
	id string
}

func (e stubEvent) Type() domain.EventType { return e.t }
func (e stubEvent) AgentID() string        { return e.id }
func (e stubEvent) OccurredAt() time.Time  { return time.Time{} }

func TestInMemoryBus_DeliversToRegisteredHandlers(t *testing.T) {
	bus := NewInMemoryBus(silentLogger())
	var got []string
	handler := func(_ context.Context, e domain.Event) error {
		got = append(got, e.AgentID())
		return nil
	}

	if err := bus.Subscribe(domain.EventType("X"), handler); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := bus.Publish(context.Background(), stubEvent{t: "X", id: "a1"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(got) != 1 || got[0] != "a1" {
		t.Errorf("handler did not receive event: got %v", got)
	}
}

func TestInMemoryBus_PreservesRegistrationOrder(t *testing.T) {
	bus := NewInMemoryBus(silentLogger())
	var seen []string
	for _, tag := range []string{"first", "second", "third"} {
		_ = bus.Subscribe("EV", func(_ context.Context, _ domain.Event) error {
			seen = append(seen, tag)
			return nil
		})
	}
	_ = bus.Publish(context.Background(), stubEvent{t: "EV", id: "x"})
	if len(seen) != 3 || seen[0] != "first" || seen[2] != "third" {
		t.Errorf("order not preserved: %v", seen)
	}
}

func TestInMemoryBus_HandlerErrorDoesNotAbortOthers(t *testing.T) {
	bus := NewInMemoryBus(silentLogger())
	count := 0
	_ = bus.Subscribe("EV", func(_ context.Context, _ domain.Event) error {
		return errors.New("boom")
	})
	_ = bus.Subscribe("EV", func(_ context.Context, _ domain.Event) error {
		count++
		return nil
	})
	if err := bus.Publish(context.Background(), stubEvent{t: "EV", id: "a"}); err != nil {
		t.Errorf("publish: want nil, got %v", err)
	}
	if count != 1 {
		t.Errorf("second handler not called after first's error")
	}
}

func TestInMemoryBus_NoHandlersIsNoop(t *testing.T) {
	bus := NewInMemoryBus(silentLogger())
	if err := bus.Publish(context.Background(), stubEvent{t: "unknown", id: "a"}); err != nil {
		t.Errorf("publish w/ no handlers: want nil, got %v", err)
	}
}

func TestInMemoryBus_ClosePreventsFurtherPublishAndSubscribe(t *testing.T) {
	bus := NewInMemoryBus(silentLogger())
	bus.Close()

	if err := bus.Publish(context.Background(), stubEvent{t: "EV"}); !errors.Is(err, ErrClosed) {
		t.Errorf("Publish after Close: want ErrClosed, got %v", err)
	}
	err := bus.Subscribe("EV", func(context.Context, domain.Event) error { return nil })
	if !errors.Is(err, ErrClosed) {
		t.Errorf("Subscribe after Close: want ErrClosed, got %v", err)
	}
}

// Interface assertion: ensure *InMemoryBus satisfies port.EventBus.
var _ port.EventBus = (*InMemoryBus)(nil)
