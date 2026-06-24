package handler_test

import (
	"context"
	"encoding/json"
	"sync"
)

// recordingAgentSealer is a test service.AgentEventSealer for the agent
// activation seal-before-success path. By default it succeeds and records
// each sealed event so a test can assert what verify-dns submitted to the
// TL — the AGENT_REGISTERED event no longer rides the outbox. Set failErr
// to exercise the fail-closed path (activation must then refuse to report
// ACTIVE and the agent stays PENDING_DNS).
type recordingAgentSealer struct {
	mu      sync.Mutex
	events  []sealedAgentEvent
	failErr error
}

type sealedAgentEvent struct {
	SchemaVersion  string
	EventType      string
	InnerCanonical []byte
}

func (r *recordingAgentSealer) SealAgentEvent(_ context.Context, schemaVersion string, innerCanonical []byte, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failErr != nil {
		return r.failErr
	}
	var meta struct {
		EventType string `json:"eventType"`
	}
	_ = json.Unmarshal(innerCanonical, &meta)
	r.events = append(r.events, sealedAgentEvent{
		SchemaVersion:  schemaVersion,
		EventType:      meta.EventType,
		InnerCanonical: append([]byte(nil), innerCanonical...),
	})
	return nil
}

// sealed returns a copy of the events sealed so far.
func (r *recordingAgentSealer) sealed() []sealedAgentEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sealedAgentEvent(nil), r.events...)
}

// sealedTypes returns the eventType of each sealed event, in order.
func (r *recordingAgentSealer) sealedTypes() []string {
	sealed := r.sealed()
	out := make([]string, 0, len(sealed))
	for _, e := range sealed {
		out = append(out, e.EventType)
	}
	return out
}
