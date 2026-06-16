package service_test

import (
	"context"
	"sync"
)

// recordingAgentSealer is a test AgentEventSealer for the agent activation
// seal-before-success path. By default it succeeds and records each sealed
// event so a test can assert what verify-dns submitted to the TL (the
// AGENT_REGISTERED event no longer rides the outbox). Set failErr to drive
// the fail-closed path (activation must then refuse to report ACTIVE).
type recordingAgentSealer struct {
	mu      sync.Mutex
	events  []sealedAgentEvent
	failErr error
}

type sealedAgentEvent struct {
	SchemaVersion  string
	InnerCanonical []byte
	ProducerSig    string
}

func (r *recordingAgentSealer) SealAgentEvent(_ context.Context, schemaVersion string, innerCanonical []byte, producerSig string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failErr != nil {
		return r.failErr
	}
	r.events = append(r.events, sealedAgentEvent{
		SchemaVersion:  schemaVersion,
		InnerCanonical: append([]byte(nil), innerCanonical...),
		ProducerSig:    producerSig,
	})
	return nil
}

// sealed returns a copy of the events sealed so far.
func (r *recordingAgentSealer) sealed() []sealedAgentEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sealedAgentEvent(nil), r.events...)
}
