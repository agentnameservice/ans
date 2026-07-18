package service_test

import (
	"context"
	"fmt"
	"sync"
)

// recordingAgentSealer is a test AgentEventSealer for the agent activation
// seal-before-success path. By default it succeeds, records each sealed
// event so a test can assert what verify-dns submitted to the TL (the
// AGENT_REGISTERED event no longer rides the outbox worker), and returns a
// deterministic per-event logId ("test-log-1", "test-log-2", …) mirroring
// the TL ack — the activation persists it on the pre-delivered feed row.
// Set failErr to drive the fail-closed path (activation must then refuse
// to report ACTIVE).
type recordingAgentSealer struct {
	mu      sync.Mutex
	events  []sealedAgentEvent
	failErr error
	// hook, when set, runs inside the seal round trip (after the TL
	// "ack", before the caller's commit phase) — the window a rival
	// writer can land in. Race tests use it to commit conflicting store
	// state mid-seal, mirroring the identity lane's recordingSealer.hook.
	hook func()
}

type sealedAgentEvent struct {
	SchemaVersion  string
	InnerCanonical []byte
	ProducerSig    string
	LogID          string
}

func (r *recordingAgentSealer) SealAgentEvent(_ context.Context, schemaVersion string, innerCanonical []byte, producerSig string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failErr != nil {
		return "", r.failErr
	}
	logID := fmt.Sprintf("test-log-%d", len(r.events)+1)
	r.events = append(r.events, sealedAgentEvent{
		SchemaVersion:  schemaVersion,
		InnerCanonical: append([]byte(nil), innerCanonical...),
		ProducerSig:    producerSig,
		LogID:          logID,
	})
	if r.hook != nil {
		r.hook()
	}
	return logID, nil
}

// sealed returns a copy of the events sealed so far.
func (r *recordingAgentSealer) sealed() []sealedAgentEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sealedAgentEvent(nil), r.events...)
}
