package event_test

// Coverage for the trivial Envelope getters. Each one has a
// `if inner != nil` early-return that pre-coverage tests didn't
// reach because they always passed populated envelopes.

import (
	"testing"

	"github.com/godaddy/ans/internal/tl/event"
)

// nilInnerEnvelope returns an Envelope whose Payload is nil — the
// shape produced by an empty/uninitialized struct or a JSON unmarshal
// of a body without a `payload` field.
func nilInnerEnvelope() *event.Envelope {
	return &event.Envelope{}
}

// fullEnvelope returns an Envelope with a populated inner event so
// the happy-path arms are exercised alongside the nil-fallback arms
// — pin each getter's both branches in one test file.
func fullEnvelope() *event.Envelope {
	inner := &event.Event{
		AnsID:     "10000000-0000-4000-8000-000000000001",
		AnsName:   "ans://v1.0.0.agent.example.com",
		EventType: event.TypeAgentRegistered,
		Agent: &event.Agent{
			Host:    "agent.example.com",
			Name:    "a",
			Version: "1.0.0",
		},
		RaID:      "ra-test",
		IssuedAt:  "2026-04-17T00:00:00Z",
		Timestamp: "2026-04-17T00:00:00Z",
		ExpiresAt: "2027-04-17T00:00:00Z",
	}
	return event.BuildEnvelope("log-id", inner, "kid-1", "sig")
}

func TestEnvelope_AnsName_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().AnsName(); got != "" {
		t.Errorf("nil-inner AnsName: got %q want empty", got)
	}
	if got := fullEnvelope().AnsName(); got != "ans://v1.0.0.agent.example.com" {
		t.Errorf("full AnsName: got %q", got)
	}
}

func TestEnvelope_AgentFQDN_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().AgentFQDN(); got != "" {
		t.Errorf("nil-inner AgentFQDN: got %q want empty", got)
	}
	if got := fullEnvelope().AgentFQDN(); got != "agent.example.com" {
		t.Errorf("full AgentFQDN: got %q", got)
	}
}

func TestEnvelope_EventType_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().EventType(); got != "" {
		t.Errorf("nil-inner EventType: got %q want empty", got)
	}
	if got := fullEnvelope().EventType(); got != "AGENT_REGISTERED" {
		t.Errorf("full EventType: got %q", got)
	}
}

func TestEnvelope_Timestamp_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().Timestamp(); got != "" {
		t.Errorf("nil-inner Timestamp: got %q want empty", got)
	}
	if got := fullEnvelope().Timestamp(); got != "2026-04-17T00:00:00Z" {
		t.Errorf("full Timestamp: got %q", got)
	}
}

func TestEnvelope_ExpiresAt_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().ExpiresAt(); got != "" {
		t.Errorf("nil-inner ExpiresAt: got %q want empty", got)
	}
	if got := fullEnvelope().ExpiresAt(); got != "2027-04-17T00:00:00Z" {
		t.Errorf("full ExpiresAt: got %q", got)
	}
}

// AgentID is exercised similarly; pin both arms. Keeps the audit
// shape's read-side getters fully covered.
func TestEnvelope_AgentID_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().AgentID(); got != "" {
		t.Errorf("nil-inner AgentID: got %q want empty", got)
	}
	if got := fullEnvelope().AgentID(); got != "10000000-0000-4000-8000-000000000001" {
		t.Errorf("full AgentID: got %q", got)
	}
}

// LogID lives on the outer payload, not on the inner event — exercise
// both the populated and the nil-payload cases.
func TestEnvelope_LogID_BothArms(t *testing.T) {
	if got := nilInnerEnvelope().LogID(); got != "" {
		t.Errorf("nil-payload LogID: got %q want empty", got)
	}
	if got := fullEnvelope().LogID(); got != "log-id" {
		t.Errorf("full LogID: got %q", got)
	}
}

// Version returns the schemaVersion stamped into the envelope —
// always "V2" for envelopes built via BuildEnvelope.
func TestEnvelope_Version_BothArms(t *testing.T) {
	// Envelope with no SchemaVersion set returns whatever empty
	// string is stored. BuildEnvelope stamps "V2".
	if got := nilInnerEnvelope().Version(); got != "" {
		t.Errorf("nil envelope Version: got %q want empty", got)
	}
	if got := fullEnvelope().Version(); got != "V2" {
		t.Errorf("full envelope Version: got %q want V2", got)
	}
}
