package event

import (
	"encoding/json"
	"strings"
	"testing"
)

// validLinkEvent returns a populated EQUIVALENCE_LINK envelope that
// passes Validate (modulo signing fields). Tests build mutations on
// top of this fixture rather than re-stating the entire shape.
func validLinkEvent() *Envelope {
	return &Envelope{
		SchemaVersion: SchemaVersion,
		Payload: &Payload{
			LogID: "log-uuid-1",
			Producer: &Producer{
				KeyID:     "ans-ra-signer",
				Signature: "sig-jws",
				Event: &Event{
					AnsID:     "primary-id",
					AnsName:   "ans://v1.0.0.invoicing.acme.com",
					EventType: TypeEquivalenceLink,
					RaID:      "ans-ra-local",
					Timestamp: "2026-05-17T10:00:00Z",
					Equivalence: &EquivalenceLink{
						LinkedAnsID:            "linked-id",
						LinkedAnsName:          "ans://v1.0.0.invoicing.acme.com",
						LinkedAnchorType:       "lei",
						LinkedAnchorResolvedID: "529900T8BM49AURSDO55",
						Rationale:              "operator-asserted-multi-anchor",
					},
				},
			},
		},
	}
}

func TestValidate_EquivalenceLink_HappyPath(t *testing.T) {
	if err := validLinkEvent().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_EquivalenceLink_MissingEquivalenceFails(t *testing.T) {
	env := validLinkEvent()
	env.Payload.Producer.Event.Equivalence = nil
	err := env.Validate()
	if err == nil {
		t.Fatal("expected error when EQUIVALENCE_LINK has no equivalence")
	}
	if !strings.Contains(err.Error(), "EQUIVALENCE_LINK requires equivalence") {
		t.Errorf("error: %v", err)
	}
}

func TestValidate_EquivalenceLink_MissingLinkedAnsIDFails(t *testing.T) {
	env := validLinkEvent()
	env.Payload.Producer.Event.Equivalence.LinkedAnsID = ""
	err := env.Validate()
	if err == nil {
		t.Fatal("expected error when LinkedAnsID is empty")
	}
	if !strings.Contains(err.Error(), "equivalence.linkedAnsId required") {
		t.Errorf("error: %v", err)
	}
}

func TestValidate_EquivalenceLink_SelfReferenceFails(t *testing.T) {
	env := validLinkEvent()
	env.Payload.Producer.Event.Equivalence.LinkedAnsID = env.Payload.Producer.Event.AnsID
	err := env.Validate()
	if err == nil {
		t.Fatal("expected error when LinkedAnsID == AnsID")
	}
	if !strings.Contains(err.Error(), "must differ from ansId") {
		t.Errorf("error: %v", err)
	}
}

func TestValidate_EquivalenceLink_AgentFieldRejected(t *testing.T) {
	env := validLinkEvent()
	env.Payload.Producer.Event.Agent = &Agent{Host: "x.test", Name: "x", Version: "1.0.0"}
	err := env.Validate()
	if err == nil {
		t.Fatal("expected error when EQUIVALENCE_LINK carries agent")
	}
	if !strings.Contains(err.Error(), "must not carry agent") {
		t.Errorf("error: %v", err)
	}
}

func TestValidate_EquivalenceLink_AttestationsRejected(t *testing.T) {
	env := validLinkEvent()
	env.Payload.Producer.Event.Attestations = &Attestations{DomainValidation: "ACME-DNS-01"}
	err := env.Validate()
	if err == nil {
		t.Fatal("expected error when EQUIVALENCE_LINK carries attestations")
	}
	if !strings.Contains(err.Error(), "must not carry attestations") {
		t.Errorf("error: %v", err)
	}
}

func TestValidate_NonLink_RejectsEquivalence(t *testing.T) {
	env := validLinkEvent()
	env.Payload.Producer.Event.EventType = TypeAgentRegistered
	env.Payload.Producer.Event.Agent = &Agent{Host: "x.test", Name: "x", Version: "1.0.0"}
	env.Payload.Producer.Event.Attestations = &Attestations{DomainValidation: "ACME-DNS-01"}
	// Equivalence is still populated; should be rejected.
	err := env.Validate()
	if err == nil {
		t.Fatal("expected error when AGENT_REGISTERED carries equivalence")
	}
	if !strings.Contains(err.Error(), "equivalence not allowed for eventType") {
		t.Errorf("error: %v", err)
	}
}

func TestType_EquivalenceLink_IsValid(t *testing.T) {
	if !TypeEquivalenceLink.IsValid() {
		t.Error("TypeEquivalenceLink should be IsValid true")
	}
}

// TestEquivalenceLink_JSONRoundTrip exercises the envelope's JCS path:
// EQUIVALENCE_LINK serializes to JSON and deserializes back without
// shape drift. Important because the leaf hash is computed over the
// canonical bytes; any field-name change breaks downstream verifiers.
func TestEquivalenceLink_JSONRoundTrip(t *testing.T) {
	env := validLinkEvent()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Spot-check the canonical field names appear in the output.
	for _, want := range []string{
		`"eventType":"EQUIVALENCE_LINK"`,
		`"equivalence":`,
		`"linkedAnsId":"linked-id"`,
		`"linkedAnchorType":"lei"`,
		`"linkedAnchorResolvedId":"529900T8BM49AURSDO55"`,
		`"rationale":"operator-asserted-multi-anchor"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON missing %s", want)
		}
	}

	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Payload.Producer.Event.Equivalence.LinkedAnsID != "linked-id" {
		t.Errorf("round-trip lost LinkedAnsID: %+v", back.Payload.Producer.Event.Equivalence)
	}
}

// TestEquivalenceLink_OmitemptyOnNonLink confirms the equivalence field
// stays absent in JSON when not set, so existing AGENT_REGISTERED bytes
// stay byte-identical to pre-change.
func TestEquivalenceLink_OmitemptyOnNonLink(t *testing.T) {
	env := &Envelope{
		SchemaVersion: SchemaVersion,
		Payload: &Payload{
			LogID: "log-uuid-2",
			Producer: &Producer{
				KeyID:     "ans-ra-signer",
				Signature: "sig",
				Event: &Event{
					AnsID:     "primary",
					AnsName:   "ans://v1.0.0.acme.com",
					EventType: TypeAgentRegistered,
					Timestamp: "2026-05-17T10:00:00Z",
					Agent:     &Agent{Host: "acme.com", Name: "acme", Version: "1.0.0"},
				},
			},
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), `"equivalence"`) {
		t.Errorf("equivalence key should be absent on non-link events; got: %s", b)
	}
}
