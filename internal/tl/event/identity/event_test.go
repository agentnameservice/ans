package identity

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

// validEvent returns a minimal valid event of the given type.
func validEvent(t Type) *Event {
	ev := &Event{
		EventType:  t,
		IdentityID: "01HXKQ00000000000000000000",
		Kind:       "did:web",
		Value:      "did:web:identity.acme-corp.com",
		Timestamp:  "2026-06-10T15:04:05Z",
	}
	switch {
	case t.isProof():
		ev.ProviderID = "PID-8294"
		ev.ProofMethod = "did-web-sig"
		ev.VerifiedAt = "2026-06-10T15:04:05Z"
		ev.Keys = []ProvenKey{{
			VerificationMethod: json.RawMessage(`{"id":"did:web:identity.acme-corp.com#key-1","type":"JsonWebKey2020","controller":"did:web:identity.acme-corp.com","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"abc"}}`),
			SignedProof:        "eyJhbGciOiJFZERTQSJ9.payload.sig",
		}}
	case t.isLink():
		ev.AnsIDs = []string{"550e8400-e29b-41d4-a716-446655440000"}
	case t == TypeIdentityRevoked:
		ev.RevokedAt = "2026-06-10T16:00:00Z"
	}
	return ev
}

func TestTypeIsValid(t *testing.T) {
	for _, tt := range []Type{
		TypeIdentityVerified, TypeIdentityUpdated, TypeIdentityRevoked,
		TypeIdentityLinked, TypeIdentityUnlinked,
	} {
		if !tt.IsValid() {
			t.Errorf("%s should be valid", tt)
		}
	}
	for _, tt := range []Type{"", "AGENT_REGISTERED", "IDENTITY_ADDED", "identity_verified"} {
		if tt.IsValid() {
			t.Errorf("%s should be invalid", tt)
		}
	}
}

func TestEventValidate_AllTypesHappyPath(t *testing.T) {
	for _, tt := range []Type{
		TypeIdentityVerified, TypeIdentityUpdated, TypeIdentityRevoked,
		TypeIdentityLinked, TypeIdentityUnlinked,
	} {
		if err := validEvent(tt).Validate(); err != nil {
			t.Errorf("%s: unexpected validation error: %v", tt, err)
		}
	}
}

func TestEventValidate_RequiredFieldMatrix(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Event)
		base    Type
		wantSub string
	}{
		{"nil event", nil, TypeIdentityVerified, "producer.event required"},
		{"bad type", func(e *Event) { e.EventType = "AGENT_REGISTERED" }, TypeIdentityVerified, "invalid eventType"},
		{"missing identityId", func(e *Event) { e.IdentityID = "" }, TypeIdentityVerified, "identityId required"},
		{"missing kind", func(e *Event) { e.Kind = "" }, TypeIdentityVerified, "kind required"},
		{"missing value", func(e *Event) { e.Value = "" }, TypeIdentityVerified, "value required"},
		{"missing timestamp", func(e *Event) { e.Timestamp = "" }, TypeIdentityVerified, "timestamp required"},
		{"bad timestamp", func(e *Event) { e.Timestamp = "yesterday" }, TypeIdentityVerified, "RFC3339"},
		{"verified without keys", func(e *Event) { e.Keys = nil }, TypeIdentityVerified, "requires non-empty keys"},
		{"updated without keys", func(e *Event) { e.Keys = nil }, TypeIdentityUpdated, "requires non-empty keys"},
		{"key missing verificationMethod", func(e *Event) { e.Keys[0].VerificationMethod = nil }, TypeIdentityVerified, "verificationMethod required"},
		{"verificationMethod without id", func(e *Event) { e.Keys[0].VerificationMethod = json.RawMessage(`{"type":"JsonWebKey2020"}`) }, TypeIdentityVerified, "must be an object with an id"},
		{"key missing signedProof", func(e *Event) { e.Keys[0].SignedProof = "" }, TypeIdentityVerified, "signedProof required"},
		{"verified without verifiedAt", func(e *Event) { e.VerifiedAt = "" }, TypeIdentityVerified, "requires verifiedAt"},
		{"verified without providerId", func(e *Event) { e.ProviderID = "" }, TypeIdentityVerified, "requires providerId"},
		{"revoked without revokedAt", func(e *Event) { e.RevokedAt = "" }, TypeIdentityRevoked, "requires revokedAt"},
		{"linked without ansIds", func(e *Event) { e.AnsIDs = nil }, TypeIdentityLinked, "requires non-empty ansIds"},
		{"unlinked without ansIds", func(e *Event) { e.AnsIDs = nil }, TypeIdentityUnlinked, "requires non-empty ansIds"},
		{"linked with empty ansId entry", func(e *Event) { e.AnsIDs = []string{"a", ""} }, TypeIdentityLinked, "ansIds[1] is empty"},
		{"proof with ansIds", func(e *Event) { e.AnsIDs = []string{"a"} }, TypeIdentityVerified, "ansIds forbidden"},
		{"revoked with ansIds", func(e *Event) { e.AnsIDs = []string{"a"} }, TypeIdentityRevoked, "ansIds forbidden"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ev *Event
			if tc.mutate != nil {
				ev = validEvent(tc.base)
				tc.mutate(ev)
			}
			err := ev.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestEnvelopeValidate(t *testing.T) {
	mk := func() *Envelope {
		return BuildEnvelope("log-1", validEvent(TypeIdentityVerified), "key-1", "sig-1")
	}

	if err := mk().Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*Envelope)
		env     *Envelope
		wantSub string
	}{
		{name: "nil envelope", env: nil, wantSub: "nil envelope"},
		{name: "wrong schema", mutate: func(e *Envelope) { e.SchemaVersion = "V1" }, wantSub: "schemaVersion"},
		{name: "missing payload", mutate: func(e *Envelope) { e.Payload = nil }, wantSub: "payload required"},
		{name: "missing logId", mutate: func(e *Envelope) { e.Payload.LogID = "" }, wantSub: "logId required"},
		{name: "missing producer", mutate: func(e *Envelope) { e.Payload.Producer = nil }, wantSub: "producer required"},
		{name: "missing keyId", mutate: func(e *Envelope) { e.Payload.Producer.KeyID = "" }, wantSub: "keyId required"},
		{name: "missing signature", mutate: func(e *Envelope) { e.Payload.Producer.Signature = "" }, wantSub: "signature required"},
		{name: "invalid inner", mutate: func(e *Envelope) { e.Payload.Producer.Event.IdentityID = "" }, wantSub: "identityId required"},
		{name: "nil inner", mutate: func(e *Envelope) { e.Payload.Producer.Event = nil }, wantSub: "producer.event required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if tc.mutate != nil {
				env = mk()
				tc.mutate(env)
			}
			err := env.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestSigningLifecycle(t *testing.T) {
	env := BuildEnvelope("log-1", validEvent(TypeIdentityVerified), "key-1", "sig-1")

	// LeafBytes before signing is a misuse.
	if _, err := env.LeafBytes(); err == nil {
		t.Fatal("LeafBytes on unsigned envelope should error")
	}

	signingInput, err := env.SigningInput()
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}
	// The omitempty on the outer Signature is load-bearing: the
	// signing input must have no TOP-LEVEL "signature" key (the
	// producer's signature under payload.producer is sealed content
	// and legitimately present).
	var top map[string]json.RawMessage
	if err := json.Unmarshal(signingInput, &top); err != nil {
		t.Fatalf("signing input not JSON: %v", err)
	}
	if _, ok := top["signature"]; ok {
		t.Fatal("signing input must not contain the top-level signature key")
	}

	env.Signature = "tl-attestation-jws"

	// SigningInput after signing is a misuse.
	if _, err := env.SigningInput(); err == nil {
		t.Fatal("SigningInput on signed envelope should error")
	}

	leaf, err := env.LeafBytes()
	if err != nil {
		t.Fatalf("LeafBytes: %v", err)
	}
	if !strings.Contains(string(leaf), `"signature":"tl-attestation-jws"`) {
		t.Fatal("leaf bytes must contain the outer signature")
	}

	// LeafHash = SHA-256(0x00 || leaf) per RFC 6962 §2.1.
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	var want [32]byte
	copy(want[:], h.Sum(nil))
	got, err := env.LeafHash()
	if err != nil {
		t.Fatalf("LeafHash: %v", err)
	}
	if got != want {
		t.Fatal("leaf hash mismatch with independent RFC 6962 computation")
	}
}

func TestLeafHashOnUnsignedEnvelope(t *testing.T) {
	env := BuildEnvelope("log-1", validEvent(TypeIdentityVerified), "key-1", "sig-1")
	if _, err := env.LeafHash(); err == nil {
		t.Fatal("LeafHash on unsigned envelope should error")
	}
}

func TestCanonicalizeEventDeterministic(t *testing.T) {
	ev := validEvent(TypeIdentityLinked)
	a, err := CanonicalizeEvent(ev)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, err := CanonicalizeEvent(ev)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("canonicalization must be deterministic")
	}
	// JCS sorts keys: ansIds before eventType before identityId.
	s := string(a)
	if strings.Index(s, `"ansIds"`) >= strings.Index(s, `"eventType"`) ||
		strings.Index(s, `"eventType"`) >= strings.Index(s, `"identityId"`) {
		t.Fatalf("canonical bytes not JCS-sorted: %s", s)
	}
}

func TestViewAccessors(t *testing.T) {
	ev := validEvent(TypeIdentityLinked)
	env := BuildEnvelope("log-9", ev, "key-9", "psig-9")

	if env.Version() != "V2" {
		t.Errorf("Version = %q", env.Version())
	}
	if env.LogID() != "log-9" {
		t.Errorf("LogID = %q", env.LogID())
	}
	if env.AgentID() != "" || env.AnsName() != "" || env.AgentFQDN() != "" {
		t.Error("agent-side accessors must be empty on identity envelopes")
	}
	if env.EventType() != "IDENTITY_LINKED" {
		t.Errorf("EventType = %q", env.EventType())
	}
	if env.Timestamp() != ev.Timestamp {
		t.Errorf("Timestamp = %q", env.Timestamp())
	}
	if env.ProducerKeyID() != "key-9" || env.ProducerSignature() != "psig-9" {
		t.Error("producer accessors mismatch")
	}
	if env.IdentityID() != ev.IdentityID {
		t.Errorf("IdentityID = %q", env.IdentityID())
	}
	if got := env.LinkedAgentIDs(); len(got) != 1 || got[0] != ev.AnsIDs[0] {
		t.Errorf("LinkedAgentIDs = %v", got)
	}
}

func TestViewAccessorsOnEmptyEnvelope(t *testing.T) {
	var nilEnv *Envelope
	if nilEnv.innerEvent() != nil {
		t.Fatal("nil envelope must have nil inner event")
	}
	empty := &Envelope{}
	if empty.LogID() != "" || empty.EventType() != "" || empty.Timestamp() != "" ||
		empty.ProducerKeyID() != "" || empty.ProducerSignature() != "" ||
		empty.IdentityID() != "" || empty.LinkedAgentIDs() != nil {
		t.Fatal("accessors on empty envelope must return zero values")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	env := BuildEnvelope("log-1", validEvent(TypeIdentityVerified), "key-1", "sig-1")
	env.Signature = "outer"
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Envelope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped envelope invalid: %v", err)
	}
	if back.IdentityID() != env.IdentityID() {
		t.Fatal("identityId lost in round trip")
	}
	if len(back.Payload.Producer.Event.Keys) != 1 {
		t.Fatal("keys lost in round trip")
	}
}
