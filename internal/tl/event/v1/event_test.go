package v1_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/godaddy/ans/internal/tl/event/v1"
)

// V1 golden fixtures are pinned independently of V2 because the V1
// inner-event shape differs (singleton identityCert/serverCert +
// rotation arrays, map-typed dnsRecordsProvisioned). Any drift here
// means offline verifiers built against the reference TL's V1 event
// schema stop round-tripping our leaves.
//
// Stability requirements pinned by these fixtures:
//   - schemaVersion value = "V1" (capital; matches reference V1
//     envelope's schemaVersion constant)
//   - Inner-event JSON tag names (ansId / ansName / eventType /
//     issuedAt / expiresAt / revocationReasonCode / raId / …) match
//     reference byte-for-byte
//   - Singleton `identityCert` / `serverCert` + rotation arrays
//     `validIdentityCerts[]` / `validServerCerts[]`, not the V2
//     unified arrays
//   - `dnsRecordsProvisioned` is serialized as a JSON object
//     (map[name]value), not as the V2 typed-array
//   - JCS canonicalization output is byte-stable
//   - LeafHash = SHA-256(0x00 || canonical) — identical formula to V2
//     (Tessera doesn't care about inner shape for leaf hashing)
const (
	goldenLeafHex = "testdata/envelope_v1_golden.leafhash.hex"
	goldenJCS     = "testdata/envelope_v1_golden.jcs.bin"
)

// fixedEnvelope returns a V1 envelope populated with every reference-
// matching field. The attestations block exercises BOTH the singleton
// `identityCert`/`serverCert` AND the rotation arrays
// `validIdentityCerts[]`/`validServerCerts[]` so the JCS output pins
// both shapes at once — catches the regression where someone
// "simplifies" V1 to match V2's unified arrays.
func fixedEnvelope() *v1.Envelope {
	return &v1.Envelope{
		SchemaVersion: v1.SchemaVersion,
		Payload: &v1.Payload{
			LogID: "01870e4c-9c9a-7000-8000-0000000000a1",
			Producer: &v1.Producer{
				Event: &v1.Event{
					AnsID:     "10000000-0000-4000-8000-0000000000a1",
					AnsName:   "ans://v1.0.0.agent.example.com",
					EventType: v1.TypeAgentRegistered,
					Agent: &v1.Agent{
						Host:    "agent.example.com",
						Name:    "sentiment-analyzer",
						Version: "1.0.0",
					},
					Attestations: &v1.Attestations{
						DomainValidation: "ACME-DNS-01",
						// Map form — note that V1 cannot distinguish two
						// TXT records at the same owner name. This is
						// the documented lossy-ness that motivated the
						// V2 typed-array upgrade.
						DNSRecordsProvisioned: map[string]string{
							"_ans.agent.example.com":       "v=ans1; version=1.0.0; p=mcp; mode=direct; url=https://agent.example.com/mcp",
							"_ans-badge.agent.example.com": "v=ans-badge1; version=1.0.0; url=https://agent.example.com/mcp",
							"_443._tcp.agent.example.com":  "3 1 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						},
						IdentityCert: &v1.CertificateInfo{
							Fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							CertType:    "X509-OV-CLIENT",
						},
						ServerCert: &v1.CertificateInfo{
							Fingerprint: "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
							CertType:    "X509-DV-SERVER",
						},
						// Rotation arrays populated — mirrors the
						// reference during cert overlap windows where
						// the new cert hasn't fully taken over yet.
						ValidIdentityCerts: []v1.CertificateInfoExtended{
							{
								Fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
								CertType:    "X509-OV-CLIENT",
								NotAfter:    "2026-09-24T21:03:47.055Z",
							},
						},
						ValidServerCerts: []v1.CertificateInfoExtended{
							{
								Fingerprint: "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
								CertType:    "X509-DV-SERVER",
								NotAfter:    "2026-09-24T21:03:47.055Z",
							},
						},
						MetadataHashes: map[string]string{
							"A2A": "SHA256:3b4f2c1a00000000000000000000000000000000000000000000000000000000",
							"MCP": "SHA256:a1c9e7b300000000000000000000000000000000000000000000000000000000",
						},
					},
					RaID:      "ans-ra-local",
					IssuedAt:  "2026-04-17T00:00:00Z",
					ExpiresAt: "2027-04-17T00:00:00Z",
					Timestamp: "2026-04-17T00:00:00Z",
				},
				KeyID:     "producer-k1",
				Signature: "ZmFrZS1wcm9kdWNlci1zaWc", // b64url placeholder
			},
		},
		Signature: "ZmFrZS10bC1hdHRlc3Q", // placeholder outer attestation
	}
}

func TestType_Valid(t *testing.T) {
	t.Parallel()
	for _, tp := range []v1.Type{
		v1.TypeAgentDeprecated, v1.TypeAgentRegistered,
		v1.TypeAgentRenewed, v1.TypeAgentRevoked,
	} {
		if !tp.Valid() {
			t.Errorf("%q should be valid", tp)
		}
	}
	if v1.Type("AGENT_REGISTRATION").Valid() {
		// V2 enum value; V1 must reject.
		t.Error("AGENT_REGISTRATION (V2) must not be a valid V1 eventType")
	}
	if v1.Type("").Valid() {
		t.Error("empty type must not be valid")
	}
}

func TestEnvelope_Validate_Success(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	if err := env.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestEnvelope_Validate_RevocationReasonCode_Valid(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	env.Payload.Producer.Event.RevocationReasonCode = "REMOVE_FROM_CRL"
	if err := env.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestEnvelope_Validate_Failures(t *testing.T) {
	t.Parallel()
	cases := map[string]func(e *v1.Envelope){
		"wrong schema":     func(e *v1.Envelope) { e.SchemaVersion = "v1" },
		"v2 schema":        func(e *v1.Envelope) { e.SchemaVersion = "V2" },
		"no payload":       func(e *v1.Envelope) { e.Payload = nil },
		"no logId":         func(e *v1.Envelope) { e.Payload.LogID = "" },
		"no producer":      func(e *v1.Envelope) { e.Payload.Producer = nil },
		"no event":         func(e *v1.Envelope) { e.Payload.Producer.Event = nil },
		"bad event type":   func(e *v1.Envelope) { e.Payload.Producer.Event.EventType = "BOGUS" },
		"v2 event type":    func(e *v1.Envelope) { e.Payload.Producer.Event.EventType = "AGENT_REGISTRATION" },
		"no ansId":         func(e *v1.Envelope) { e.Payload.Producer.Event.AnsID = "" },
		"no ansName":       func(e *v1.Envelope) { e.Payload.Producer.Event.AnsName = "" },
		"no timestamp":     func(e *v1.Envelope) { e.Payload.Producer.Event.Timestamp = "" },
		"non-RFC3339 time": func(e *v1.Envelope) { e.Payload.Producer.Event.Timestamp = "yesterday" },
		"bad revocationReasonCode": func(e *v1.Envelope) {
			e.Payload.Producer.Event.RevocationReasonCode = "BOGUS"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := fixedEnvelope()
			mutate(env)
			if err := env.Validate(); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}

func TestEnvelope_Validate_NilReceiver(t *testing.T) {
	t.Parallel()
	var nilEnv *v1.Envelope
	if err := nilEnv.Validate(); err == nil {
		t.Fatal("nil receiver must error")
	}
}

// TestEnvelope_LeafHash_RFC6962Prefix guards the V1 leaf hash formula.
// The parity review found a bug where leaves were bare SHA-256 — this
// test fails fast if anyone "cleans up" the 0x00 prefix.
func TestEnvelope_LeafHash_RFC6962Prefix(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	leaf, err := env.LeafBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.New()
	want.Write([]byte{0x00})
	want.Write(leaf)
	wantHash := want.Sum(nil)

	got, err := env.LeafHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], wantHash) {
		t.Fatalf("RFC 6962 leaf hash mismatch:\n  got : %x\n  want: %x", got, wantHash)
	}

	naive := sha256.Sum256(leaf)
	if bytes.Equal(got[:], naive[:]) {
		t.Fatal("LeafHash regressed to bare SHA-256(canonical) — missing 0x00 prefix")
	}
}

func TestEnvelope_SigningInput_RefusesSigned(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	if _, err := env.SigningInput(); err == nil {
		t.Fatal("SigningInput should refuse a signed envelope")
	}
	env.Signature = ""
	if _, err := env.SigningInput(); err != nil {
		t.Fatalf("SigningInput on unsigned envelope: %v", err)
	}
}

func TestEnvelope_LeafBytes_RefusesUnsigned(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	env.Signature = ""
	if _, err := env.LeafBytes(); err == nil {
		t.Fatal("LeafBytes should refuse unsigned envelope")
	}
	if _, err := env.LeafHash(); err == nil {
		t.Fatal("LeafHash should refuse unsigned envelope")
	}
}

func TestEnvelope_CanonicalBytes_Stable(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	a, err := env.LeafBytes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.LeafBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same envelope produced different canonical bytes across calls")
	}
}

func TestEnvelope_Accessors_NilSafe(t *testing.T) {
	t.Parallel()
	empty := &v1.Envelope{}
	if empty.LogID() != "" || empty.AgentID() != "" || empty.AnsName() != "" ||
		empty.EventType() != "" || empty.Timestamp() != "" || empty.AgentFQDN() != "" ||
		empty.ProducerKeyID() != "" || empty.ProducerSignature() != "" {
		t.Fatal("empty envelope accessors should all be empty strings")
	}
	// Even with payload but no producer, accessors must stay safe.
	partial := &v1.Envelope{Payload: &v1.Payload{LogID: "log-x"}}
	if partial.LogID() != "log-x" {
		t.Errorf("LogID: got %q", partial.LogID())
	}
	if partial.ProducerKeyID() != "" || partial.ProducerSignature() != "" ||
		partial.EventType() != "" || partial.AgentID() != "" {
		t.Error("missing-producer accessors should return empty")
	}
}

func TestEnvelope_Accessors_ReadValues(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	if got := env.LogID(); got != "01870e4c-9c9a-7000-8000-0000000000a1" {
		t.Errorf("LogID: got %q", got)
	}
	if got := env.AgentID(); got != "10000000-0000-4000-8000-0000000000a1" {
		t.Errorf("AgentID: got %q", got)
	}
	if got := env.AnsName(); got != "ans://v1.0.0.agent.example.com" {
		t.Errorf("AnsName: got %q", got)
	}
	if got := env.EventType(); got != "AGENT_REGISTERED" {
		t.Errorf("EventType: got %q", got)
	}
	if got := env.AgentFQDN(); got != "agent.example.com" {
		t.Errorf("AgentFQDN: got %q", got)
	}
	if got := env.Timestamp(); got != "2026-04-17T00:00:00Z" {
		t.Errorf("Timestamp: got %q", got)
	}
	if got := env.ProducerKeyID(); got != "producer-k1" {
		t.Errorf("ProducerKeyID: got %q", got)
	}
	if got := env.ProducerSignature(); got != "ZmFrZS1wcm9kdWNlci1zaWc" {
		t.Errorf("ProducerSignature: got %q", got)
	}
	if got := env.Version(); got != "V1" {
		t.Errorf("Version: got %q", got)
	}
}

// TestBuildEnvelope_Shape proves the V1 builder produces the exact
// shape TL consumers expect — TL owns logId assignment, outer
// signature starts empty and is populated only after TL attestation
// signing.
func TestBuildEnvelope_Shape(t *testing.T) {
	t.Parallel()
	inner := &v1.Event{
		AnsID:     "a",
		AnsName:   "ans://v1.0.0.a.example.com",
		EventType: v1.TypeAgentRegistered,
		Timestamp: "2026-04-17T00:00:00Z",
	}
	env := v1.BuildEnvelope("log-1", inner, "kid-1", "sig-1")
	if env.SchemaVersion != v1.SchemaVersion {
		t.Errorf("schemaVersion: got %q", env.SchemaVersion)
	}
	if env.Payload.LogID != "log-1" {
		t.Errorf("logId: got %q", env.Payload.LogID)
	}
	if env.Payload.Producer.KeyID != "kid-1" {
		t.Errorf("kid: got %q", env.Payload.Producer.KeyID)
	}
	if env.Payload.Producer.Signature != "sig-1" {
		t.Errorf("sig: got %q", env.Payload.Producer.Signature)
	}
	if env.Signature != "" {
		t.Errorf("outer signature should start empty, got %q", env.Signature)
	}
}

func TestCanonicalizeEvent_Stable(t *testing.T) {
	t.Parallel()
	inner := &v1.Event{
		AnsID:     "a",
		AnsName:   "ans://v1.0.0.a.example.com",
		EventType: v1.TypeAgentRegistered,
		Timestamp: "2026-04-17T00:00:00Z",
	}
	a, err := v1.CanonicalizeEvent(inner)
	if err != nil {
		t.Fatal(err)
	}
	b, err := v1.CanonicalizeEvent(inner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("CanonicalizeEvent not stable across calls")
	}
}

// TestAttestations_SingletonAndRotation pins the V1-specific shape
// difference: singleton `identityCert` + rotation array
// `validIdentityCerts[]`. A simplifying edit that drops the singleton
// into the rotation array would break round-trip with the reference.
func TestAttestations_SingletonAndRotation(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	env.Signature = "" // don't couple to the golden outer signature
	canonical, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	var round v1.Envelope
	if err := json.Unmarshal(canonical, &round); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	att := round.Payload.Producer.Event.Attestations
	if att.IdentityCert == nil {
		t.Fatal("singleton identityCert dropped during canonicalize")
	}
	if att.ServerCert == nil {
		t.Fatal("singleton serverCert dropped during canonicalize")
	}
	if len(att.ValidIdentityCerts) != 1 {
		t.Fatalf("validIdentityCerts: got %d, want 1", len(att.ValidIdentityCerts))
	}
	if len(att.ValidServerCerts) != 1 {
		t.Fatalf("validServerCerts: got %d, want 1", len(att.ValidServerCerts))
	}
	if _, ok := att.DNSRecordsProvisioned["_ans.agent.example.com"]; !ok {
		t.Error("expected _ans TXT record in V1 map")
	}
}

// TestEnvelope_Golden pins the canonical bytes + leaf hash for V1. Any
// JCS, JSON-tag, or field-ordering drift from the reference fails
// here before it leaks into Tessera-stored leaves. Regenerate with
// UPDATE_GOLDEN=1 ONLY when intentionally changing the V1 schema
// (which is a capital-I incident for offline verifiers).
func TestEnvelope_Golden(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	canonical, err := env.LeafBytes()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := env.LeafHash()
	if err != nil {
		t.Fatal(err)
	}

	if *update {
		mustWrite(t, goldenJCS, canonical)
		mustWrite(t, goldenLeafHex, []byte(hex.EncodeToString(leaf[:])+"\n"))
		return
	}

	wantCanonical := mustRead(t, goldenJCS)
	if !bytes.Equal(canonical, wantCanonical) {
		t.Fatalf("canonical bytes mismatch:\n  got : %s\n  want: %s", canonical, wantCanonical)
	}

	wantLeafHex := strings.TrimSpace(string(mustRead(t, goldenLeafHex)))
	if got := hex.EncodeToString(leaf[:]); got != wantLeafHex {
		t.Fatalf("leaf hash mismatch:\n  got : %s\n  want: %s", got, wantLeafHex)
	}

	// Round-trip through JSON — the golden bytes must re-parse into
	// the same schemaVersion + field names.
	var round v1.Envelope
	if err := json.Unmarshal(canonical, &round); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if round.SchemaVersion != v1.SchemaVersion {
		t.Fatalf("schemaVersion: got %q, want %q", round.SchemaVersion, v1.SchemaVersion)
	}
}

// Test helpers below — UPDATE_GOLDEN regenerates fixtures.

var update = boolPtr(os.Getenv("UPDATE_GOLDEN") != "")

func boolPtr(b bool) *bool { return &b }

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
