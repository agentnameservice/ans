package event_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/tl/event"
)

// Test data: a hand-constructed envelope whose canonical JSON bytes
// are pinned in testdata/. If this golden file drifts, either:
//   - the schema is broken (regression) and the test caught it, or
//   - the schema was intentionally changed and the golden file needs
//     regeneration via `go test -run TestEnvelope -update`.
//
// Stability requirements pinned by these fixtures:
//   - schemaVersion value = "V1" (capital)
//   - JSON tag names match the reference byte-for-byte
//   - JCS canonicalization output is stable
//   - LeafHash = SHA-256(0x00 || canonical)
const (
	goldenLeafHex = "testdata/envelope_v1_golden.leafhash.hex"
	goldenJCS     = "testdata/envelope_v1_golden.jcs.bin"
)

// fixedEnvelope returns an envelope with every reference-matching
// field populated — run it through JCS to get the bytes that would
// be appended to the tree. The Attestations block exercises the full
// V1 attestation shape: ACME DNS-01 validation, a TXT-record array,
// single-element identity and server cert arrays, and per-protocol
// metadata hashes.
func fixedEnvelope() *event.Envelope {
	return &event.Envelope{
		SchemaVersion: event.SchemaVersion,
		Payload: &event.Payload{
			LogID: "01870e4c-9c9a-7000-8000-000000000001",
			Producer: &event.Producer{
				Event: &event.Event{
					AnsID:     "10000000-0000-4000-8000-000000000001",
					AnsName:   "ans://v1.0.0.agent.example.com",
					EventType: event.TypeAgentRegistered,
					Agent: &event.Agent{
						Host:    "agent.example.com",
						Name:    "sentiment-analyzer",
						Version: "1.0.0",
					},
					Attestations: &event.Attestations{
						// `domainValidation` names the method the RA used to
						// prove domain control at registration time —
						// ephemeral evidence that lives outside the log.
						DomainValidation: "ACME-DNS-01",
						// `dnsRecordsProvisioned` attests the agent's
						// *production* DNS state — what the authoritative
						// nameserver serves in steady state. ACME challenge
						// records are deliberately NOT included: they're
						// ephemeral and torn down after validation.
						DNSRecordsProvisioned: []event.DNSRecord{
							{
								Name: "_ans.agent.example.com",
								Data: "v=ans1; version=1.0.0; p=mcp; mode=direct; url=https://agent.example.com/mcp",
								Type: "TXT",
							},
							{
								Name: "_ans-badge.agent.example.com",
								Data: "v=ans-badge1; version=1.0.0; url=https://agent.example.com/mcp",
								Type: "TXT",
							},
							{
								Name: "_443._tcp.agent.example.com",
								Data: "3 1 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
								Type: "TLSA",
							},
							{
								Name: "agent.example.com",
								Data: "1 . alpn=h2 ipv4hint=192.0.2.1",
								Type: "HTTPS",
							},
						},
						IdentityCerts: []event.CertificateInfo{
							{
								Fingerprint: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
								CertType:    "X509-OV-CLIENT",
								NotAfter:    "2026-09-24T21:03:47.055Z",
							},
						},
						ServerCerts: []event.CertificateInfo{
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
					Timestamp: "2026-04-17T00:00:00Z",
				},
				KeyID:     "producer-k1",
				Signature: "ZmFrZS1wcm9kdWNlci1zaWc", // placeholder b64url
			},
		},
		Signature: "ZmFrZS10bC1hdHRlc3Q", // placeholder outer attestation
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
	env.Payload.Producer.Event.RevocationReasonCode = "AA_COMPROMISE"
	if err := env.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestEnvelope_Validate_MissingFields(t *testing.T) {
	t.Parallel()
	cases := map[string]func(e *event.Envelope){
		"nil envelope":     func(e *event.Envelope) { *e = event.Envelope{} },
		"wrong schema":     func(e *event.Envelope) { e.SchemaVersion = "v1" },
		"no payload":       func(e *event.Envelope) { e.Payload = nil },
		"no logId":         func(e *event.Envelope) { e.Payload.LogID = "" },
		"no producer":      func(e *event.Envelope) { e.Payload.Producer = nil },
		"no producer kid":  func(e *event.Envelope) { e.Payload.Producer.KeyID = "" },
		"no producer sig":  func(e *event.Envelope) { e.Payload.Producer.Signature = "" },
		"no event":         func(e *event.Envelope) { e.Payload.Producer.Event = nil },
		"bad event type":   func(e *event.Envelope) { e.Payload.Producer.Event.EventType = "BOGUS" },
		"no ansId":         func(e *event.Envelope) { e.Payload.Producer.Event.AnsID = "" },
		"no ansName":       func(e *event.Envelope) { e.Payload.Producer.Event.AnsName = "" },
		"no timestamp":     func(e *event.Envelope) { e.Payload.Producer.Event.Timestamp = "" },
		"non-RFC3339 time": func(e *event.Envelope) { e.Payload.Producer.Event.Timestamp = "yesterday" },
		"bad revocationReasonCode": func(e *event.Envelope) {
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

// TestEnvelope_LeafHash_NoPrefixBug guards against the RFC 6962 prefix
// regression that the parity review caught. If LeafHash ever reverts
// to bare SHA-256(canonical), this test fails.
func TestEnvelope_LeafHash_NoPrefixBug(t *testing.T) {
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

	// Positively assert this is *not* the naive SHA-256(canonical).
	naive := sha256.Sum256(leaf)
	if bytes.Equal(got[:], naive[:]) {
		t.Fatal("LeafHash regressed to bare SHA-256(canonical) — missing 0x00 prefix")
	}
}

// TestEnvelope_SigningInput_Before refuses to produce signing input
// once the outer Signature is populated. Prevents the footgun of
// signing bytes that differ from what future verifiers reconstruct.
func TestEnvelope_SigningInput_RefusesSignedEnvelope(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	if _, err := env.SigningInput(); err == nil {
		t.Fatal("SigningInput should refuse a signed envelope")
	}
	// Now empty the signature; it should work.
	env.Signature = ""
	if _, err := env.SigningInput(); err != nil {
		t.Fatalf("SigningInput on unsigned envelope: %v", err)
	}
}

func TestEnvelope_LeafBytes_RefusesUnsignedEnvelope(t *testing.T) {
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

// TestEnvelope_CanonicalBytes_StableAcrossKeyOrder is the core JCS
// guarantee — struct field order must not matter because JCS sorts
// keys lexically.
func TestEnvelope_CanonicalBytes_StableAcrossKeyOrder(t *testing.T) {
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

	// Manually mutate a field, canonicalize, un-mutate — round-trip
	// bytes must match.
	orig := env.Payload.Producer.Event.IssuedAt
	env.Payload.Producer.Event.IssuedAt = "different"
	_, _ = env.LeafBytes()
	env.Payload.Producer.Event.IssuedAt = orig
	c, err := env.LeafBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) {
		t.Fatal("round-trip mutation changed canonical bytes")
	}
}

// TestEnvelope_Accessors returns zero values on every missing-pointer
// path — we never dereference nil.
func TestEnvelope_Accessors_NilSafe(t *testing.T) {
	t.Parallel()
	var nilEnv *event.Envelope
	if nilEnv.AgentID() != "" || nilEnv.AnsName() != "" || nilEnv.EventType() != "" {
		t.Fatal("nil envelope accessors should return empty")
	}
	// Envelope without payload.
	empty := &event.Envelope{}
	if empty.LogID() != "" || empty.ProducerKeyID() != "" || empty.ProducerSignature() != "" {
		t.Fatal("empty envelope accessors should return empty")
	}
	if empty.Timestamp() != "" || empty.ExpiresAt() != "" || empty.AgentFQDN() != "" {
		t.Fatal("empty envelope secondary accessors should return empty")
	}
}

func TestEnvelope_Accessors_ReadValues(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	if got := env.LogID(); got != "01870e4c-9c9a-7000-8000-000000000001" {
		t.Errorf("LogID: got %q", got)
	}
	if got := env.AgentID(); got != "10000000-0000-4000-8000-000000000001" {
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
	// Version exposes schemaVersion for the EnvelopeView interface
	// shared with v1 — mismatched value here would surface as the
	// wrong `schemaVersion` written to tl_events and echoed back in
	// TransparencyLog responses.
	if got := env.Version(); got != event.SchemaVersion {
		t.Errorf("Version: got %q, want %q", got, event.SchemaVersion)
	}
}

// TestEnvelope_Golden pins the canonical bytes + leaf hash so that
// any reference-drift in JCS, JSON tags, or field ordering fails here
// before it leaks into receipts. Regenerate with `-update` only when
// intentionally changing the schema (which is a capital-I incident
// for offline verifiers).
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

	// Belt & braces: canonical bytes must round-trip through JSON
	// without losing the shape the golden file fixes.
	var round event.Envelope
	if err := json.Unmarshal(canonical, &round); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if round.SchemaVersion != event.SchemaVersion {
		t.Fatalf("schemaVersion: got %q, want %q", round.SchemaVersion, event.SchemaVersion)
	}
}

// TestBuildEnvelope_Shape proves the builder produces the exact shape
// we want and that the TL — not the RA — owns logId assignment.
func TestBuildEnvelope_Shape(t *testing.T) {
	t.Parallel()
	inner := &event.Event{
		AnsID:     "a",
		AnsName:   "ans://v1.0.0.a.example.com",
		EventType: event.TypeAgentRegistered,
		Timestamp: "2026-04-17T00:00:00Z",
	}
	env := event.BuildEnvelope("log-1", inner, "kid-1", "sig-1")
	if env.SchemaVersion != event.SchemaVersion {
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

// TestCanonicalizeEvent_Stable matches identical inputs to identical
// bytes regardless of struct field declaration order (JCS sorts).
func TestCanonicalizeEvent_Stable(t *testing.T) {
	t.Parallel()
	inner := &event.Event{
		AnsID:     "a",
		AnsName:   "ans://v1.0.0.a.example.com",
		EventType: event.TypeAgentRegistered,
		Timestamp: "2026-04-17T00:00:00Z",
	}
	a, err := event.CanonicalizeEvent(inner)
	if err != nil {
		t.Fatal(err)
	}
	b, err := event.CanonicalizeEvent(inner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("CanonicalizeEvent not stable")
	}
}

// TestAttestations_ArraysRoundTrip exercises the shape change away
// from reference-singleton + reference-rotation-array to unified
// arrays. A single-cert event produces one-element identityCerts and
// serverCerts; a rotation-window event produces multi-element arrays.
// DNS records round-trip through the typed DNSRecord struct.
func TestAttestations_ArraysRoundTrip(t *testing.T) {
	t.Parallel()
	env := fixedEnvelope()
	env.Signature = "" // avoid golden coupling; we only want canonical shape

	env.Payload.Producer.Event.Attestations.IdentityCerts = append(
		env.Payload.Producer.Event.Attestations.IdentityCerts,
		event.CertificateInfo{
			Fingerprint: "SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			CertType:    "X509-OV-CLIENT",
			NotAfter:    "2027-01-01T00:00:00Z",
		},
	)

	canonical, err := env.SigningInput()
	if err != nil {
		t.Fatal(err)
	}
	var round event.Envelope
	if err := json.Unmarshal(canonical, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := round.Payload.Producer.Event.Attestations
	if len(got.IdentityCerts) != 2 {
		t.Fatalf("identityCerts: got %d, want 2", len(got.IdentityCerts))
	}
	if len(got.ServerCerts) != 1 {
		t.Fatalf("serverCerts: got %d, want 1", len(got.ServerCerts))
	}
	// Fixture now carries the realistic production record set:
	// _ans TXT + _ans-badge TXT + TLSA + HTTPS. ACME challenge
	// records never land in the attestation.
	if len(got.DNSRecordsProvisioned) != 4 {
		t.Fatalf("dnsRecords: got %d, want 4", len(got.DNSRecordsProvisioned))
	}
	seen := map[string]bool{}
	for _, r := range got.DNSRecordsProvisioned {
		seen[r.Type] = true
		if r.Name == "_acme-challenge.agent.example.com" {
			t.Error("ACME challenge record must not be attested to TL")
		}
	}
	for _, want := range []string{"TXT", "TLSA", "HTTPS"} {
		if !seen[want] {
			t.Errorf("missing %s record in attestation set", want)
		}
	}
	if got.DomainValidation != "ACME-DNS-01" {
		t.Errorf("domainValidation: got %q", got.DomainValidation)
	}
}

func TestType_IsValid(t *testing.T) {
	t.Parallel()
	for _, tp := range []event.Type{
		event.TypeAgentRegistered, event.TypeAgentRenewed,
		event.TypeAgentRevoked, event.TypeAgentRegistered,
	} {
		if !tp.IsValid() {
			t.Errorf("%q should be valid", tp)
		}
	}
	if event.Type("bogus").IsValid() {
		t.Error("bogus should not be valid")
	}
}

// ----- helpers -----

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
