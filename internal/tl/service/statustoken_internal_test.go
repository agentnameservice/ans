package service

// White-box tests for the small extractors and status-mappers in
// statustoken.go. The service-layer happy path runs through
// statustoken_test.go's testbed; these tests cover branches the
// happy-path test can't reach without spinning up a separate event
// type per case (REVOKED / DEPRECATED / RENEWED / unknown), and the
// drillAttestations defensive guards.

import (
	"testing"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
)

// ----- deriveAgentStatus -----
//
// The four-arm switch is the source of truth for the wire-format
// agent status enum. Each arm matters because the status-token
// generator uses it to populate the `agentStatus` claim and to gate
// the ErrStatusTokenNotIssued branch (terminal states return 410).

func TestDeriveAgentStatus_AllBranches(t *testing.T) {
	cases := map[string]string{
		"AGENT_REVOKED":     "REVOKED",
		"AGENT_REGISTERED":  "ACTIVE",
		"AGENT_RENEWED":     "ACTIVE",
		"AGENT_DEPRECATED":  "DEPRECATED",
		"SOMETHING_UNUSUAL": "SOMETHING_UNUSUAL", // default arm
	}
	for ev, want := range cases {
		t.Run(ev, func(t *testing.T) {
			got := deriveAgentStatus(&sqlitetl.EventRecord{EventType: ev})
			if got != want {
				t.Errorf("deriveAgentStatus(%q): got %q want %q", ev, got, want)
			}
		})
	}
}

// ----- isTerminal -----
//
// REVOKED / EXPIRED are the only terminal statuses; DEPRECATED is
// not terminal because the agent is still reachable. Pin every case.
func TestIsTerminal_Cases(t *testing.T) {
	cases := map[string]bool{
		"REVOKED":    true,
		"EXPIRED":    true,
		"ACTIVE":     false,
		"DEPRECATED": false,
		"":           false,
	}
	for status, want := range cases {
		if got := isTerminal(status); got != want {
			t.Errorf("isTerminal(%q): got %v want %v", status, got, want)
		}
	}
}

// ----- drillAttestations -----
//
// Each cast in drillAttestations is a defensive guard against a
// malformed envelope. Direct unit tests pin each early-nil path.

func TestDrillAttestations_HappyPath(t *testing.T) {
	env := map[string]any{
		"payload": map[string]any{
			"producer": map[string]any{
				"event": map[string]any{
					"attestations": map[string]any{
						"identityCerts": []any{},
					},
				},
			},
		},
	}
	got := drillAttestations(env)
	if got == nil {
		t.Fatal("expected non-nil attestations map")
	}
	if _, ok := got["identityCerts"]; !ok {
		t.Error("expected identityCerts key to round-trip")
	}
}

func TestDrillAttestations_MissingPayload(t *testing.T) {
	if got := drillAttestations(map[string]any{"otherField": "x"}); got != nil {
		t.Errorf("expected nil for envelope without payload; got %v", got)
	}
}

func TestDrillAttestations_PayloadNotMap(t *testing.T) {
	if got := drillAttestations(map[string]any{"payload": "string-not-map"}); got != nil {
		t.Errorf("expected nil when payload is not a map; got %v", got)
	}
}

func TestDrillAttestations_MissingProducer(t *testing.T) {
	env := map[string]any{"payload": map[string]any{"logId": "x"}}
	if got := drillAttestations(env); got != nil {
		t.Errorf("expected nil when producer absent; got %v", got)
	}
}

func TestDrillAttestations_MissingEvent(t *testing.T) {
	env := map[string]any{
		"payload": map[string]any{
			"producer": map[string]any{"keyId": "x"},
		},
	}
	if got := drillAttestations(env); got != nil {
		t.Errorf("expected nil when event absent; got %v", got)
	}
}

func TestDrillAttestations_MissingAttestations(t *testing.T) {
	env := map[string]any{
		"payload": map[string]any{
			"producer": map[string]any{
				"event": map[string]any{"eventType": "AGENT_REGISTERED"},
			},
		},
	}
	if got := drillAttestations(env); got != nil {
		t.Errorf("expected nil when attestations absent; got %v", got)
	}
}

// ----- extractCertFingerprints -----

func TestExtractCertFingerprints_NotArray(t *testing.T) {
	if got := extractCertFingerprints("not an array"); got != nil {
		t.Errorf("expected nil for non-array; got %v", got)
	}
}

func TestExtractCertFingerprints_EntryNotMap(t *testing.T) {
	// Skips non-map entries, returns nil if no valid entries remain.
	if got := extractCertFingerprints([]any{"string", 42, true}); got != nil {
		t.Errorf("expected nil when no entries are maps; got %v", got)
	}
}

func TestExtractCertFingerprints_SkipsEntriesMissingFingerprint(t *testing.T) {
	// Maps without a non-empty fingerprint are silently skipped.
	in := []any{
		map[string]any{"fingerprint": "", "type": "X509-OV"},
		map[string]any{"type": "X509-OV-CLIENT"}, // missing fingerprint key
	}
	if got := extractCertFingerprints(in); got != nil {
		t.Errorf("expected nil when no entries have fingerprint; got %v", got)
	}
}

func TestExtractCertFingerprints_GoodAndBadMixed(t *testing.T) {
	in := []any{
		"non-map skipped",
		map[string]any{"fingerprint": "SHA256:abcd", "type": "X509-OV-CLIENT"},
		map[string]any{"fingerprint": "SHA256:efgh"}, // type empty, still kept
		map[string]any{"fingerprint": ""},            // skipped
	}
	got := extractCertFingerprints(in)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Fingerprint != "SHA256:abcd" || got[0].CertType != "X509-OV-CLIENT" {
		t.Errorf("entry[0]: %+v", got[0])
	}
	if got[1].Fingerprint != "SHA256:efgh" {
		t.Errorf("entry[1]: %+v", got[1])
	}
}

// ----- extractMetadataHashes -----

func TestExtractMetadataHashes_NotMap(t *testing.T) {
	if got := extractMetadataHashes("string-not-map"); got != nil {
		t.Errorf("expected nil for non-map; got %v", got)
	}
}

func TestExtractMetadataHashes_EmptyMap(t *testing.T) {
	if got := extractMetadataHashes(map[string]any{}); got != nil {
		t.Errorf("expected nil for empty map; got %v", got)
	}
}

func TestExtractMetadataHashes_NonStringValuesSkipped(t *testing.T) {
	in := map[string]any{
		"MCP": "SHA256:good",
		"A2A": 12345,    // not a string → skipped
		"AGB": "",       // empty string → skipped
		"BLD": []any{1}, // not a string → skipped
	}
	got := extractMetadataHashes(in)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got["MCP"] != "SHA256:good" {
		t.Errorf("MCP: got %q want SHA256:good", got["MCP"])
	}
}

func TestExtractMetadataHashes_AllNonStringYieldsNil(t *testing.T) {
	// After filtering, the resulting map is empty → nil per contract.
	in := map[string]any{"MCP": 42, "A2A": ""}
	if got := extractMetadataHashes(in); got != nil {
		t.Errorf("expected nil when all values invalid; got %v", got)
	}
}

// ----- buildStatusClaims edge cases -----

func TestBuildStatusClaims_MalformedJSONReturnsError(t *testing.T) {
	rec := &sqlitetl.EventRecord{
		AgentID:  "a-1",
		AnsName:  "ans://v1.0.0.a.example.com",
		RawEvent: "{not-json",
	}
	if _, err := buildStatusClaims(rec, "ACTIVE"); err == nil {
		t.Error("expected unmarshal error for malformed JSON")
	}
}

func TestBuildStatusClaims_MissingAttestationsStillSucceeds(t *testing.T) {
	// Pre-attestation events (e.g., PENDING_VALIDATION) carry no
	// attestation block. The claims should still build with just
	// AgentID + ANSName + Status.
	rec := &sqlitetl.EventRecord{
		AgentID: "a-1",
		AnsName: "ans://v1.0.0.a.example.com",
		// Bare envelope shell — drillAttestations returns nil.
		RawEvent: `{"payload":{"producer":{"event":{}}}}`,
	}
	got, err := buildStatusClaims(rec, "ACTIVE")
	if err != nil {
		t.Fatalf("buildStatusClaims: %v", err)
	}
	if got.AgentID != "a-1" {
		t.Errorf("AgentID: got %q", got.AgentID)
	}
	if got.Status != "ACTIVE" {
		t.Errorf("Status: got %q", got.Status)
	}
	if got.ValidIdentityCerts != nil {
		t.Errorf("ValidIdentityCerts should be nil; got %v", got.ValidIdentityCerts)
	}
}
