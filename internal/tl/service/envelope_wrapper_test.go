package service

import (
	"fmt"
	"testing"
	"time"
)

// The wrapper parser is the schema-agnostic boundary the badge/audit
// read path depends on — it must stay tolerant of both V1 and V2
// payload shapes (which differ in the inner `event` block) and must
// refuse malformed JSON at the outer layer.

func TestParseEnvelopeWrapper_V2Shape(t *testing.T) {
	t.Parallel()
	// V2 attestations use unified `identityCerts[]` / `serverCerts[]`
	// arrays. The wrapper parses notAfter out of both and the badge
	// uses the earlier family expiry for its WARNING/EXPIRED derivation.
	raw := `{
		"payload": {
			"logId": "log-1",
			"producer": {
				"event": {
					"ansId": "agent-a",
					"ansName": "ans://v1.0.0.a.example.com",
					"eventType": "AGENT_REGISTERED",
					"timestamp": "2026-04-17T00:00:00Z",
					"attestations": {
						"identityCerts": [
							{"fingerprint":"SHA256:aaa","notAfter":"2027-04-17T00:00:00Z"}
						],
						"serverCerts": [
							{"fingerprint":"SHA256:bbb","notAfter":"2027-01-01T00:00:00Z"}
						]
					}
				},
				"keyId": "kid-1",
				"signature": "producer-sig"
			}
		},
		"schemaVersion": "V2",
		"signature": "tl-attest",
		"status": "VALID"
	}`
	w, err := parseEnvelopeWrapper(raw)
	if err != nil {
		t.Fatalf("parseEnvelopeWrapper: %v", err)
	}
	if w.SchemaVersion != "V2" {
		t.Errorf("SchemaVersion: got %q", w.SchemaVersion)
	}
	if w.Signature != "tl-attest" {
		t.Errorf("Signature: got %q", w.Signature)
	}
	if w.Status != "VALID" {
		t.Errorf("Status: got %q", w.Status)
	}
	if len(w.Payload) == 0 {
		t.Fatal("Payload should be retained as opaque JSON")
	}
	// min(identity=2027-04, server=2027-01) = 2027-01.
	want, _ := time.Parse(time.RFC3339, "2027-01-01T00:00:00Z")
	if got := w.certExpiresAt(); !got.Equal(want) {
		t.Errorf("certExpiresAt: got %v, want %v", got, want)
	}
}

func TestParseEnvelopeWrapper_V1Shape(t *testing.T) {
	t.Parallel()
	// V1 uses singleton `identityCert` / `serverCert` + rotation
	// arrays. The rotation array takes precedence over the singleton.
	raw := `{
		"payload": {
			"logId": "log-1",
			"producer": {
				"event": {
					"ansId": "agent-b",
					"ansName": "ans://v1.0.0.b.example.com",
					"eventType": "AGENT_REGISTERED",
					"timestamp": "2026-04-17T00:00:00Z",
					"attestations": {
						"identityCert": {"fingerprint":"SHA256:aaa","notAfter":"2028-01-01T00:00:00Z"},
						"validIdentityCerts": [
							{"fingerprint":"SHA256:aaa","notAfter":"2028-01-01T00:00:00Z"}
						]
					}
				},
				"keyId": "kid-1",
				"signature": "producer-sig"
			}
		},
		"schemaVersion": "V1",
		"signature": "tl-attest"
	}`
	w, err := parseEnvelopeWrapper(raw)
	if err != nil {
		t.Fatalf("parseEnvelopeWrapper: %v", err)
	}
	if w.SchemaVersion != "V1" {
		t.Errorf("SchemaVersion: got %q", w.SchemaVersion)
	}
	if w.Status != "" {
		t.Errorf("Status: expected empty, got %q", w.Status)
	}
	want, _ := time.Parse(time.RFC3339, "2028-01-01T00:00:00Z")
	if got := w.certExpiresAt(); !got.Equal(want) {
		t.Errorf("certExpiresAt: got %v, want %v", got, want)
	}
}

func TestEnvelopeWrapper_CertificateOverlapUsesLatestInEachFamily(t *testing.T) {
	for _, fields := range [][2]string{
		{"identityCerts", "serverCerts"},
		{"validIdentityCerts", "validServerCerts"},
		{"serverCerts", "identityCerts"},
		{"validServerCerts", "validIdentityCerts"},
	} {
		t.Run(fields[0], func(t *testing.T) {
			raw := fmt.Sprintf(`{"payload":{"producer":{"event":{"attestations":{
				"identityCert":{"notAfter":"2030-01-01T00:00:00Z"},
				"serverCert":{"notAfter":"2030-01-01T00:00:00Z"},
				%q:[{"notAfter":"2027-10-01T00:00:00Z"},{"notAfter":"2027-12-01T00:00:00Z"}],
				%q:[{"notAfter":"2026-12-01T00:00:00Z"},{"notAfter":"2027-01-01T00:00:00Z"}]
			}}}}}`, fields[0], fields[1])
			w, err := parseEnvelopeWrapper(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
			if got := w.certExpiresAt(); !got.Equal(want) {
				t.Fatalf("overlap expires at %v, want %v", got, want)
			}
		})
	}
}

func TestParseEnvelopeWrapper_Malformed(t *testing.T) {
	t.Parallel()
	if _, err := parseEnvelopeWrapper("{ not json"); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestEnvelopeWrapper_CertExpiresAt_MissingPaths(t *testing.T) {
	t.Parallel()
	// Every intermediate path element can be missing without panicking.
	cases := []string{
		`{"payload":{}}`,                        // no producer
		`{"payload":{"producer":{}}}`,           // no event
		`{"payload":{"producer":{"event":{}}}}`, // event without attestations
		`{"payload":{"producer":{"event":{"attestations":{}}}}}`,
		`{}`,
	}
	for _, raw := range cases {
		w, err := parseEnvelopeWrapper(raw)
		if err != nil {
			t.Fatalf("parseEnvelopeWrapper(%q): %v", raw, err)
		}
		if got := w.certExpiresAt(); !got.IsZero() {
			t.Errorf("certExpiresAt(%q): got %v, want zero", raw, got)
		}
	}
}

func TestEnvelopeWrapper_CertExpiresAt_MalformedPayload(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		`{"payload":"not-an-object"}`,
		`{"payload":{"producer":{"event":{"attestations":{"identityCerts":[{"notAfter":"invalid"}]}}}}}`,
		`{"payload":{"producer":{"event":{"attestations":{"validServerCerts":[{"notAfter":"invalid"}]}}}}}`,
	} {
		if _, err := parseEnvelopeWrapper(raw); err == nil {
			t.Fatalf("malformed certificate evidence accepted: %s", raw)
		}
	}
}
