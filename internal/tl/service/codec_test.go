package service

// White-box unit tests for the V1/V2 envelope codecs. The integration
// tests through the TL handler hit the happy paths; this file pins
// the validation-error and raId-mismatch branches that pre-coverage
// stayed at 71.4%.

import (
	"strings"
	"testing"
)

// ----- v2Codec.ParseAndBuild -----

func TestV2Codec_ParseAndBuild_HappyPath(t *testing.T) {
	t.Parallel()
	c := v2Codec{}
	body := []byte(`{
		"ansId":"10000000-0000-4000-8000-000000000001",
		"ansName":"ans://v1.0.0.agent.example.com",
		"eventType":"AGENT_REGISTERED",
		"agent":{"host":"agent.example.com","name":"a","version":"1.0.0"},
		"raId":"ra-test",
		"issuedAt":"2026-04-17T00:00:00Z",
		"timestamp":"2026-04-17T00:00:00Z"
	}`)
	env, canonical, err := c.ParseAndBuild(body, "ra-test", "kid-1", "sig", "log-id")
	if err != nil {
		t.Fatalf("ParseAndBuild: %v", err)
	}
	if env == nil {
		t.Fatal("nil envelope")
	}
	if len(canonical) == 0 {
		t.Fatal("empty canonical bytes")
	}
}

func TestV2Codec_ParseAndBuild_BadJSON(t *testing.T) {
	t.Parallel()
	_, _, err := v2Codec{}.ParseAndBuild(
		[]byte("{not json"), "ra-test", "k", "s", "l")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestV2Codec_ParseAndBuild_ValidateFails(t *testing.T) {
	t.Parallel()
	// Missing required fields → Validate returns a non-nil error.
	body := []byte(`{}`)
	_, _, err := v2Codec{}.ParseAndBuild(body, "ra-test", "k", "s", "l")
	if err == nil {
		t.Error("expected validation error for empty event")
	}
}

func TestV2Codec_ParseAndBuild_RaidMismatch(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"ansId":"10000000-0000-4000-8000-000000000001",
		"ansName":"ans://v1.0.0.agent.example.com",
		"eventType":"AGENT_REGISTERED",
		"agent":{"host":"agent.example.com","name":"a","version":"1.0.0"},
		"raId":"ra-other",
		"issuedAt":"2026-04-17T00:00:00Z",
		"timestamp":"2026-04-17T00:00:00Z"
	}`)
	_, _, err := v2Codec{}.ParseAndBuild(body, "ra-test", "k", "s", "l")
	if err == nil {
		t.Fatal("expected RAID_MISMATCH error")
	}
	if !strings.Contains(err.Error(), "raId") {
		t.Errorf("error message: got %q, expected mention of raId", err.Error())
	}
}

func TestV2Codec_ParseAndBuild_StampsBlankRAID(t *testing.T) {
	t.Parallel()
	// Body with empty raId — codec stamps the verified value.
	body := []byte(`{
		"ansId":"10000000-0000-4000-8000-000000000001",
		"ansName":"ans://v1.0.0.agent.example.com",
		"eventType":"AGENT_REGISTERED",
		"agent":{"host":"agent.example.com","name":"a","version":"1.0.0"},
		"issuedAt":"2026-04-17T00:00:00Z",
		"timestamp":"2026-04-17T00:00:00Z"
	}`)
	env, canonical, err := v2Codec{}.ParseAndBuild(body, "ra-stamped", "k", "s", "l")
	if err != nil {
		t.Fatalf("ParseAndBuild: %v", err)
	}
	if env == nil || len(canonical) == 0 {
		t.Error("happy build with stamped raID failed")
	}
}

// ----- v1Codec.ParseAndBuild -----

func TestV1Codec_ParseAndBuild_HappyPath(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"ansId":"10000000-0000-4000-8000-000000000001",
		"ansName":"ans://v1.0.0.agent.example.com",
		"eventType":"AGENT_REGISTERED",
		"agent":{"host":"agent.example.com","name":"a","version":"1.0.0"},
		"raId":"ra-test",
		"issuedAt":"2026-04-17T00:00:00Z",
		"timestamp":"2026-04-17T00:00:00Z"
	}`)
	env, canonical, err := v1Codec{}.ParseAndBuild(body, "ra-test", "kid-1", "sig", "log-id")
	if err != nil {
		t.Fatalf("ParseAndBuild: %v", err)
	}
	if env == nil {
		t.Fatal("nil envelope")
	}
	if len(canonical) == 0 {
		t.Fatal("empty canonical bytes")
	}
}

func TestV1Codec_ParseAndBuild_BadJSON(t *testing.T) {
	t.Parallel()
	_, _, err := v1Codec{}.ParseAndBuild(
		[]byte("{not json"), "ra-test", "k", "s", "l")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestV1Codec_ParseAndBuild_ValidateFails(t *testing.T) {
	t.Parallel()
	body := []byte(`{}`)
	_, _, err := v1Codec{}.ParseAndBuild(body, "ra-test", "k", "s", "l")
	if err == nil {
		t.Error("expected validation error for empty V1 event")
	}
}

func TestV1Codec_ParseAndBuild_RaidMismatch(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"ansId":"10000000-0000-4000-8000-000000000001",
		"ansName":"ans://v1.0.0.agent.example.com",
		"eventType":"AGENT_REGISTERED",
		"agent":{"host":"agent.example.com","name":"a","version":"1.0.0"},
		"raId":"ra-other",
		"issuedAt":"2026-04-17T00:00:00Z",
		"timestamp":"2026-04-17T00:00:00Z"
	}`)
	_, _, err := v1Codec{}.ParseAndBuild(body, "ra-test", "k", "s", "l")
	if err == nil {
		t.Error("expected RAID_MISMATCH error in V1 codec")
	}
}

// ----- decodeB64 -----

func TestDecodeB64_StdHappyPath(t *testing.T) {
	t.Parallel()
	got, err := decodeB64("std", "aGVsbG8=") // "hello"
	if err != nil {
		t.Fatalf("decodeB64: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q want hello", got)
	}
}

func TestDecodeB64_URLHappyPath(t *testing.T) {
	t.Parallel()
	got, err := decodeB64("url", "aGVsbG8") // raw url-safe (no padding)
	if err != nil {
		t.Fatalf("decodeB64: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q want hello", got)
	}
}

func TestDecodeB64_StdUnpaddedFallback(t *testing.T) {
	t.Parallel()
	// "hello" without `=` padding — std-padded fails, raw-std succeeds.
	got, err := decodeB64("std", "aGVsbG8")
	if err != nil {
		t.Fatalf("decodeB64: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q want hello", got)
	}
}

func TestDecodeB64_URLPaddedFallback(t *testing.T) {
	t.Parallel()
	// "hello" with `=` padding — raw-url fails, padded url succeeds.
	got, err := decodeB64("url", "aGVsbG8=")
	if err != nil {
		t.Fatalf("decodeB64: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q want hello", got)
	}
}

func TestDecodeB64_UnknownFlavor(t *testing.T) {
	t.Parallel()
	if _, err := decodeB64("hex", "abcd"); err == nil {
		t.Error("expected error for unknown flavor")
	}
}

func TestDecodeB64_BadInput(t *testing.T) {
	t.Parallel()
	if _, err := decodeB64("std", "!!!not-base64!!!"); err == nil {
		t.Error("expected error for malformed base64")
	}
}
