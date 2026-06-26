package service

// White-box unit tests for the identity envelope codec, including the
// cross-lane guards: agent-shaped bodies fail this codec's closed
// enum, and identity-shaped bodies fail the V1/V2 agent codecs — both
// directions reject with INVALID_EVENT before anything touches the
// tree.

import (
	"strings"
	"testing"
)

const validIdentityBody = `{
	"identityId":"01HXKQ00000000000000000000",
	"kind":"did:web",
	"value":"did:web:identity.acme-corp.com",
	"providerId":"PID-8294",
	"proofMethod":"did-web-sig",
	"eventType":"IDENTITY_VERIFIED",
	"keys":[{
		"verificationMethod":{
			"id":"did:web:identity.acme-corp.com#key-1",
			"type":"JsonWebKey2020",
			"controller":"did:web:identity.acme-corp.com",
			"publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"abc"}
		},
		"signedProof":"eyJhbGciOiJFZERTQSJ9.p.s"
	}],
	"verifiedAt":"2026-06-10T15:04:05Z",
	"raId":"ra-test",
	"timestamp":"2026-06-10T15:04:05Z"
}`

func TestIdentityCodec_ParseAndBuild_HappyPath(t *testing.T) {
	t.Parallel()
	env, canonical, err := identityCodec{}.ParseAndBuild(
		[]byte(validIdentityBody), "ra-test", "kid-1", "sig", "log-id")
	if err != nil {
		t.Fatalf("ParseAndBuild: %v", err)
	}
	if env == nil {
		t.Fatal("nil envelope")
	}
	if len(canonical) == 0 {
		t.Fatal("empty canonical bytes")
	}
	if env.EventType() != "IDENTITY_VERIFIED" {
		t.Fatalf("EventType = %q", env.EventType())
	}
}

func TestIdentityCodec_ParseAndBuild_BadJSON(t *testing.T) {
	t.Parallel()
	_, _, err := identityCodec{}.ParseAndBuild(
		[]byte("{not json"), "ra-test", "k", "s", "l")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestIdentityCodec_ParseAndBuild_RaidMismatch(t *testing.T) {
	t.Parallel()
	_, _, err := identityCodec{}.ParseAndBuild(
		[]byte(validIdentityBody), "ra-other", "k", "s", "l")
	if err == nil || !strings.Contains(err.Error(), "raId") {
		t.Fatalf("expected RAID_MISMATCH error, got %v", err)
	}
}

func TestIdentityCodec_ParseAndBuild_StampsBlankRAID(t *testing.T) {
	t.Parallel()
	body := strings.Replace(validIdentityBody, `"raId":"ra-test",`, "", 1)
	env, _, err := identityCodec{}.ParseAndBuild(
		[]byte(body), "ra-verified", "k", "s", "l")
	if err != nil {
		t.Fatalf("ParseAndBuild: %v", err)
	}
	if env == nil {
		t.Fatal("nil envelope")
	}
}

// TestIdentityCodec_RejectsAgentBody is one half of the cross-lane
// guard: a V2 agent event posted to the identity ingest lane fails
// the identity codec's closed enum + required identityId.
func TestIdentityCodec_RejectsAgentBody(t *testing.T) {
	t.Parallel()
	agentBody := []byte(`{
		"ansId":"10000000-0000-4000-8000-000000000001",
		"ansName":"ans://v1.0.0.agent.example.com",
		"eventType":"AGENT_REGISTERED",
		"timestamp":"2026-04-17T00:00:00Z"
	}`)
	_, _, err := identityCodec{}.ParseAndBuild(agentBody, "ra-test", "k", "s", "l")
	if err == nil {
		t.Fatal("agent body must fail the identity codec")
	}
	if !strings.Contains(err.Error(), "INVALID_EVENT") && !strings.Contains(err.Error(), "eventType") {
		t.Fatalf("expected INVALID_EVENT for agent body, got %v", err)
	}
}

// TestAgentCodecs_RejectIdentityBody is the other half: an identity
// event posted to either agent lane fails the agent codecs (unknown
// eventType for the closed agent enums + missing ansId).
func TestAgentCodecs_RejectIdentityBody(t *testing.T) {
	t.Parallel()
	if _, _, err := (v2Codec{}).ParseAndBuild(
		[]byte(validIdentityBody), "ra-test", "k", "s", "l"); err == nil {
		t.Fatal("identity body must fail the V2 agent codec")
	}
	if _, _, err := (v1Codec{}).ParseAndBuild(
		[]byte(validIdentityBody), "ra-test", "k", "s", "l"); err == nil {
		t.Fatal("identity body must fail the V1 agent codec — the V1 lane is frozen")
	}
}
