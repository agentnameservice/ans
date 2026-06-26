package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var idNow = time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)

func newPendingIdentity(t *testing.T, value string) *VerifiedIdentity {
	t.Helper()
	v, err := NewVerifiedIdentity("01HXKQTEST", "PID-1", value, idNow)
	if err != nil {
		t.Fatalf("NewVerifiedIdentity(%s): %v", value, err)
	}
	return v
}

func TestInferIdentifierKind(t *testing.T) {
	cases := []struct {
		in            string
		wantKind      IdentifierKind
		wantCanonical string
		wantErr       string
	}{
		{in: "did:web:identity.acme-corp.com", wantKind: KindDIDWeb, wantCanonical: "did:web:identity.acme-corp.com"},
		{in: "  did:web:Identity.ACME-corp.COM  ", wantKind: KindDIDWeb, wantCanonical: "did:web:identity.acme-corp.com"},
		{in: "did:web:acme-corp.com:identity:agents", wantKind: KindDIDWeb, wantCanonical: "did:web:acme-corp.com:identity:agents"},
		{in: "did:key:zDnaeUm3QkcyZWZTPttxB711jgqRDhkwvhF485SFw1bDZ9AQw", wantKind: KindDIDKey, wantCanonical: "did:key:zDnaeUm3QkcyZWZTPttxB711jgqRDhkwvhF485SFw1bDZ9AQw"},
		{in: "5493001KJTIIGC8Y1R17", wantKind: KindLEI, wantCanonical: "5493001KJTIIGC8Y1R17"},
		{in: "5493001kjtiigc8y1r17", wantKind: KindLEI, wantCanonical: "5493001KJTIIGC8Y1R17"},
		{in: "did:web:", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:acme.com%3A8443", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:user@acme.com", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:acme.com/path", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:acme.com:", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:acme..com", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:-acme.com", wantErr: "DID_BAD_FORMAT"},
		{in: "did:web:acme_corp.com", wantErr: "DID_BAD_FORMAT"},
		{in: "did:key:", wantErr: "DID_BAD_FORMAT"},
		{in: "urn:uuid:1234", wantErr: "IDENTIFIER_KIND_UNSUPPORTED"},
		{in: "", wantErr: "IDENTIFIER_KIND_UNSUPPORTED"},
		{in: "5493001KJTIIGC8Y1R1!", wantErr: "IDENTIFIER_KIND_UNSUPPORTED"},
		// Unrecognized did methods name the method precisely —
		// these are the kinds the controlVerifier registry grows
		// into (did:plc, did:ion, did:ethr, …).
		{in: "did:plc:ewvi7nxzyoun6zhxrhs64oiz", wantErr: `did method "plc" is not supported`},
		{in: "did:ion:EiClkZMDxPKqC9c-umQfTkR8", wantErr: `did method "ion" is not supported`},
		{in: "did:bogus", wantErr: `did method "bogus" is not supported`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			kind, canonical, err := InferIdentifierKind(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kind != tc.wantKind || canonical != tc.wantCanonical {
				t.Fatalf("got (%s, %s), want (%s, %s)", kind, canonical, tc.wantKind, tc.wantCanonical)
			}
		})
	}
}

func TestValidateDNSHostEdges(t *testing.T) {
	longHost := strings.Repeat("a", 254)
	if _, _, err := InferIdentifierKind("did:web:" + longHost); err == nil {
		t.Error("over-long host should fail")
	}
	longLabel := strings.Repeat("a", 64) + ".com"
	if _, _, err := InferIdentifierKind("did:web:" + longLabel); err == nil {
		t.Error("over-long label should fail")
	}
	if _, _, err := InferIdentifierKind("did:web:acme-.com"); err == nil {
		t.Error("trailing-hyphen label should fail")
	}
}

func TestDIDWebResolutionURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "did:web:example.com", want: "https://example.com/.well-known/did.json"},
		{in: "did:web:example.com:user:alice", want: "https://example.com/user/alice/did.json"},
		{in: "did:key:z6Mk", wantErr: true},
		{in: "did:web:", wantErr: true},
	}
	for _, tc := range cases {
		got, err := DIDWebResolutionURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: want error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got (%s, %v), want %s", tc.in, got, err, tc.want)
		}
	}
}

func TestNewVerifiedIdentityValidation(t *testing.T) {
	if _, err := NewVerifiedIdentity("", "PID-1", "did:web:a.com", idNow); err == nil {
		t.Error("missing identityId should fail")
	}
	if _, err := NewVerifiedIdentity("id-1", "", "did:web:a.com", idNow); err == nil {
		t.Error("missing providerId should fail")
	}
	if _, err := NewVerifiedIdentity("id-1", "PID-1", "bogus", idNow); err == nil {
		t.Error("bogus value should fail")
	}
	v := newPendingIdentity(t, "did:web:a.com")
	if v.Status != IdentityPendingControl || v.Kind != KindDIDWeb {
		t.Fatalf("fresh identity wrong: %+v", v)
	}
}

func TestIssueAndCheckChallenge(t *testing.T) {
	v := newPendingIdentity(t, "did:web:a.com")

	if err := v.IssueChallenge("", time.Hour, idNow); err == nil {
		t.Error("empty nonce should fail")
	}
	if err := v.IssueChallenge("nonce-1", 0, idNow); err == nil {
		t.Error("zero ttl should fail")
	}
	if err := v.CheckChallenge(idNow); err == nil || !strings.Contains(err.Error(), "IDENTIFIER_CHALLENGE_EXPIRED") {
		t.Errorf("no challenge should report IDENTIFIER_CHALLENGE_EXPIRED, got %v", err)
	}

	if err := v.IssueChallenge("nonce-1", time.Hour, idNow); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := v.CheckChallenge(idNow.Add(30 * time.Minute)); err != nil {
		t.Errorf("fresh challenge should pass: %v", err)
	}
	if err := v.CheckChallenge(idNow.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "PRICC_TOKEN_EXPIRED") {
		t.Errorf("expired challenge: got %v", err)
	}

	consumed := idNow.Add(time.Minute)
	v.Challenge.ConsumedAt = &consumed
	if err := v.CheckChallenge(idNow.Add(2 * time.Minute)); err == nil || !strings.Contains(err.Error(), "PRICC_TOKEN_ALREADY_USED") {
		t.Errorf("consumed challenge: got %v", err)
	}

	// Re-issue supersedes (idempotent re-add).
	if err := v.IssueChallenge("nonce-2", time.Hour, idNow.Add(3*time.Minute)); err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	if v.Challenge.Nonce != "nonce-2" || v.Challenge.ConsumedAt != nil {
		t.Fatalf("re-issue did not supersede: %+v", v.Challenge)
	}

	// Revoked identities cannot be challenged.
	v.Status = IdentityRevoked
	if err := v.IssueChallenge("nonce-3", time.Hour, idNow); err == nil {
		t.Error("revoked identity should not be challengeable")
	}
}

func TestCompleteVerificationLifecycle(t *testing.T) {
	v := newPendingIdentity(t, "did:web:a.com")

	prev, err := v.CompleteVerification(idNow)
	if err != nil || prev != "" {
		t.Fatalf("first proof: prev=%q err=%v", prev, err)
	}
	if v.Status != IdentityVerified || v.ProofMethod != "did-web-sig" || v.VerifiedAt.IsZero() {
		t.Fatalf("after first proof: %+v", v)
	}

	// Re-proof without rotation: same value, no previousValue.
	prev, err = v.CompleteVerification(idNow.Add(time.Hour))
	if err != nil || prev != "" {
		t.Fatalf("re-proof: prev=%q err=%v", prev, err)
	}

	// Rotation to a new value.
	if err := v.StageRotation("did:web:b.com", idNow); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if v.EffectiveValue() != "did:web:b.com" || v.Value != "did:web:a.com" {
		t.Fatalf("staged state wrong: %+v", v)
	}
	prev, err = v.CompleteVerification(idNow.Add(2 * time.Hour))
	if err != nil || prev != "did:web:a.com" {
		t.Fatalf("rotation: prev=%q err=%v", prev, err)
	}
	if v.Value != "did:web:b.com" || v.PendingValue != "" {
		t.Fatalf("after rotation: %+v", v)
	}

	// Rotation staged to the SAME value: no previousValue reported.
	if err := v.StageRotation("did:web:b.com", idNow); err != nil {
		t.Fatalf("stage same: %v", err)
	}
	prev, err = v.CompleteVerification(idNow.Add(3 * time.Hour))
	if err != nil || prev != "" {
		t.Fatalf("same-value rotation: prev=%q err=%v", prev, err)
	}

	// Revoked → cannot verify.
	v.Status = IdentityRevoked
	if _, err := v.CompleteVerification(idNow); err == nil {
		t.Error("revoked identity should not verify")
	}

	// Unknown status → invalid state.
	v.Status = IdentityStatus("BOGUS")
	if _, err := v.CompleteVerification(idNow); err == nil {
		t.Error("unknown status should not verify")
	}
}

func TestStageRotationGuards(t *testing.T) {
	v := newPendingIdentity(t, "did:web:a.com")
	if err := v.StageRotation("did:web:b.com", idNow); err == nil {
		t.Error("rotation requires VERIFIED")
	}
	if _, err := v.CompleteVerification(idNow); err != nil {
		t.Fatal(err)
	}
	if err := v.StageRotation("bogus", idNow); err == nil {
		t.Error("bogus replacement should fail")
	}
	if err := v.StageRotation("did:key:zDnaeUm3QkcyZWZTPttxB711jgqRDhkwvhF485SFw1bDZ9AQw", idNow); err == nil ||
		!strings.Contains(err.Error(), "IDENTIFIER_KIND_MISMATCH") {
		t.Errorf("cross-kind rotation: got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	v := newPendingIdentity(t, "did:web:a.com")
	if err := v.Revoke(idNow); err == nil {
		t.Error("revoking PENDING_CONTROL should fail — nothing was sealed")
	}
	if _, err := v.CompleteVerification(idNow); err != nil {
		t.Fatal(err)
	}
	if err := v.IssueChallenge("n", time.Hour, idNow); err != nil {
		t.Fatal(err)
	}
	if err := v.Revoke(idNow.Add(time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if v.Status != IdentityRevoked || v.Challenge != nil || v.PendingValue != "" {
		t.Fatalf("after revoke: %+v", v)
	}
	if err := v.Revoke(idNow); err == nil {
		t.Error("double revoke should fail")
	}
}

func TestProofMethodForKind(t *testing.T) {
	cases := map[IdentifierKind]string{
		KindDIDWeb:            "did-web-sig",
		KindDIDKey:            "did-key-sig",
		KindLEI:               "lei-vlei-acdc",
		IdentifierKind("???"): "",
	}
	for kind, want := range cases {
		if got := ProofMethodForKind(kind); got != want {
			t.Errorf("ProofMethodForKind(%s) = %q, want %q", kind, got, want)
		}
	}
}

func TestEffectiveValueWithoutPending(t *testing.T) {
	v := newPendingIdentity(t, "did:web:a.com")
	if v.EffectiveValue() != "did:web:a.com" {
		t.Fatal("effective value should be the proven value when nothing is staged")
	}
}

// TestInferIdentifierKind_DIDWebSegmentRejections pins the §3.6
// per-segment rejection list: '.', '..', and control characters are
// DID_BAD_FORMAT (empty segments, '%', '@', '/', and ports are pinned
// by the existing grammar tests).
func TestInferIdentifierKind_DIDWebSegmentRejections(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"did:web:acme-corp.com:.",
		"did:web:acme-corp.com:..",
		"did:web:acme-corp.com:..:identity",
		"did:web:acme-corp.com:iden\x00tity",
		"did:web:acme-corp.com:iden\ttity",
	} {
		_, _, err := InferIdentifierKind(value)
		var de *Error
		if !errors.As(err, &de) || de.Code != "DID_BAD_FORMAT" {
			t.Fatalf("%q: want DID_BAD_FORMAT, got %v", value, err)
		}
	}

	// Sane multi-segment forms still canonicalize.
	kind, canonical, err := InferIdentifierKind("did:web:Acme-Corp.com:user:alice")
	if err != nil || kind != KindDIDWeb || canonical != "did:web:acme-corp.com:user:alice" {
		t.Fatalf("multi-segment: %v %v %v", kind, canonical, err)
	}
}
