package service

import (
	"encoding/base64"
	"strings"
	"testing"
)

// ----- treeHeight -----

func TestTreeHeight(t *testing.T) {
	t.Parallel()
	cases := []struct {
		size uint64
		want int
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 2}, // ceil(log2(3))
		{4, 2},
		{5, 3},
		{8, 3},
		{9, 4},
		{1024, 10},
	}
	for _, tc := range cases {
		if got := treeHeight(tc.size); got != tc.want {
			t.Errorf("treeHeight(%d): got %d, want %d", tc.size, got, tc.want)
		}
	}
}

// ----- checkpointSignatureViews -----
//
// The exhaustive note-parsing cases (lenient tokenization, keyhash hex
// layering, c2sp/jws classification, malformed-line skipping) live in
// the internal/lognote package tests. These smoke tests only confirm
// the service-layer mapping on top of lognote.SplitNote: the "0x"
// keyhash prefix, the origin fallback for an empty signer name, the
// ES256 algorithm label, and the no-separator short-circuit.

func TestCheckpointSignatureViews_SingleC2SP(t *testing.T) {
	t.Parallel()
	// 4 keyhash bytes followed by an ASN.1-DER-shaped (non-JWS) blob.
	sigBytes := []byte{
		0xde, 0xad, 0xbe, 0xef,
		0x30, 0x06,
		0x02, 0x01, 0x01,
		0x02, 0x01, 0x02,
	}
	b64 := base64.StdEncoding.EncodeToString(sigBytes)
	note := "ans-demo\n5\nhashhex\n\n— ans-demo " + b64 + "\n"

	body, sigs := checkpointSignatureViews(note, "ans-demo")
	if !strings.Contains(body, "ans-demo") {
		t.Errorf("body should include header: %q", body)
	}
	if len(sigs) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigs))
	}
	s := sigs[0]
	if s.SignerName != "ans-demo" {
		t.Errorf("signer: got %q, want ans-demo", s.SignerName)
	}
	if s.SignatureType != "c2sp" || s.Algorithm != "ES256" {
		t.Errorf("type/alg: got %s/%s, want c2sp/ES256", s.SignatureType, s.Algorithm)
	}
	if s.KeyHash != "0xdeadbeef" {
		t.Errorf("keyhash: got %q, want 0xdeadbeef", s.KeyHash)
	}
	if s.RawSignature != b64 {
		t.Errorf("rawSignature: got %q, want %q", s.RawSignature, b64)
	}
}

func TestCheckpointSignatureViews_JWSClassification(t *testing.T) {
	t.Parallel()
	// 4 keyhash bytes + the JWS marker base64("{\"alg\":") + padding.
	raw := make([]byte, 0, 4+10+20)
	raw = append(raw, 0x01, 0x02, 0x03, 0x04)
	raw = append(raw, []byte("eyJhbGciOi")...)
	raw = append(raw, make([]byte, 20)...)
	b64 := base64.StdEncoding.EncodeToString(raw)
	note := "origin\n\n— origin " + b64 + "\n"

	_, sigs := checkpointSignatureViews(note, "origin")
	if len(sigs) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigs))
	}
	if sigs[0].SignatureType != "jws" || sigs[0].Algorithm != "ES256" {
		t.Errorf("want jws/ES256, got %s/%s", sigs[0].SignatureType, sigs[0].Algorithm)
	}
}

func TestCheckpointSignatureViews_NoSeparatorReturnsRawNoSigs(t *testing.T) {
	t.Parallel()
	body, sigs := checkpointSignatureViews("header only", "origin")
	if body != "header only" {
		t.Errorf("body: got %q, want %q", body, "header only")
	}
	if sigs != nil {
		t.Errorf("sigs should be nil when no separator: %v", sigs)
	}
}

func TestCheckpointSignatureViews_SeparatorButNoSigs(t *testing.T) {
	t.Parallel()
	body, sigs := checkpointSignatureViews("origin\n5\nrh\n\n", "origin")
	if body != "origin\n5\nrh\n" {
		t.Errorf("body: got %q, want %q", body, "origin\n5\nrh\n")
	}
	if sigs != nil {
		t.Errorf("sigs should be nil when no signature lines: %v", sigs)
	}
}

func TestCheckpointSignatureViews_EmptyNameFallsBackToOrigin(t *testing.T) {
	t.Parallel()
	// A signature line whose name segment is empty: "—  <base64>"
	// (em-dash, space, empty name token, space, base64). After stripping
	// the "— " prefix the remainder is " <base64>"; LastIndex(" ")
	// puts an empty string before the blob, so the view's signer name is
	// empty and must fall back to the origin.
	b64 := base64.StdEncoding.EncodeToString(make([]byte, 4+32))
	note := "origin\n1\nrh\n\n—  " + b64 + "\n"
	_, sigs := checkpointSignatureViews(note, "fallback-origin")
	if len(sigs) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigs))
	}
	if sigs[0].SignerName != "fallback-origin" {
		t.Errorf("signer: got %q, want fallback-origin", sigs[0].SignerName)
	}
}
