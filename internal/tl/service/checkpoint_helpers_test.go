package service

import (
	"encoding/base64"
	"encoding/binary"
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

// ----- splitNoteBody -----

func TestSplitNoteBody_SingleSumdbSig(t *testing.T) {
	t.Parallel()
	// Construct a sumdb-note-style body.
	// 4 keyhash bytes + 64-byte-ish ed25519 sig.
	sigBytes := make([]byte, 4+64)
	binary.BigEndian.PutUint32(sigBytes[:4], 0xdeadbeef)
	// Fill the signature with some bytes — not validated here.
	for i := 4; i < len(sigBytes); i++ {
		sigBytes[i] = byte(i)
	}
	b64Sig := base64.StdEncoding.EncodeToString(sigBytes)
	note := "ans-demo\n5\nhashhex\n\n\u2014 ans-demo " + b64Sig + "\n"

	body, sigs := splitNoteBody(note, "ans-demo")
	if !strings.Contains(body, "ans-demo") {
		t.Errorf("body should include header: %q", body)
	}
	if len(sigs) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigs))
	}
	s := sigs[0]
	if s.SignerName != "ans-demo" {
		t.Errorf("signer: got %q", s.SignerName)
	}
	if s.SignatureType != "c2sp" || s.Algorithm != "ES256" {
		t.Errorf("type/alg: got %s/%s, want c2sp/ES256", s.SignatureType, s.Algorithm)
	}
	if s.KeyHash != "0xdeadbeef" {
		t.Errorf("keyhash: got %q, want 0xdeadbeef", s.KeyHash)
	}
}

func TestSplitNoteBody_NoSeparatorReturnsFullTextNoSigs(t *testing.T) {
	body, sigs := splitNoteBody("header only", "origin")
	if body != "header only" {
		t.Errorf("body: got %q", body)
	}
	if sigs != nil {
		t.Errorf("sigs should be nil when no separator: %v", sigs)
	}
}

func TestSplitNoteBody_JWSClassification(t *testing.T) {
	// JWS sig: 4 keyhash bytes + bytes starting with base64("{\"alg\":").
	raw := make([]byte, 0, 4+10+20)
	raw = append(raw, 0x01, 0x02, 0x03, 0x04)  // keyhash
	raw = append(raw, []byte("eyJhbGciOi")...) // JWS marker
	raw = append(raw, make([]byte, 20)...)     // padding
	b64 := base64.StdEncoding.EncodeToString(raw)
	note := "origin\n\n\u2014 origin " + b64 + "\n"

	_, sigs := splitNoteBody(note, "origin")
	if len(sigs) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigs))
	}
	if sigs[0].SignatureType != "jws" || sigs[0].Algorithm != "ES256" {
		t.Errorf("want jws/ES256, got %s/%s", sigs[0].SignatureType, sigs[0].Algorithm)
	}
}

func TestSplitNoteBody_SkipsMalformedLines(t *testing.T) {
	note := "origin\n\n" +
		"not a sig line\n" +
		"\u2014 without-sig-segment\n" + // missing base64 part
		"\u2014 name " + base64.StdEncoding.EncodeToString(make([]byte, 4+32)) + "\n"
	_, sigs := splitNoteBody(note, "origin")
	if len(sigs) != 1 {
		t.Errorf("want 1 valid sig after filtering malformed, got %d", len(sigs))
	}
}

// ----- keyhashFromSumdbSig -----

func TestKeyhashFromSumdbSig(t *testing.T) {
	t.Parallel()
	// Construct a sig with known keyhash bytes. Production emits the
	// keyhash with a `0x` prefix, matching what verifiers compare
	// against the header `kid` and the /root-keys entry.
	raw := []byte{0x12, 0x34, 0x56, 0x78, 0x99, 0x00, 0x00}
	b64 := base64.StdEncoding.EncodeToString(raw)
	if got := keyhashFromSumdbSig(b64); got != "0x12345678" {
		t.Errorf("got %q, want 0x12345678", got)
	}
}

func TestKeyhashFromSumdbSig_BadBase64(t *testing.T) {
	if got := keyhashFromSumdbSig("!!!"); got != "" {
		t.Errorf("bad base64: got %q, want empty", got)
	}
}

func TestKeyhashFromSumdbSig_TooShort(t *testing.T) {
	// 3 bytes < 4-byte prefix.
	b64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	if got := keyhashFromSumdbSig(b64); got != "" {
		t.Errorf("too-short: got %q, want empty", got)
	}
}

// ----- classifySumdbSig -----

func TestClassifySumdbSig_DefaultC2SP(t *testing.T) {
	t.Parallel()
	// Enough bytes, no JWS marker → c2sp.
	raw := make([]byte, 4+64)
	b64 := base64.StdEncoding.EncodeToString(raw)
	if sigType := classifySumdbSig(b64); sigType != "c2sp" {
		t.Errorf("got %s, want c2sp", sigType)
	}
}

func TestClassifySumdbSig_ShortOrBadReturnsDefault(t *testing.T) {
	// Too short → default (no classification possible).
	if st := classifySumdbSig("AA=="); st != "c2sp" {
		t.Errorf("short: got %s", st)
	}
	if st := classifySumdbSig("!!!"); st != "c2sp" {
		t.Errorf("bad b64: got %s", st)
	}
}
