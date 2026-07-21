package lognote_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/lognote"
)

// ----- Signature.KeyHash / KeyHashHex (keyhash hex layering) -----

func TestSignatureKeyHash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		blob     []byte
		wantHash uint32
		wantOK   bool
		wantHex  string
	}{
		{
			name:     "four byte prefix",
			blob:     []byte{0x12, 0x34, 0x56, 0x78, 0x99, 0x00},
			wantHash: 0x12345678,
			wantOK:   true,
			wantHex:  "12345678",
		},
		{
			name:     "exactly four bytes",
			blob:     []byte{0xde, 0xad, 0xbe, 0xef},
			wantHash: 0xdeadbeef,
			wantOK:   true,
			wantHex:  "deadbeef",
		},
		{
			name:     "leading zero keyhash zero-pads to eight hex chars",
			blob:     []byte{0x00, 0x00, 0x00, 0x01, 0xaa},
			wantHash: 0x00000001,
			wantOK:   true,
			wantHex:  "00000001",
		},
		{
			name:    "three bytes is too short",
			blob:    []byte{0x01, 0x02, 0x03},
			wantOK:  false,
			wantHex: "",
		},
		{
			name:    "nil blob",
			blob:    nil,
			wantOK:  false,
			wantHex: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig := lognote.Signature{Blob: tc.blob}
			gotHash, gotOK := sig.KeyHash()
			if gotOK != tc.wantOK {
				t.Fatalf("KeyHash ok: got %v, want %v", gotOK, tc.wantOK)
			}
			if gotOK && gotHash != tc.wantHash {
				t.Errorf("KeyHash: got 0x%08x, want 0x%08x", gotHash, tc.wantHash)
			}
			if gotHex := sig.KeyHashHex(); gotHex != tc.wantHex {
				t.Errorf("KeyHashHex: got %q, want %q", gotHex, tc.wantHex)
			}
		})
	}
}

// ----- Signature.Body (length guards ≥4) -----

func TestSignatureBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		blob []byte
		want []byte
	}{
		{"keyhash plus body", []byte{0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb}, []byte{0xaa, 0xbb}},
		{"keyhash only", []byte{0x01, 0x02, 0x03, 0x04}, []byte{}},
		{"shorter than keyhash", []byte{0x01, 0x02}, nil},
		{"nil", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig := lognote.Signature{Blob: tc.blob}
			got := sig.Body()
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Body: got %x, want %x", got, tc.want)
			}
		})
	}
}

// ----- Signature.Classify (length guard ≥14, prefix eyJhbGciOi) -----

func TestSignatureClassify(t *testing.T) {
	t.Parallel()

	jwsBlob := func() []byte {
		b := make([]byte, 0, 4+10+10)
		b = append(b, 0x01, 0x02, 0x03, 0x04)  // keyhash
		b = append(b, []byte("eyJhbGciOi")...) // JWS marker (exactly 10 bytes)
		b = append(b, make([]byte, 10)...)
		return b
	}()
	jwsBlobMinimal := func() []byte {
		// Exactly 14 bytes: 4 keyhash + 10-byte JWS marker, nothing more.
		b := make([]byte, 0, 14)
		b = append(b, 0x01, 0x02, 0x03, 0x04)
		b = append(b, []byte("eyJhbGciOi")...)
		return b
	}()

	cases := []struct {
		name string
		blob []byte
		want lognote.SigType
	}{
		{"der ecdsa is c2sp", []byte{0x01, 0x02, 0x03, 0x04, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00}, lognote.SigTypeC2SP},
		{"jws marker is jws", jwsBlob, lognote.SigTypeJWS},
		{"jws marker at exact minimum length", jwsBlobMinimal, lognote.SigTypeJWS},
		{"thirteen bytes too short for jws check defaults c2sp", make([]byte, 13), lognote.SigTypeC2SP},
		{"empty defaults c2sp", nil, lognote.SigTypeC2SP},
		{"keyhash only defaults c2sp", []byte{0x01, 0x02, 0x03, 0x04}, lognote.SigTypeC2SP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig := lognote.Signature{Blob: tc.blob}
			if got := sig.Classify(); got != tc.want {
				t.Errorf("Classify: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSigTypeString(t *testing.T) {
	t.Parallel()
	if lognote.SigTypeC2SP.String() != "c2sp" {
		t.Errorf("SigTypeC2SP: got %q, want c2sp", lognote.SigTypeC2SP.String())
	}
	if lognote.SigTypeJWS.String() != "jws" {
		t.Errorf("SigTypeJWS: got %q, want jws", lognote.SigTypeJWS.String())
	}
}

// ----- SplitNote (lenient tokenization; found semantics) -----

func TestSplitNote(t *testing.T) {
	t.Parallel()

	derBlob := []byte{0xde, 0xad, 0xbe, 0xef, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	b64DER := base64.StdEncoding.EncodeToString(derBlob)

	cases := []struct {
		name      string
		raw       string
		wantFound bool
		wantBody  string
		wantSigs  []lognote.Signature
	}{
		{
			name:      "single signature",
			raw:       "ans-demo\n5\nrootb64\n\n— ans-demo " + b64DER + "\n",
			wantFound: true,
			wantBody:  "ans-demo\n5\nrootb64\n",
			wantSigs: []lognote.Signature{
				{Name: "ans-demo", Raw: b64DER, Blob: derBlob},
			},
		},
		{
			name:      "missing separator yields found false and full text",
			raw:       "header only no separator",
			wantFound: false,
			wantBody:  "header only no separator",
			wantSigs:  nil,
		},
		{
			// The separator is the LITERAL "\n\n"; a CRLF-separated
			// note ("\r\n\r\n") never contains it, so found=false and
			// the whole input is returned as body. Pins the separator
			// contract against CRLF-normalized inputs.
			name:      "crlf separator is not the literal lf-lf separator",
			raw:       "origin\r\n1\r\nrh\r\n\r\n— origin AAAAAA==\r\n",
			wantFound: false,
			wantBody:  "origin\r\n1\r\nrh\r\n\r\n— origin AAAAAA==\r\n",
			wantSigs:  nil,
		},
		{
			name:      "separator present but no signature lines",
			raw:       "ans-demo\n5\nrootb64\n\n",
			wantFound: true,
			wantBody:  "ans-demo\n5\nrootb64\n",
			wantSigs:  nil,
		},
		{
			name: "skips non-signature and malformed lines",
			raw: "origin\n\n" +
				"not a signature line\n" +
				"— missing-base64-segment\n" +
				"— name " + base64.StdEncoding.EncodeToString(make([]byte, 4+32)) + "\n",
			wantFound: true,
			wantBody:  "origin\n",
			wantSigs: []lognote.Signature{
				{
					Name: "name",
					Raw:  base64.StdEncoding.EncodeToString(make([]byte, 4+32)),
					Blob: make([]byte, 4+32),
				},
			},
		},
		{
			name:      "bad base64 in signature line is skipped",
			raw:       "origin\n\n— name !!!not-base64!!!\n",
			wantFound: true,
			wantBody:  "origin\n",
			wantSigs:  nil,
		},
		{
			name: "two signature lines both parsed",
			raw: "origin\n1\nrh\n\n" +
				"— origin " + b64DER + "\n" +
				"— origin " + base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}) + "\n",
			wantFound: true,
			wantBody:  "origin\n1\nrh\n",
			wantSigs: []lognote.Signature{
				{Name: "origin", Raw: b64DER, Blob: derBlob},
				{
					Name: "origin",
					Raw:  base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}),
					Blob: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, sigs, found := lognote.SplitNote([]byte(tc.raw))
			if found != tc.wantFound {
				t.Fatalf("found: got %v, want %v", found, tc.wantFound)
			}
			if string(body) != tc.wantBody {
				t.Errorf("body: got %q, want %q", body, tc.wantBody)
			}
			if len(sigs) != len(tc.wantSigs) {
				t.Fatalf("sig count: got %d, want %d (%+v)", len(sigs), len(tc.wantSigs), sigs)
			}
			for i := range sigs {
				if sigs[i].Name != tc.wantSigs[i].Name {
					t.Errorf("sig[%d].Name: got %q, want %q", i, sigs[i].Name, tc.wantSigs[i].Name)
				}
				if sigs[i].Raw != tc.wantSigs[i].Raw {
					t.Errorf("sig[%d].Raw: got %q, want %q", i, sigs[i].Raw, tc.wantSigs[i].Raw)
				}
				if !bytes.Equal(sigs[i].Blob, tc.wantSigs[i].Blob) {
					t.Errorf("sig[%d].Blob: got %x, want %x", i, sigs[i].Blob, tc.wantSigs[i].Blob)
				}
			}
		})
	}
}

// SplitNote signer-name fallback to origin is the view layer's job, not
// SplitNote's — SplitNote leaves Name empty when the line has no name
// segment. A "— token" line (em-dash, space, single token) is dropped:
// the "— " prefix consumes the only space, leaving "token" with no
// internal space, so LastIndex(" ") returns -1 and the line is treated
// as malformed (no name/signature split). This pins that LastIndex
// split — a single post-prefix token never yields a signature.
func TestSplitNoteSingleTokenAfterDashIsSkipped(t *testing.T) {
	t.Parallel()
	// "— token" — em-dash, space, one token. After stripping the
	// "— " prefix we have "token"; LastIndex(" ") = -1, so the line is
	// malformed (no name/sig split) and dropped.
	raw := []byte("origin\n\n— token\n")
	_, sigs, found := lognote.SplitNote(raw)
	if !found {
		t.Fatal("found: got false, want true")
	}
	if len(sigs) != 0 {
		t.Fatalf("want 0 sigs for single-token line, got %d", len(sigs))
	}
}

// CRLF tolerance is line-level: the body/signature separator is the
// literal "\n\n" (matching golang.org/x/mod/sumdb/note), but a stray
// trailing "\r" on a signature line must not defeat parsing — TrimSpace
// strips it before the prefix check and the LastIndex split. This pins
// that a CR on the signature line is tolerated while the body uses LF.
func TestSplitNoteCRLFOnSignatureLine(t *testing.T) {
	t.Parallel()
	blob := []byte{0x01, 0x02, 0x03, 0x04, 0xaa}
	b64 := base64.StdEncoding.EncodeToString(blob)
	raw := []byte("origin\n1\nrh\n\n— origin " + b64 + "\r\n")
	body, sigs, found := lognote.SplitNote(raw)
	if !found {
		t.Fatal("found: got false, want true")
	}
	if string(body) != "origin\n1\nrh\n" {
		t.Errorf("body: got %q, want %q", body, "origin\n1\nrh\n")
	}
	if len(sigs) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigs))
	}
	if sigs[0].Name != "origin" {
		t.Errorf("name: got %q, want origin", sigs[0].Name)
	}
	if !bytes.Equal(sigs[0].Blob, blob) {
		t.Errorf("blob: got %x, want %x", sigs[0].Blob, blob)
	}
}

// ----- VerifyCheckpointNote happy path (golden note signed over real
// bytes with a real ECDSA key) -----

func TestVerifyCheckpointNoteHappyPath(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	khex := keyHashHex(t, &priv.PublicKey)
	rootHash := sha256.Sum256([]byte("synthetic root"))
	note := signCheckpoint(t, priv, "demo.example", 42, rootHash[:])

	cp, err := lognote.VerifyCheckpointNote(note, map[string]*ecdsa.PublicKey{khex: &priv.PublicKey})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cp.Origin != "demo.example" {
		t.Errorf("origin: got %q, want demo.example", cp.Origin)
	}
	if cp.Size != 42 {
		t.Errorf("size: got %d, want 42", cp.Size)
	}
	if !bytes.Equal(cp.RootHash, rootHash[:]) {
		t.Errorf("rootHash mismatch")
	}
}

// The signed body INCLUDES its trailing newline (signed-note spec). A
// golden note signed over real bytes is the only way to prove the
// verifier hashes exactly raw[:sep+1] and not raw[:sep]. We sign the
// real body, then confirm verification against the same key succeeds
// and that flipping the trailing-newline boundary breaks it.
func TestVerifyCheckpointNoteTrailingNewlineSignedBody(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	rootHash := sha256.Sum256([]byte("rh"))

	body := []byte(fmt.Sprintf("demo.example\n7\n%s\n",
		base64.StdEncoding.EncodeToString(rootHash[:])))
	// Sign EXACTLY the body bytes (including the trailing \n).
	digest := sha256.Sum256(body)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	blob := append(keyHash4(t, &priv.PublicKey), der...)
	note := append(append(body, '\n'),
		[]byte("— demo.example "+base64.StdEncoding.EncodeToString(blob)+"\n")...)

	cp, err := lognote.VerifyCheckpointNote(note, map[string]*ecdsa.PublicKey{khex: &priv.PublicKey})
	if err != nil {
		t.Fatalf("verify golden note: %v", err)
	}
	if cp.Size != 7 {
		t.Errorf("size: got %d, want 7", cp.Size)
	}

	// Verify directly that VerifyC2SPECDSA validates the signature only
	// against the body WITH the trailing newline (and fails without it).
	if !lognote.VerifyC2SPECDSA(&priv.PublicKey, body, der) {
		t.Error("signature should verify against body with trailing newline")
	}
	if lognote.VerifyC2SPECDSA(&priv.PublicKey, bytes.TrimRight(body, "\n"), der) {
		t.Error("signature must NOT verify against body without trailing newline")
	}
}

func TestVerifyCheckpointNoteTamperedBody(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	rootHash := sha256.Sum256([]byte("v1"))
	note := signCheckpoint(t, priv, "demo.example", 42, rootHash[:])
	tampered := bytes.Replace(note, []byte("\n42\n"), []byte("\n99\n"), 1)
	if _, err := lognote.VerifyCheckpointNote(tampered,
		map[string]*ecdsa.PublicKey{khex: &priv.PublicKey}); err == nil {
		t.Fatal("want error for tampered body, got nil")
	}
}

func TestVerifyCheckpointNoteUnknownKey(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherHex := keyHashHex(t, &other.PublicKey)
	rootHash := sha256.Sum256([]byte("rh"))
	note := signCheckpoint(t, priv, "demo.example", 1, rootHash[:])
	if _, err := lognote.VerifyCheckpointNote(note,
		map[string]*ecdsa.PublicKey{otherHex: &other.PublicKey}); err == nil {
		t.Fatal("want unknown-key error, got nil")
	}
}

func TestVerifyCheckpointNoteNoKeys(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootHash := sha256.Sum256([]byte("rh"))
	note := signCheckpoint(t, priv, "demo.example", 1, rootHash[:])
	if _, err := lognote.VerifyCheckpointNote(note, nil); err == nil {
		t.Fatal("want error for empty key map, got nil")
	}
	if _, err := lognote.VerifyCheckpointNote(note, map[string]*ecdsa.PublicKey{}); err == nil {
		t.Fatal("want error for empty key map, got nil")
	}
}

func TestVerifyCheckpointNoteMalformedBody(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	keys := map[string]*ecdsa.PublicKey{khex: &priv.PublicKey}

	cases := map[string][]byte{
		"no separator":           []byte("just one line\n"),
		"empty":                  nil,
		"missing rootHash line":  []byte("origin\n42\n\n— x AA==\n"),
		"non-numeric size":       []byte("origin\nNaN\nAAAA\n\n— x AA==\n"),
		"bad base64 rootHash":    []byte("origin\n1\n!!!notb64\n\n— x AA==\n"),
		"two body lines too few": []byte("origin\n42\n\n— x AA==\n"),
		"size overflows uint64":  []byte("origin\n99999999999999999999999\nAAAA\n\n— x AA==\n"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := lognote.VerifyCheckpointNote(body, keys); err == nil {
				t.Fatalf("want error for %s, got nil", name)
			}
		})
	}
}

// strict body verify-path-only: a signature blob shorter than the
// 4-byte keyhash prefix is rejected on the verify path (distinct from
// SplitNote, which is lenient but still records the short Blob).
func TestVerifyCheckpointNoteShortBlobRejected(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	keys := map[string]*ecdsa.PublicKey{khex: &priv.PublicKey}
	// Valid body, but the only signature blob is 3 bytes (< keyhash).
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	note := []byte("origin\n1\n" + base64.StdEncoding.EncodeToString([]byte("rh")) + "\n\n— origin " + short + "\n")
	if _, err := lognote.VerifyCheckpointNote(note, keys); err == nil {
		t.Fatal("want error: short blob has no keyhash, got nil")
	}
}

// Adversarial (reconciliation pin #8): a signature line with a KNOWN
// keyhash but a garbage signature must be rejected, AND the verify loop
// must continue past it to a LATER valid signature line and succeed.
func TestVerifyCheckpointNoteKnownKeyhashGarbageSigThenValid(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	kh4 := keyHash4(t, &priv.PublicKey)
	rootHash := sha256.Sum256([]byte("adversarial"))

	body := []byte(fmt.Sprintf("demo.example\n3\n%s\n",
		base64.StdEncoding.EncodeToString(rootHash[:])))
	digest := sha256.Sum256(body)
	validDER, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// First sig line: KNOWN keyhash, GARBAGE signature bytes (not a
	// valid DER or P1363 sig over the body). Must be rejected.
	garbageBlob := append(append([]byte{}, kh4...), []byte{0x00, 0xff, 0x00, 0xff, 0x00, 0xff}...)
	// Second sig line: same KNOWN keyhash, VALID signature. Must succeed.
	validBlob := append(append([]byte{}, kh4...), validDER...)

	note := append(append(body, '\n'),
		[]byte(
			"— demo.example "+base64.StdEncoding.EncodeToString(garbageBlob)+"\n"+
				"— demo.example "+base64.StdEncoding.EncodeToString(validBlob)+"\n",
		)...)

	cp, err := lognote.VerifyCheckpointNote(note, map[string]*ecdsa.PublicKey{khex: &priv.PublicKey})
	if err != nil {
		t.Fatalf("verify should succeed via the second valid line: %v", err)
	}
	if cp.Size != 3 {
		t.Errorf("size: got %d, want 3", cp.Size)
	}

	// And with ONLY the garbage line, verification must fail.
	garbageOnly := append(append(body, '\n'),
		[]byte("— demo.example "+base64.StdEncoding.EncodeToString(garbageBlob)+"\n")...)
	if _, err := lognote.VerifyCheckpointNote(garbageOnly,
		map[string]*ecdsa.PublicKey{khex: &priv.PublicKey}); err == nil {
		t.Fatal("want error: known keyhash with garbage sig must be rejected")
	}
}

// A signature line whose base64 decodes but whose keyhash is unknown is
// skipped; if a later line carries a known keyhash and valid sig, the
// note still verifies.
func TestVerifyCheckpointNoteUnknownKeyhashThenKnown(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	kh4 := keyHash4(t, &priv.PublicKey)
	rootHash := sha256.Sum256([]byte("rh"))

	body := []byte(fmt.Sprintf("demo.example\n9\n%s\n",
		base64.StdEncoding.EncodeToString(rootHash[:])))
	digest := sha256.Sum256(body)
	validDER, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])

	unknownBlob := append([]byte{0xab, 0xcd, 0xef, 0x01}, validDER...)
	validBlob := append(append([]byte{}, kh4...), validDER...)
	note := append(append(body, '\n'),
		[]byte(
			"— demo.example "+base64.StdEncoding.EncodeToString(unknownBlob)+"\n"+
				"— demo.example "+base64.StdEncoding.EncodeToString(validBlob)+"\n",
		)...)

	cp, err := lognote.VerifyCheckpointNote(note, map[string]*ecdsa.PublicKey{khex: &priv.PublicKey})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cp.Size != 9 {
		t.Errorf("size: got %d, want 9", cp.Size)
	}
}

// A note with a valid body but zero signature lines fails verification
// with the "no signature line matched" error.
func TestVerifyCheckpointNoteNoSignatureLines(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex := keyHashHex(t, &priv.PublicKey)
	note := []byte("origin\n1\n" + base64.StdEncoding.EncodeToString([]byte("rh")) + "\n\n")
	if _, err := lognote.VerifyCheckpointNote(note,
		map[string]*ecdsa.PublicKey{khex: &priv.PublicKey}); err == nil {
		t.Fatal("want error for note with no signatures, got nil")
	}
}

// ----- VerifyC2SPECDSA (tables moved from logstore) -----

func TestVerifyC2SPECDSAAcceptsDERAndLegacyP1363(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	body := []byte("ans-test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	digest := sha256.Sum256(body)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	p1363, err := anscrypto.DERToP1363(der, anscrypto.CoordinateBytes(&priv.PublicKey))
	if err != nil {
		t.Fatalf("DERToP1363: %v", err)
	}

	if !lognote.VerifyC2SPECDSA(&priv.PublicKey, body, der) {
		t.Error("DER signature did not verify")
	}
	if !lognote.VerifyC2SPECDSA(&priv.PublicKey, body, p1363) {
		t.Error("legacy P1363 signature did not verify")
	}
	if lognote.VerifyC2SPECDSA(&priv.PublicKey, []byte("tampered\n"), der) {
		t.Error("signature verified against the wrong checkpoint body")
	}
}

func TestVerifyC2SPECDSANegativePaths(t *testing.T) {
	t.Parallel()
	pub, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongLenP1363 := make([]byte, 2*anscrypto.CoordinateBytes(&pub.PublicKey)+1)

	cases := []struct {
		name string
		pub  *ecdsa.PublicKey
		body []byte
		sig  []byte
	}{
		{"nil public key", nil, []byte("body"), []byte{0x01, 0x02}},
		{"empty signature", &pub.PublicKey, []byte("body"), nil},
		{"malformed five bytes", &pub.PublicKey, []byte("body"), []byte{1, 2, 3, 4, 5}},
		{"p1363 wrong length", &pub.PublicKey, []byte("body"), wrongLenP1363},
		{"p1363 right length but not a signature", &pub.PublicKey, []byte("body"), make([]byte, 2*anscrypto.CoordinateBytes(&pub.PublicKey))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if lognote.VerifyC2SPECDSA(tc.pub, tc.body, tc.sig) {
				t.Errorf("expected false for %s", tc.name)
			}
		})
	}
}

// A nil-curve public key is rejected (defensive guard) even with a
// non-empty signature.
func TestVerifyC2SPECDSANilCurve(t *testing.T) {
	t.Parallel()
	if lognote.VerifyC2SPECDSA(&ecdsa.PublicKey{}, []byte("body"), []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Error("expected false for public key with nil curve")
	}
}

// ----- test helpers -----

// signCheckpoint builds a C2SP-shaped signed note: body (origin, size,
// base64 rootHash, each newline-terminated), a blank separator line,
// then one "— <origin> <base64(keyhash||DER-sig)>" signature line. The
// signature is computed over the real body bytes with the real key.
func signCheckpoint(t *testing.T, priv *ecdsa.PrivateKey, origin string, size uint64, rootHash []byte) []byte {
	t.Helper()
	body := []byte(fmt.Sprintf("%s\n%d\n%s\n",
		origin, size, base64.StdEncoding.EncodeToString(rootHash)))
	digest := sha256.Sum256(body)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("DER marshal: %v", err)
	}
	blob := append(keyHash4(t, &priv.PublicKey), der...)
	sigLine := fmt.Sprintf("— %s %s\n", origin, base64.StdEncoding.EncodeToString(blob))
	return append(body, append([]byte("\n"), []byte(sigLine)...)...)
}

// keyHash4 returns the 4-byte big-endian SPKI keyhash for pub, sourced
// from the production crypto helper (never a self-computed comparison).
func keyHash4(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	h, err := anscrypto.SPKIKeyHash4(pub)
	if err != nil {
		t.Fatalf("SPKIKeyHash4: %v", err)
	}
	return h
}

// keyHashHex returns the plain 8-char hex keyhash via the production
// crypto helper, matching the keysByHash map key VerifyCheckpointNote
// looks up.
func keyHashHex(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	h := keyHash4(t, pub)
	return fmt.Sprintf("%08x", binary.BigEndian.Uint32(h))
}
