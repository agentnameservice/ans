package logstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/godaddy/ans/internal/adapter/keymanager"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/logstore"
)

type ecdsaDERForTest struct {
	R, S *big.Int
}

func TestC2SPSignerSignReturnsDER(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	signer := newC2SPTestSigner(ctx, t, "ans-test")
	body := []byte("ans-test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")

	sig, err := signer.Sign(body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	assertDERSignature(t, signer.PublicKey(), body, sig)
}

func TestC2SPSignerNoteSignatureLineWrapsDER(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	origin := "ans-test"
	signer := newC2SPTestSigner(ctx, t, origin)
	body := "ans-test\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"

	signed, err := note.Sign(&note.Note{Text: body}, signer)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}

	raw := decodeLastNoteSignature(t, signed)
	if len(raw) <= 4 {
		t.Fatalf("note signature length: got %d, want keyhash plus DER signature", len(raw))
	}
	if got := binary.BigEndian.Uint32(raw[:4]); got != signer.KeyHash() {
		t.Fatalf("keyhash: got 0x%08x, want 0x%08x", got, signer.KeyHash())
	}
	assertDERSignature(t, signer.PublicKey(), []byte(body), raw[4:])
}

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

	if !logstore.VerifyC2SPECDSA(&priv.PublicKey, body, der) {
		t.Fatal("DER signature did not verify")
	}
	if !logstore.VerifyC2SPECDSA(&priv.PublicKey, body, p1363) {
		t.Fatal("legacy P1363 signature did not verify")
	}
	if logstore.VerifyC2SPECDSA(&priv.PublicKey, []byte("tampered\n"), der) {
		t.Fatal("signature verified against the wrong checkpoint body")
	}
}

func newC2SPTestSigner(ctx context.Context, t *testing.T, origin string) *logstore.C2SPECDSASigner {
	t.Helper()

	dir := t.TempDir()
	km, err := keymanager.NewFileKeyManager(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("NewFileKeyManager: %v", err)
	}
	if _, err := km.EnsureKey(ctx, "tl-sign", port.AlgorithmECDSAP256); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	signer, err := logstore.NewC2SPECDSASigner(ctx, km, "tl-sign", origin)
	if err != nil {
		t.Fatalf("NewC2SPECDSASigner: %v", err)
	}
	return signer
}

func assertDERSignature(t *testing.T, pub *ecdsa.PublicKey, body, sig []byte) {
	t.Helper()

	var parsed ecdsaDERForTest
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		t.Fatalf("signature is not ASN.1 DER: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("DER signature has trailing bytes: %x", rest)
	}
	if parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		t.Fatalf("DER signature has invalid ECDSA scalars: %+v", parsed)
	}

	digest := sha256.Sum256(body)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("DER signature failed VerifyASN1")
	}
}

func decodeLastNoteSignature(t *testing.T, signed []byte) []byte {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(string(signed)), "\n")
	if len(lines) == 0 {
		t.Fatal("signed note has no lines")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) != 3 || fields[0] != "\u2014" {
		t.Fatalf("signature line: got %q, want em-dash signer base64", lines[len(lines)-1])
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return raw
}
