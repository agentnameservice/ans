package cose_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/godaddy/ans/internal/crypto/cose"
)

// staticSigner is a deterministic Signer that returns a fixed
// signature regardless of input. Lets us pin the COSE_Sign1 byte
// layout in tests without dealing with ECDSA non-determinism.
type staticSigner struct {
	sig []byte
	err error
	// captured is the last msg the signer was asked to sign;
	// tests use it to assert the Sig_structure shape.
	captured []byte
}

func (s *staticSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.captured = append([]byte(nil), msg...)
	if s.sig != nil {
		return s.sig, nil
	}
	return make([]byte, 64), nil
}

func TestSign1_HappyPath(t *testing.T) {
	t.Parallel()
	signer := &staticSigner{sig: bytesPattern(0xAB, 64)}
	protected := map[int]any{1: -7, 4: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
	unprotected := map[int]any{396: "vdp-placeholder"}
	payload := []byte(`{"hello":"world"}`)

	out, err := cose.Sign1(context.Background(), signer, protected, unprotected, payload)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	var tag cbor.Tag
	if err := cbor.Unmarshal(out, &tag); err != nil {
		t.Fatalf("decode top-level tag: %v", err)
	}
	if tag.Number != 18 {
		t.Errorf("tag = %d, want 18 (COSE_Sign1)", tag.Number)
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		t.Fatalf("content = %#v, want 4-element array", tag.Content)
	}

	protectedBytes, ok := arr[0].([]byte)
	if !ok {
		t.Fatalf("protected element type = %T, want []byte", arr[0])
	}
	// The Sig_structure the signer captured must start with
	// "Signature1" — proves the standard sig-structure shape was
	// built, not some bespoke message.
	if signer.captured == nil {
		t.Fatal("signer was not called")
	}
	var sigStruct []any
	if err := cbor.Unmarshal(signer.captured, &sigStruct); err != nil {
		t.Fatalf("decode sig_structure: %v", err)
	}
	if len(sigStruct) != 4 {
		t.Fatalf("sig_structure len = %d, want 4", len(sigStruct))
	}
	if sigStruct[0] != "Signature1" {
		t.Errorf("sig_structure[0] = %v, want Signature1", sigStruct[0])
	}
	if got, ok := sigStruct[1].([]byte); !ok || !equalBytes(got, protectedBytes) {
		t.Errorf("sig_structure[1] != protected bytes")
	}
	if got, ok := sigStruct[3].([]byte); !ok || !equalBytes(got, payload) {
		t.Errorf("sig_structure[3] != payload")
	}
}

func TestSign1_NilUnprotectedEncodesAsEmptyMap(t *testing.T) {
	t.Parallel()
	// Passing nil for unprotected is shorthand for "no unprotected
	// params". On the wire this is encoded as an empty CBOR map (not
	// CBOR null) so verifiers can always index into it.
	signer := &staticSigner{}
	out, err := cose.Sign1(context.Background(), signer,
		map[int]any{1: -7}, nil, []byte("p"))
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}
	var tag cbor.Tag
	if err := cbor.Unmarshal(out, &tag); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr := tag.Content.([]any)
	m, ok := arr[1].(map[any]any)
	if !ok {
		t.Fatalf("unprotected element type = %T, want map", arr[1])
	}
	if len(m) != 0 {
		t.Errorf("unprotected map = %v, want empty", m)
	}
}

func TestSign1_EmptyProtectedHeaderEncodesAsZeroLengthBstr(t *testing.T) {
	t.Parallel()
	// RFC 9052 §3: an empty protected header is encoded as a
	// zero-length byte string (h''), NOT as bstr-wrapping an empty
	// map. This is wire-observable across implementations.
	signer := &staticSigner{}
	out, err := cose.Sign1(context.Background(), signer, nil, nil, []byte("p"))
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}
	var tag cbor.Tag
	if err := cbor.Unmarshal(out, &tag); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr := tag.Content.([]any)
	b, ok := arr[0].([]byte)
	if !ok {
		t.Fatalf("protected element type = %T", arr[0])
	}
	if len(b) != 0 {
		t.Errorf("protected bytes len = %d, want 0", len(b))
	}
}

func TestSign1_NilSigner(t *testing.T) {
	t.Parallel()
	_, err := cose.Sign1(context.Background(), nil,
		map[int]any{1: -7}, nil, []byte("p"))
	if err == nil {
		t.Fatal("want error for nil signer")
	}
}

func TestSign1_EmptyPayload(t *testing.T) {
	t.Parallel()
	signer := &staticSigner{}
	_, err := cose.Sign1(context.Background(), signer,
		map[int]any{1: -7}, nil, nil)
	if err == nil {
		t.Fatal("want error for nil payload")
	}
	_, err = cose.Sign1(context.Background(), signer,
		map[int]any{1: -7}, nil, []byte{})
	if err == nil {
		t.Fatal("want error for empty payload")
	}
}

func TestSign1_SignerError(t *testing.T) {
	t.Parallel()
	want := errors.New("hsm offline")
	signer := &staticSigner{err: want}
	_, err := cose.Sign1(context.Background(), signer,
		map[int]any{1: -7}, nil, []byte("p"))
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want wrapping %v", err, want)
	}
}

// fakeKM is a port.KeyManager that signs by hashing-and-signing with
// a real ECDSA key. Used to drive KeyManagerSigner end-to-end without
// importing internal/adapter/keymanager (which would create a layering
// inversion).
type fakeKM struct {
	priv *ecdsa.PrivateKey
}

func (k *fakeKM) Sign(_ context.Context, _ string, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
func (k *fakeKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, errors.New("not implemented")
}
func (k *fakeKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return &k.priv.PublicKey, nil
}
func (k *fakeKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (k *fakeKM) ListKeys(_ context.Context) ([]string, error)          { return nil, nil }

type errKM struct{ err error }

func (e *errKM) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, e.err
}
func (e *errKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, e.err
}
func (e *errKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return nil, e.err
}
func (e *errKM) CreateKey(_ context.Context, _ string) (string, error) { return "", e.err }
func (e *errKM) ListKeys(_ context.Context) ([]string, error)          { return nil, e.err }

// brokenDERKM returns garbage bytes posing as DER so DERToP1363 fails.
type brokenDERKM struct{}

func (b *brokenDERKM) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return []byte{0xFF, 0xFF, 0xFF}, nil
}
func (b *brokenDERKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, nil
}
func (b *brokenDERKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return nil, nil
}
func (b *brokenDERKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (b *brokenDERKM) ListKeys(_ context.Context) ([]string, error)          { return nil, nil }

func TestKeyManagerSigner_RoundTripVerifies(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signer, err := cose.NewKeyManagerSigner(&fakeKM{priv: priv}, "k")
	if err != nil {
		t.Fatalf("NewKeyManagerSigner: %v", err)
	}
	msg := []byte("payload-to-sign")
	sig, err := signer.Sign(context.Background(), msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig len = %d, want 64 (P1363 P-256)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Fatal("ecdsa.Verify failed for round-tripped signature")
	}
}

func TestNewKeyManagerSigner_Validation(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := cose.NewKeyManagerSigner(nil, "k"); err == nil {
		t.Error("want error for nil km")
	}
	if _, err := cose.NewKeyManagerSigner(&fakeKM{priv: priv}, ""); err == nil {
		t.Error("want error for empty keyID")
	}
}

func TestKeyManagerSigner_KMError(t *testing.T) {
	t.Parallel()
	want := errors.New("hsm offline")
	signer, err := cose.NewKeyManagerSigner(&errKM{err: want}, "k")
	if err != nil {
		t.Fatalf("NewKeyManagerSigner: %v", err)
	}
	_, err = signer.Sign(context.Background(), []byte("msg"))
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want wrapping %v", err, want)
	}
}

func TestKeyManagerSigner_BadDER(t *testing.T) {
	t.Parallel()
	signer, err := cose.NewKeyManagerSigner(&brokenDERKM{}, "k")
	if err != nil {
		t.Fatalf("NewKeyManagerSigner: %v", err)
	}
	if _, err := signer.Sign(context.Background(), []byte("msg")); err == nil {
		t.Fatal("want error for broken DER, got nil")
	}
}

func TestSign1_UnencodableProtectedHeader(t *testing.T) {
	t.Parallel()
	// A channel is not CBOR-encodable; fxamacker/cbor returns
	// UnsupportedTypeError. Confirms the encodeProtectedHeader
	// error-return path is wired up (it cascades from detMarshal).
	signer := &staticSigner{}
	_, err := cose.Sign1(context.Background(), signer,
		map[int]any{1: make(chan int)}, nil, []byte("p"))
	if err == nil {
		t.Fatal("want encode error for channel-valued header")
	}
}

func TestSign1_UnencodableUnprotectedHeader(t *testing.T) {
	t.Parallel()
	// Channel in the unprotected map slips past the empty-protected
	// shortcut and reaches the final COSE_Sign1 encode — the
	// defensive branch SAFETY-annotated in Sign1.
	signer := &staticSigner{}
	_, err := cose.Sign1(context.Background(), signer,
		nil, map[int]any{99: make(chan int)}, []byte("p"))
	if err == nil {
		t.Fatal("want encode error for channel-valued unprotected header")
	}
}

func TestSign1_EndToEndWithRealKey(t *testing.T) {
	t.Parallel()
	// End-to-end: real ECDSA key, real signer, real Sign1, then
	// re-derive the Sig_structure and verify against the public key.
	// Catches drift between what we sign and what the wire actually
	// contains.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := cose.NewKeyManagerSigner(&fakeKM{priv: priv}, "k")

	protected := map[int]any{1: -7, 4: []byte{0xCA, 0xFE}}
	payload := []byte(`{"x":1}`)
	out, err := cose.Sign1(context.Background(), signer, protected, nil, payload)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}
	var tag cbor.Tag
	if err := cbor.Unmarshal(out, &tag); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr := tag.Content.([]any)
	protectedBytes := arr[0].([]byte)
	sig := arr[3].([]byte)

	em, _ := cbor.CoreDetEncOptions().EncMode()
	sigStructureBytes, _ := em.Marshal([]any{
		"Signature1", protectedBytes, []byte{}, payload,
	})
	digest := sha256.Sum256(sigStructureBytes)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Fatal("Sign1 output does not verify against signer public key")
	}
}

// --- helpers ---

func bytesPattern(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
