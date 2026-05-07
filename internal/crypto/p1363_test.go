package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

func TestDERToP1363_RoundTrip(t *testing.T) {
	t.Parallel()
	r := new(big.Int).SetBytes([]byte{0x01, 0x23, 0x45})
	s := new(big.Int).SetBytes([]byte{0x67, 0x89, 0xab})
	der, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	p1363, err := DERToP1363(der, 32)
	if err != nil {
		t.Fatalf("DERToP1363: %v", err)
	}
	if len(p1363) != 64 {
		t.Fatalf("want 64 bytes, got %d", len(p1363))
	}

	der2, err := P1363ToDER(p1363)
	if err != nil {
		t.Fatalf("P1363ToDER: %v", err)
	}
	// asn1.Marshal is deterministic for the same inputs, so a byte
	// compare is meaningful.
	if !bytes.Equal(der, der2) {
		t.Fatalf("DER round-trip mismatch:\n  in : %x\n  out: %x", der, der2)
	}
}

func TestDERToP1363_LeadingZeroScalars(t *testing.T) {
	t.Parallel()
	// An r/s scalar whose most-significant byte is < 0x80 encodes as
	// fewer than 32 bytes in the DER INTEGER form but still needs
	// zero-padding to 32 in P1363.
	r := new(big.Int).SetBytes([]byte{0x01}) // one byte
	s := new(big.Int).SetBytes([]byte{0x02})
	der, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}

	p1363, err := DERToP1363(der, 32)
	if err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 64)
	want[31] = 0x01
	want[63] = 0x02
	if !bytes.Equal(p1363, want) {
		t.Fatalf("leading-zero pad wrong:\n  got : %x\n  want: %x", p1363, want)
	}
}

func TestDERToP1363_RealSignature(t *testing.T) {
	t.Parallel()
	// A real DER signature from crypto/ecdsa must round-trip.
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the attack will begin at dawn")
	digest := sha256.Sum256(msg)
	derSig, err := ecdsa.SignASN1(rand.Reader, pk, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	p1363, err := DERToP1363(derSig, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1363) != 64 {
		t.Fatalf("want 64 bytes, got %d", len(p1363))
	}

	r, s, err := P1363ToScalars(p1363)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.Verify(&pk.PublicKey, digest[:], r, s) {
		t.Fatal("P1363-derived scalars failed to verify a valid signature")
	}
}

func TestDERToP1363_BadInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		der        []byte
		coordBytes int
	}{
		{"zero coordBytes", []byte{0x30, 0x00}, 0},
		{"negative coordBytes", []byte{0x30, 0x00}, -1},
		{"not der at all", []byte{0xff, 0xff}, 32},
		{"trailing bytes", append(mustMarshalDER(t, big.NewInt(1), big.NewInt(2)), 0x00), 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DERToP1363(tc.der, tc.coordBytes); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestDERToP1363_ScalarExceedsCoord(t *testing.T) {
	t.Parallel()
	big33 := new(big.Int).SetBytes(bytes.Repeat([]byte{0x01}, 33))
	der := mustMarshalDER(t, big33, big.NewInt(1))
	if _, err := DERToP1363(der, 32); err == nil {
		t.Fatal("expected error when scalar larger than coord size")
	}
}

func TestDERToP1363_ZeroScalar(t *testing.T) {
	t.Parallel()
	// R or S of zero is an invalid ECDSA signature — we reject up front.
	der := mustMarshalDER(t, big.NewInt(0), big.NewInt(1))
	if _, err := DERToP1363(der, 32); err == nil {
		t.Fatal("zero scalar should fail")
	}
}

func TestP1363ToDER_BadLength(t *testing.T) {
	t.Parallel()
	cases := [][]byte{nil, {}, make([]byte, 63), make([]byte, 1)}
	for _, c := range cases {
		if _, err := P1363ToDER(c); !errors.Is(err, ErrInvalidP1363Length) {
			t.Fatalf("want ErrInvalidP1363Length, got %v", err)
		}
		if _, _, err := P1363ToScalars(c); !errors.Is(err, ErrInvalidP1363Length) {
			t.Fatalf("P1363ToScalars: want ErrInvalidP1363Length, got %v", err)
		}
	}
}

func TestP1363ToDER_ZeroScalar(t *testing.T) {
	t.Parallel()
	p := make([]byte, 64) // all zero → r=0, s=0
	if _, err := P1363ToDER(p); err == nil {
		t.Fatal("expected error for zero scalars")
	}
	if _, _, err := P1363ToScalars(p); err == nil {
		t.Fatal("expected error for zero scalars")
	}
}

func TestCoordinateBytes(t *testing.T) {
	t.Parallel()
	pk256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if got := CoordinateBytes(&pk256.PublicKey); got != 32 {
		t.Fatalf("P-256 want 32, got %d", got)
	}
	pk384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if got := CoordinateBytes(&pk384.PublicKey); got != 48 {
		t.Fatalf("P-384 want 48, got %d", got)
	}
}

// ----- helpers -----

func mustMarshalDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	der, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	return der
}
