package crypto

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ECDSA signatures have two equally valid wire formats:
//
//   - ASN.1 DER (RFC 3279) — variable length, what Go's crypto.Signer
//     returns by default. Used in X.509 certificates, TLS, and PKCS#7.
//   - IEEE P1363 — fixed length `r || s`, each scalar zero-padded to
//     the curve's coordinate size. Used in JWS/JWA (RFC 7518 §3.4),
//     COSE (RFC 8152), and WebCrypto.
//
// Interop between these two worlds is the whole reason this file
// exists. Callers that emit JWS or COSE convert DER signatures at
// the KeyManager boundary so those wire formats stay in their
// required P1363 form.

// ErrInvalidP1363Length is returned when a P1363 signature is not
// exactly 2*coordinateSize bytes.
var ErrInvalidP1363Length = errors.New("crypto: invalid P1363 signature length")

// ecdsaASN1Signature mirrors the DER structure RFC 3279 prescribes.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// DERToP1363 converts an ASN.1 DER-encoded ECDSA signature to IEEE
// P1363 format (raw r || s, each scalar zero-padded to coordBytes).
// For P-256, coordBytes is 32 and the output is 64 bytes.
func DERToP1363(derSig []byte, coordBytes int) ([]byte, error) {
	if coordBytes <= 0 {
		return nil, fmt.Errorf("crypto: coordBytes must be positive, got %d", coordBytes)
	}
	var sig ecdsaASN1Signature
	rest, err := asn1.Unmarshal(derSig, &sig)
	if err != nil {
		return nil, fmt.Errorf("crypto: unmarshal DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("crypto: trailing bytes after DER signature")
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("crypto: invalid ECDSA scalars")
	}
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	if len(rBytes) > coordBytes || len(sBytes) > coordBytes {
		return nil, fmt.Errorf("crypto: ECDSA scalar exceeds %d bytes", coordBytes)
	}
	out := make([]byte, 2*coordBytes)
	copy(out[coordBytes-len(rBytes):coordBytes], rBytes)
	copy(out[2*coordBytes-len(sBytes):], sBytes)
	return out, nil
}

// P1363ToDER converts an IEEE P1363 ECDSA signature (raw r || s) to
// ASN.1 DER form. Used on the verify path when the verifier needs to
// hand bytes to a DER-expecting API (not currently hit by our stack
// since ecdsa.Verify takes big.Int scalars directly, but kept for
// completeness and symmetry).
func P1363ToDER(p1363Sig []byte) ([]byte, error) {
	if len(p1363Sig) == 0 || len(p1363Sig)%2 != 0 {
		return nil, ErrInvalidP1363Length
	}
	half := len(p1363Sig) / 2
	r := new(big.Int).SetBytes(p1363Sig[:half])
	s := new(big.Int).SetBytes(p1363Sig[half:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, errors.New("crypto: invalid ECDSA scalars")
	}
	return asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
}

// P1363ToScalars parses a P1363 signature into its r and s scalars.
// Callers that want to use ecdsa.Verify(pub, digest, r, s) directly
// skip the DER round-trip.
func P1363ToScalars(p1363Sig []byte) (*big.Int, *big.Int, error) {
	if len(p1363Sig) == 0 || len(p1363Sig)%2 != 0 {
		return nil, nil, ErrInvalidP1363Length
	}
	half := len(p1363Sig) / 2
	r := new(big.Int).SetBytes(p1363Sig[:half])
	s := new(big.Int).SetBytes(p1363Sig[half:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, nil, errors.New("crypto: invalid ECDSA scalars")
	}
	return r, s, nil
}

// CoordinateBytes returns the zero-padded coordinate size (in bytes)
// for an ECDSA public key, which is the half-length of a P1363
// signature under that key. P-256 → 32, P-384 → 48, P-521 → 66.
func CoordinateBytes(pub *ecdsa.PublicKey) int {
	bits := pub.Curve.Params().BitSize
	return (bits + 7) / 8
}
