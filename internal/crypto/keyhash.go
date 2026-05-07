package crypto

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// SPKIKeyHash4 returns the C2SP 4-byte "opaque key hash":
//
//	SHA-256(SPKI-DER)[0:4]  — interpreted big-endian as uint32
//
// then written out as 4 big-endian bytes. This is the shape used as a
// COSE `kid` header parameter in SCITT receipts so verifiers who
// hold the /root-keys PEM can match the receipt's `kid` byte-for-
// byte without guessing a digest algorithm.
//
// Distinct from the 8-hex-char `OpaqueKeyIDFromHash` form that the
// detached-JWS header uses (which is the same 4 bytes rendered as a
// hex string) — callers should pick the form appropriate to their
// wire format.
func SPKIKeyHash4(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal SPKI: %w", err)
	}
	full := sha256.Sum256(der)
	out := make([]byte, 4)
	// Big-endian uint32 of the first 4 bytes, written as 4 bytes.
	// Equivalent to full[0:4] for cryptographic purposes but the
	// explicit BigEndian round-trip matches the reference's
	// `binary.BigEndian.PutUint32(out, binary.BigEndian.Uint32(full[:4]))`
	// which is itself a no-op but documents intent.
	v := binary.BigEndian.Uint32(full[:4])
	binary.BigEndian.PutUint32(out, v)
	return out, nil
}

// SPKIKeyIDHex4 returns the hex-encoded 4-byte opaque key ID — the
// string form the detached-JWS header uses as `kid`.
func SPKIKeyIDHex4(pub crypto.PublicKey) (string, error) {
	b, err := SPKIKeyHash4(pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
