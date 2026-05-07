package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// algEd25519 is the C2SP verifier "algorithm" byte for ed25519 keys.
const algEd25519 = 0x01

// algECDSAWithSHA256 is the C2SP verifier "algorithm" byte for ECDSA
// P-256 keys used by the sumdb/note-style verification-key format.
// Ed25519 uses 0x01; this is the ECDSA extension.
const algECDSAWithSHA256 = 0x02

// PublicKeyToVerificationLine encodes an ECDSA P-256 public key in
// the sumdb-note-style verification format the reference TL serves
// at /root-keys:
//
//	<origin>+<keyhash-hex>+<base64(0x02 || SPKI-DER)>
//
// Where `keyhash-hex` is the first 4 bytes of SHA-256(SPKI-DER) as
// a zero-padded 8-char hex string (big-endian uint32). The 0x02
// byte marks the key as ECDSA; base-64 encoding uses std alphabet
// with padding (matching the reference). Callers concatenate the
// returned line with a newline and repeat per key for the full
// /root-keys body.
//
// Byte-for-byte match with the reference TL's
// `key.PublicKeyToVerificationKey` helper.
func PublicKeyToVerificationLine(originName string, pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal SPKI: %w", err)
	}
	sum := sha256.Sum256(der)
	hash32 := binary.BigEndian.Uint32(sum[:4])
	hashHex := fmt.Sprintf("%08x", hash32)

	keyBytes := append([]byte{algECDSAWithSHA256}, der...)
	keyB64 := base64.StdEncoding.EncodeToString(keyBytes)

	return fmt.Sprintf("%s+%s+%s", originName, hashHex, keyB64), nil
}

// ParseVerificationLine is the inverse of PublicKeyToVerificationLine —
// it parses a sumdb-note-style verification key string into the
// underlying ed25519 or ECDSA P-256 public key. The return type is
// `any` because the line carries either algorithm; callers should
// type-assert to the expected key type.
//
// Accepts either the ed25519 form (`0x01 || 32B pub`) or the ECDSA
// P-256 form (`0x02 || SPKI-DER`). Any other first byte is rejected.
func ParseVerificationLine(line string) (any, error) {
	parts := strings.SplitN(strings.TrimSpace(line), "+", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("crypto: note line: want 3 '+'-separated parts, got %d", len(parts))
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("crypto: note line: base64: %w", err)
	}
	if len(raw) < 1 {
		return nil, errors.New("crypto: note line: empty key body")
	}
	switch raw[0] {
	case algEd25519:
		if len(raw) != 1+ed25519.PublicKeySize {
			return nil, fmt.Errorf("crypto: note line: ed25519 key must be %d bytes, got %d",
				ed25519.PublicKeySize, len(raw)-1)
		}
		return ed25519.PublicKey(raw[1:]), nil
	case algECDSAWithSHA256:
		pub, err := x509.ParsePKIXPublicKey(raw[1:])
		if err != nil {
			return nil, fmt.Errorf("crypto: note line: parse SPKI: %w", err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("crypto: note line: SPKI is not ECDSA (type %T)", pub)
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("crypto: note line: unknown algorithm byte 0x%02x", raw[0])
	}
}

// PublicKeyPEM marshals an ed25519 or ECDSA public key as a standard
// PEM-encoded SPKI block. Used for the `publicKeyPem` field on the
// checkpoint response, where the reference TL surfaces the primary
// signer's PEM alongside the signed note.
func PublicKeyPEM(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal SPKI: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}
