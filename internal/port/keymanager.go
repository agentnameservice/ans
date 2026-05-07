package port

import (
	"context"
	"crypto"
)

// Algorithm names understood by KeyManager implementations.
const (
	AlgorithmECDSAP256 = "ECDSA_P256"
	AlgorithmECDSAP384 = "ECDSA_P384"
	AlgorithmRSA2048   = "RSA_2048"
	AlgorithmRSA4096   = "RSA_4096"
)

// KeyManager abstracts cryptographic key storage and signing operations.
// The default local-dev adapter stores keys on disk; production adapters
// wrap AWS KMS, GCP KMS, or HashiCorp Vault Transit. Callers never see
// raw private keys — the interface only exposes sign/verify/public-key.
type KeyManager interface {
	// Sign produces a signature over data using the key identified by keyID.
	// The returned signature format is adapter-defined (typically DER for
	// ECDSA, PKCS1v15 or PSS for RSA); downstream code must match the format.
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)

	// Verify returns true if signature is valid for data under the given key.
	// A verify error (e.g., key not found) is distinct from a valid "false".
	Verify(ctx context.Context, keyID string, data, signature []byte) (bool, error)

	// GetPublicKey returns the public half of the named key. The concrete type
	// depends on the algorithm (e.g., *ecdsa.PublicKey for ECDSA_P256).
	GetPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error)

	// CreateKey generates a new key pair under the given algorithm and
	// returns its identifier. The identifier is opaque to the caller.
	CreateKey(ctx context.Context, algorithm string) (keyID string, err error)

	// ListKeys returns all known key IDs. Useful for key rotation and audit.
	ListKeys(ctx context.Context) ([]string, error)
}
