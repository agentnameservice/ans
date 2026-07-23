// Package keymanager provides KeyManager implementations.
//
// The file-based adapter stores ECDSA P-256 keys on the local filesystem
// for zero-config development use. Each key is two PEM files:
//
//	<path>/<keyID>.key  — PKCS#8 private key (mode 0600)
//	<path>/<keyID>.pub  — PKIX public key
//
// Production deployments should use cloud KMS adapters (AWS KMS, GCP KMS,
// Vault Transit). Those will be contributed by the community; the port
// interface is stable.
package keymanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/agentnameservice/ans/internal/port"
)

// Errors returned by the file key manager.
var (
	ErrKeyNotFound          = errors.New("keymanager: key not found")
	ErrUnsupportedAlgorithm = errors.New("keymanager: unsupported algorithm")
	ErrKeyExists            = errors.New("keymanager: key already exists")
)

// FileKeyManager implements port.KeyManager with on-disk ECDSA/RSA keys.
type FileKeyManager struct {
	dir   string
	mu    sync.RWMutex
	cache map[string]crypto.Signer
}

// NewFileKeyManager opens (or creates) a filesystem key directory.
// The directory is created with 0700 permissions if it does not exist.
func NewFileKeyManager(dir string) (*FileKeyManager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keymanager: create dir %s: %w", dir, err)
	}
	return &FileKeyManager{
		dir:   dir,
		cache: make(map[string]crypto.Signer),
	}, nil
}

// EnsureKey is a convenience helper: if a key with the given ID already
// exists, it is returned; otherwise a new key is generated. Used at startup
// by ans-tl to auto-provision a signing key on first run.
func (f *FileKeyManager) EnsureKey(ctx context.Context, keyID, algorithm string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.loadLocked(keyID); err == nil {
		return keyID, nil
	} else if !errors.Is(err, ErrKeyNotFound) {
		return "", err
	}
	return f.createLocked(keyID, algorithm)
}

// CreateKey generates a new key pair with a random ID.
func (f *FileKeyManager) CreateKey(ctx context.Context, algorithm string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	keyID := uuid.NewString()
	return f.createLocked(keyID, algorithm)
}

// Sign produces a signature over data using the key identified by keyID.
// ECDSA signatures are ASN.1-DER encoded; RSA uses PKCS#1 v1.5 with SHA-256.
func (f *FileKeyManager) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	signer, err := f.loadSigner(keyID)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand.Reader, data, crypto.SHA256)
}

// Verify validates the signature against data using the public key for keyID.
func (f *FileKeyManager) Verify(ctx context.Context, keyID string, data, signature []byte) (bool, error) {
	signer, err := f.loadSigner(keyID)
	if err != nil {
		return false, err
	}
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, data, signature), nil
	case *rsa.PublicKey:
		// VerifyPKCS1v15 returns rsa.ErrVerification on a sig that
		// doesn't match. That's not an "error" from this verifier's
		// perspective — the signature simply didn't verify, surface
		// `(false, nil)`. The caller of Verify is expected to act on
		// the bool.
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, data, signature); err != nil {
			return false, nil //nolint:nilerr // bad sig is "verified=false", not a verifier error
		}
		return true, nil
	default:
		return false, fmt.Errorf("keymanager: unsupported public key type %T", pub)
	}
}

// GetPublicKey returns the public key for the given keyID.
func (f *FileKeyManager) GetPublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	signer, err := f.loadSigner(keyID)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// ListKeys returns the IDs of all keys in the directory.
func (f *FileKeyManager) ListKeys(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, fmt.Errorf("keymanager: read dir: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".key") {
			ids = append(ids, strings.TrimSuffix(name, ".key"))
		}
	}
	return ids, nil
}

// loadSigner returns the private-key Signer for keyID, using the cache
// if available.
func (f *FileKeyManager) loadSigner(keyID string) (crypto.Signer, error) {
	f.mu.RLock()
	if s, ok := f.cache[keyID]; ok {
		f.mu.RUnlock()
		return s, nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.cache[keyID]; ok {
		return s, nil
	}
	return f.loadLocked(keyID)
}

// loadLocked reads the key from disk and caches it. Caller holds f.mu.
func (f *FileKeyManager) loadLocked(keyID string) (crypto.Signer, error) {
	path := filepath.Join(f.dir, keyID+".key")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
		}
		return nil, fmt.Errorf("keymanager: read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keymanager: %s is not a PKCS#8 PRIVATE KEY PEM", path)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keymanager: parse %s: %w", path, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("keymanager: %s is not a signer", path)
	}
	f.cache[keyID] = signer
	return signer, nil
}

// createLocked generates and persists a new key. Caller holds f.mu.
func (f *FileKeyManager) createLocked(keyID, algorithm string) (string, error) {
	privPath := filepath.Join(f.dir, keyID+".key")
	pubPath := filepath.Join(f.dir, keyID+".pub")

	if _, err := os.Stat(privPath); err == nil {
		return "", fmt.Errorf("%w: %s", ErrKeyExists, keyID)
	}

	var priv crypto.Signer
	switch algorithm {
	case port.AlgorithmECDSAP256, "":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", fmt.Errorf("keymanager: generate P-256: %w", err)
		}
		priv = k
	case port.AlgorithmECDSAP384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return "", fmt.Errorf("keymanager: generate P-384: %w", err)
		}
		priv = k
	case port.AlgorithmRSA2048:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", fmt.Errorf("keymanager: generate RSA-2048: %w", err)
		}
		priv = k
	case port.AlgorithmRSA4096:
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return "", fmt.Errorf("keymanager: generate RSA-4096: %w", err)
		}
		priv = k
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, algorithm)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("keymanager: marshal priv: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return "", fmt.Errorf("keymanager: marshal pub: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return "", fmt.Errorf("keymanager: write priv: %w", err)
	}
	// 0o644 (world-readable) is intentional: the public key is, by
	// definition, public. Private key path above is 0o600.
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil { //nolint:gosec // G306: public key, world-readable is by design
		return "", fmt.Errorf("keymanager: write pub: %w", err)
	}

	f.cache[keyID] = priv
	return keyID, nil
}

// KeyFingerprint returns a short identifier (first 8 bytes hex) of the
// given public key's PKIX SHA-256. Useful for log lines.
func KeyFingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// PublicKeyToPEM returns the PKIX DER of pub wrapped in a PEM block
// with type "PUBLIC KEY". Safe for inclusion in text/plain responses
// (e.g. the TL /root-keys endpoint) and for pasting into
// config files.
func PublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("keymanager: marshal pub: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
