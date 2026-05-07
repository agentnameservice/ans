package receipt

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// Status tokens are short-lived COSE_Sign1 assertions of an agent's
// current lifecycle state (ACTIVE / DEPRECATED / REVOKED / EXPIRED /
// WARNING). They work analogously to OCSP stapling in TLS: the agent
// hosting provider pulls a fresh token every ~30 minutes and staples
// it alongside the SCITT receipt in the Agent Card, so verifiers can
// check current state without a round-trip to the TL.
//
// Wire format mirrors the reference TL's status-token byte layout
// byte-for-byte:
//
//   COSE_Sign1 array, tagged 18:
//     protected_header : bstr CBOR{alg=ES256, kid=<4-byte SPKI hash>,
//                                  content_type="application/ans-status-token+cbor"}
//     unprotected_header : {}
//     payload : bstr CBOR(StatusTokenPayload)
//     signature : ES256 IEEE P1363 over the Sig_structure1
//
// TTL is 1h by default — long enough that verifiers don't beat up on
// the TL, short enough that a revocation propagates in bounded time.

const (
	// StatusTokenMediaType is the Content-Type returned for status
	// tokens. Matches reference `receipt.ContentTypeStatusToken`.
	StatusTokenMediaType = "application/ans-status-token+cbor"

	// DefaultStatusTokenTTL is how long a status token remains valid
	// from its iat. Matches reference (1h).
	DefaultStatusTokenTTL = 1 * time.Hour
)

// CertFingerprint identifies a certificate inside the status-token
// payload. Matches reference `receipt.CertFingerprint` byte-for-byte
// (CBOR keyasint 1 = fingerprint, 2 = cert type).
type CertFingerprint struct {
	Fingerprint string `cbor:"1,keyasint"` // "SHA256:<hex>"
	CertType    string `cbor:"2,keyasint"` // "X509-OV-CLIENT" / "X509-TLSA" / etc.
}

// StatusTokenPayload is the CBOR payload inside the COSE_Sign1
// status token. Short keyasint keys minimize token size. Mirrors
// reference `receipt.StatusTokenPayload` byte-for-byte.
type StatusTokenPayload struct {
	AgentID            string            `cbor:"1,keyasint"`           // Agent UUID
	Status             string            `cbor:"2,keyasint"`           // ACTIVE, DEPRECATED, REVOKED, ...
	IAT                int64             `cbor:"3,keyasint"`           // Issued-at (unix seconds)
	EXP                int64             `cbor:"4,keyasint"`           // Expires (unix seconds)
	ANSName            string            `cbor:"5,keyasint,omitempty"` // ans://v{ver}.{host}
	ValidIdentityCerts []CertFingerprint `cbor:"6,keyasint,omitempty"` // All valid identity certs
	ValidServerCerts   []CertFingerprint `cbor:"7,keyasint,omitempty"` // All valid server certs
	MetadataHashes     map[string]string `cbor:"8,keyasint,omitempty"` // protocol → SHA256 hash
}

// StatusTokenClaims bundles the dynamic fields the controller passes
// to the generator. Everything else (issuer, TTL, kid) is fixed at
// generator construction time.
type StatusTokenClaims struct {
	AgentID            string
	ANSName            string
	Status             string
	ValidIdentityCerts []CertFingerprint
	ValidServerCerts   []CertFingerprint
	MetadataHashes     map[string]string
}

// StatusTokenGenerator creates signed status tokens as COSE_Sign1
// structures. Matches the reference's generator interface.
type StatusTokenGenerator interface {
	GenerateStatusToken(ctx context.Context, claims *StatusTokenClaims) ([]byte, error)
	// PublicKey is exposed so callers (e.g. the /root-keys responder)
	// can advertise the verifier key. Required because the same
	// KeyManager may hold multiple keys and we want the caller to
	// know which one this generator signs with.
	PublicKey() *ecdsa.PublicKey
}

// KeyManagerStatusTokenGenerator is the production generator. It
// signs via the TL's port.KeyManager, converting the DER output to
// the P1363 raw-r||s form that COSE requires (RFC 8152 §8.1).
type KeyManagerStatusTokenGenerator struct {
	km      port.KeyManager
	keyID   string
	pub     *ecdsa.PublicKey
	keyHash []byte // 4-byte SPKI-DER SHA-256 prefix — becomes the COSE kid
	ttl     time.Duration
	nowFn   func() time.Time
}

// NewKeyManagerStatusTokenGenerator loads the public half of the
// signer's key (needed to derive the kid + to expose for the
// /root-keys responder) and returns a ready-to-use generator. TTL
// defaults to DefaultStatusTokenTTL when zero.
func NewKeyManagerStatusTokenGenerator(
	ctx context.Context,
	km port.KeyManager,
	keyID string,
	ttl time.Duration,
) (*KeyManagerStatusTokenGenerator, error) {
	pubAny, err := km.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("status-token: load public key: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("status-token: key %q is not ECDSA (type %T)", keyID, pubAny)
	}
	keyHash, err := anscrypto.SPKIKeyHash4(pub)
	if err != nil {
		return nil, fmt.Errorf("status-token: derive key hash: %w", err)
	}
	if ttl == 0 {
		ttl = DefaultStatusTokenTTL
	}
	return &KeyManagerStatusTokenGenerator{
		km:      km,
		keyID:   keyID,
		pub:     pub,
		keyHash: keyHash,
		ttl:     ttl,
		nowFn:   time.Now,
	}, nil
}

// WithClock overrides the clock — used in tests to pin iat/exp.
func (g *KeyManagerStatusTokenGenerator) WithClock(fn func() time.Time) *KeyManagerStatusTokenGenerator {
	g.nowFn = fn
	return g
}

// PublicKey implements StatusTokenGenerator.
func (g *KeyManagerStatusTokenGenerator) PublicKey() *ecdsa.PublicKey { return g.pub }

// GenerateStatusToken builds and signs a status token. Byte-for-byte
// wire compatibility with the reference TL's
// `KMSStatusTokenGenerator.GenerateStatusToken`.
func (g *KeyManagerStatusTokenGenerator) GenerateStatusToken(
	ctx context.Context,
	claims *StatusTokenClaims,
) ([]byte, error) {
	now := g.nowFn()

	// --- Payload ---
	payload := StatusTokenPayload{
		AgentID:            claims.AgentID,
		Status:             claims.Status,
		IAT:                now.Unix(),
		EXP:                now.Add(g.ttl).Unix(),
		ANSName:            claims.ANSName,
		ValidIdentityCerts: claims.ValidIdentityCerts,
		ValidServerCerts:   claims.ValidServerCerts,
		MetadataHashes:     claims.MetadataHashes,
	}

	// Deterministic encoding so equivalent inputs produce the same
	// payload bytes (helpful for caching + byte-identical replays).
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("status-token: cbor enc mode: %w", err)
	}
	payloadBytes, err := encMode.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("status-token: encode payload: %w", err)
	}

	// --- Protected header ---
	// kid label 4 is required + content_type label 3 pins the media
	// type inside the token itself (helpful when a status token
	// rides inside a larger envelope).
	protected := map[int]any{
		labelAlg:         algES256,
		labelKID:         g.keyHash,
		labelContentType: StatusTokenMediaType,
	}
	protectedBytes, err := encMode.Marshal(protected)
	if err != nil {
		return nil, fmt.Errorf("status-token: encode protected header: %w", err)
	}

	// --- Sig_structure1 (RFC 8152 §4.4) ---
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad: empty for status tokens
		payloadBytes,
	}
	sigStructureBytes, err := encMode.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("status-token: encode sig_structure: %w", err)
	}

	// --- Sign ---
	// The KeyManager returns a DER signature; COSE mandates
	// IEEE P1363 (raw r || s). Conversion is identical to the
	// receipt-signing path.
	digest := sha256.Sum256(sigStructureBytes)
	derSig, err := g.km.Sign(ctx, g.keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("status-token: sign: %w", err)
	}
	p1363, err := derToP1363(derSig)
	if err != nil {
		return nil, fmt.Errorf("status-token: DER→P1363: %w", err)
	}

	// --- Assemble COSE_Sign1 (tag 18) ---
	cose := cbor.Tag{
		Number: 18,
		Content: []any{
			protectedBytes,
			map[int]any{}, // unprotected: empty
			payloadBytes,
			p1363,
		},
	}
	out, err := encMode.Marshal(cose)
	if err != nil {
		return nil, fmt.Errorf("status-token: encode COSE_Sign1: %w", err)
	}
	return out, nil
}

// VerifyStatusToken parses a COSE_Sign1 status token, validates its
// ES256 signature against publicKey, and returns the decoded
// payload. Does NOT check EXP — caller decides whether to accept
// expired tokens (a just-expired token is still cryptographic
// evidence of a claim made a moment ago).
//
// Mirrors reference `receipt.VerifyStatusToken` (status.go:241).
func VerifyStatusToken(tokenBytes []byte, publicKey *ecdsa.PublicKey) (*StatusTokenPayload, error) {
	parsed, err := parseCOSESign1(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("status-token: parse: %w", err)
	}
	// Verify the signature using the existing COSE Sig_structure1
	// helper. We have to construct the same sig_structure the
	// generator signed.
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("status-token: cbor enc mode: %w", err)
	}
	sigStructure := []any{
		"Signature1",
		parsed.protectedBytes,
		[]byte{},
		parsed.payload,
	}
	sigStructureBytes, err := encMode.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("status-token: encode sig_structure: %w", err)
	}
	digest := sha256.Sum256(sigStructureBytes)

	// Parse the P1363 signature back to r/s big.Ints and verify.
	if len(parsed.signature) != 64 {
		return nil, fmt.Errorf("status-token: signature length %d; want 64", len(parsed.signature))
	}
	r := new(big.Int).SetBytes(parsed.signature[:32])
	s := new(big.Int).SetBytes(parsed.signature[32:])
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return nil, errors.New("status-token: signature invalid")
	}

	// Decode the payload.
	var payload StatusTokenPayload
	if err := cbor.Unmarshal(parsed.payload, &payload); err != nil {
		return nil, fmt.Errorf("status-token: decode payload: %w", err)
	}
	return &payload, nil
}

// derToP1363 converts an ECDSA ASN.1-DER signature to the
// IEEE P1363 raw-r||s form COSE mandates (RFC 8152 §8.1). For
// P-256 the output is exactly 64 bytes. Kept local to this file
// so the receipt package stays standalone (a helper also exists in
// internal/crypto but this package doesn't import it).
func derToP1363(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal DER: %w", err)
	}
	// P-256 R/S are each at most 32 bytes. Pad left with zeros.
	const n = 32
	out := make([]byte, 2*n)
	rb := sig.R.Bytes()
	sb := sig.S.Bytes()
	if len(rb) > n || len(sb) > n {
		return nil, fmt.Errorf("r/s exceed %d bytes", n)
	}
	copy(out[n-len(rb):n], rb)
	copy(out[2*n-len(sb):2*n], sb)
	return out, nil
}
