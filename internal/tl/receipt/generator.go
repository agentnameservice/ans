package receipt

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// InclusionProof carries the tree data needed by the VDP entry —
// produced by `internal/tl/service/BuildMerkleProof` and fed to
// GenerateReceipt.
type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      [][]byte
	RootHash  []byte
}

// Generator produces SCITT COSE_Sign1 receipts.
type Generator interface {
	// GenerateReceipt builds a receipt binding the given inclusion
	// proof to the given event bytes (the attached payload). Signs
	// via the configured KeyManager key.
	GenerateReceipt(ctx context.Context, proof *InclusionProof, eventBytes []byte) ([]byte, error)
	// PublicKey exposes the receipt signer's public key so
	// verifiers and the /root-keys endpoint can read it.
	PublicKey() *ecdsa.PublicKey
}

// KeyManagerGenerator implements Generator using port.KeyManager for
// signing. The KeyManager returns ASN.1 DER for ECDSA; we convert to
// IEEE P1363 at the COSE boundary per RFC 8152 §8.1.
type KeyManagerGenerator struct {
	km      port.KeyManager
	keyID   string
	pub     *ecdsa.PublicKey
	keyHash []byte // 4-byte SPKI opaque key hash — goes into COSE `kid`
	issuer  string // TL origin string — goes into the CWT `iss` claim
	nowFunc func() time.Time
}

// GeneratorOption tweaks a Generator at construction time.
type GeneratorOption func(*KeyManagerGenerator)

// WithNowFunc overrides the clock used for CWT `iat` — test-only.
func WithNowFunc(fn func() time.Time) GeneratorOption {
	return func(g *KeyManagerGenerator) { g.nowFunc = fn }
}

// NewKeyManagerGenerator constructs a Generator that signs via the
// given KeyManager key. The key must be an ECDSA P-256 key (ES256);
// this is checked at construction.
//
// `issuer` is the TL origin string (the same value Tessera writes
// into the first line of every checkpoint note); it ends up in the
// CWT `iss` claim so verifiers can correlate the receipt to a
// specific log.
func NewKeyManagerGenerator(ctx context.Context, km port.KeyManager, keyID, issuer string, opts ...GeneratorOption) (*KeyManagerGenerator, error) {
	if km == nil {
		return nil, errors.New("receipt: key manager required")
	}
	if keyID == "" {
		return nil, errors.New("receipt: keyID required")
	}
	pub, err := km.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("receipt: resolve key %q: %w", keyID, err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("receipt: key %q is not ECDSA (%T)", keyID, pub)
	}
	// Reject non-P256 keys up front — ES256 is fixed in COSE.
	if ecPub.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("receipt: key %q must be P-256 for ES256 (got %d-bit)", keyID, ecPub.Curve.Params().BitSize)
	}
	kh, err := anscrypto.SPKIKeyHash4(ecPub)
	if err != nil {
		return nil, fmt.Errorf("receipt: key hash: %w", err)
	}

	g := &KeyManagerGenerator{
		km:      km,
		keyID:   keyID,
		pub:     ecPub,
		keyHash: kh,
		issuer:  issuer,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(g)
	}
	return g, nil
}

// PublicKey returns the receipt signer's ECDSA public key.
func (g *KeyManagerGenerator) PublicKey() *ecdsa.PublicKey { return g.pub }

// KeyID returns the KeyManager ID (not the COSE kid — that's
// `keyHash`). Useful for logging and diagnostics.
func (g *KeyManagerGenerator) KeyID() string { return g.keyID }

// GenerateReceipt assembles the COSE_Sign1 structure and signs it.
//
// Layout (matches the reference TL's receipt byte layout):
//
//	protected := CBOR-encode of:
//	  { 1: -7, 4: keyHash, 395: 1, 15: { 1: issuer, 6: now.Unix() } }
//	unprotected := { 396: { -1: treeSize, -2: leafIndex, -3: path, -4: rootHash } }
//	payload := eventBytes (attached)
//	sig_structure := [ "Signature1", protected, external_aad=bstr(0), payload ]
//	sig := P1363(ECDSA-P256(SHA-256(sig_structure)))
//	COSE_Sign1 := CBOR tag 18 wrapping [ protected, unprotected, payload, sig ]
func (g *KeyManagerGenerator) GenerateReceipt(ctx context.Context, proof *InclusionProof, eventBytes []byte) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("receipt: proof required")
	}
	if len(eventBytes) == 0 {
		return nil, errors.New("receipt: eventBytes required (detached payloads not supported)")
	}

	// --- Protected header ---
	// Order doesn't matter for CBOR canonical encoding (integer keys
	// sort by value) — CoreDetEncOptions below ensures deterministic
	// output.
	protectedMap := map[int]any{
		labelAlg: algES256,
		labelKID: g.keyHash,
		labelVDS: vdsRFC9162SHA256,
		labelCWTClaims: map[int]any{
			cwtIss: g.issuer,
			cwtIat: g.nowFunc().Unix(),
		},
	}
	protectedBytes, err := detMarshal(protectedMap)
	if err != nil {
		return nil, fmt.Errorf("receipt: encode protected header: %w", err)
	}

	// --- Unprotected header: the VDP (Verifiable Data Structure Proof) ---
	vdp := map[int]any{
		inclusionProofTreeSize:  proof.TreeSize,
		inclusionProofLeafIndex: proof.LeafIndex,
		inclusionProofHashPath:  proof.Path,
		inclusionProofRootHash:  proof.RootHash,
	}
	unprotectedMap := map[int]any{
		labelVDP: vdp,
	}

	// --- Sig_structure (RFC 8152 §4.4) ---
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{},   // external_aad
		eventBytes, // attached payload
	}
	sigStructureBytes, err := detMarshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("receipt: encode Sig_structure: %w", err)
	}

	// --- Sign ---
	digest := sha256.Sum256(sigStructureBytes)
	derSig, err := g.km.Sign(ctx, g.keyID, digest[:])
	if err != nil {
		return nil, fmt.Errorf("receipt: sign: %w", err)
	}
	p1363Sig, err := anscrypto.DERToP1363(derSig, 32) // P-256 → 32-byte coord size
	if err != nil {
		return nil, fmt.Errorf("receipt: DER→P1363: %w", err)
	}

	// --- Assemble COSE_Sign1 as tag 18 ---
	coseArray := []any{
		protectedBytes,
		unprotectedMap,
		eventBytes,
		p1363Sig,
	}
	tagged := cbor.Tag{Number: 18, Content: coseArray}
	return detMarshal(tagged)
}

// detMarshal encodes with CBOR core-deterministic options (integer
// keys sorted by value, no indefinite lengths, smallest integer
// representations). This is what makes the receipt bytes reproducible
// — two calls with the same inputs produce the same bytes, which is
// how golden fixtures pin the wire format.
func detMarshal(v any) ([]byte, error) {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(v)
}
