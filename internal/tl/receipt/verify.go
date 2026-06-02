package receipt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// Verify checks a SCITT COSE_Sign1 receipt against the given public
// key. On success, the caller can trust: (a) the receipt was signed
// by `publicKey`, (b) the attached event bytes hash to a leaf
// covered by the inclusion proof in the unprotected VDP, and (c) the
// inclusion proof walks to the asserted root.
//
// This is an INDEPENDENT verifier — it doesn't share code with the
// generator so we can spot a generator bug instead of
// round-tripping through the same helper. Port of the reference
// TL's receipt-verify helper minus the detached-payload path
// (attached-only in this codebase).
func Verify(receiptBytes []byte, publicKey *ecdsa.PublicKey) error {
	parsed, err := parseCOSESign1(receiptBytes)
	if err != nil {
		return fmt.Errorf("receipt: parse: %w", err)
	}
	if len(parsed.payload) == 0 {
		return errors.New("receipt: detached payloads not supported in this TL")
	}

	proof, err := extractInclusionProof(parsed.unprotected)
	if err != nil {
		return fmt.Errorf("receipt: extract proof: %w", err)
	}

	// Compute RFC 9162 leaf hash from the attached payload and walk
	// the path to reconstruct the root.
	leafHash := rfc9162LeafHash(parsed.payload)
	computedRoot, err := rfc9162RootFromProof(leafHash, proof.LeafIndex, proof.TreeSize, proof.Path)
	if err != nil {
		return fmt.Errorf("receipt: walk inclusion proof: %w", err)
	}
	if len(proof.RootHash) != sha256.Size {
		return fmt.Errorf("receipt: invalid root hash length %d", len(proof.RootHash))
	}
	if computedRoot != [sha256.Size]byte(proof.RootHash) {
		return errors.New("receipt: computed root does not match proof root")
	}

	return verifySignature(parsed, publicKey)
}

// VerifyWithPEM is a convenience wrapper accepting a PEM-encoded
// public key, so callers can plumb the /root-keys response directly
// through without parsing the DER themselves.
func VerifyWithPEM(receiptBytes []byte, pubKeyPEM string) error {
	pub, err := parsePublicKeyPEM(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("receipt: parse PEM: %w", err)
	}
	return Verify(receiptBytes, pub)
}

// ExtractPayload parses a receipt and returns its attached event
// bytes. Useful for callers who want to inspect the event
// without running a full verification.
func ExtractPayload(receiptBytes []byte) ([]byte, error) {
	parsed, err := parseCOSESign1(receiptBytes)
	if err != nil {
		return nil, fmt.Errorf("receipt: parse: %w", err)
	}
	if len(parsed.payload) == 0 {
		return nil, errors.New("receipt: no attached payload")
	}
	return parsed.payload, nil
}

// ExtractKID parses a receipt and returns the 4-byte `kid` value
// from the COSE protected header (label 4). Callers pair this with
// the `<origin>+<keyhash>+<key>` lines served at /root-keys
// to map a receipt back to its signing key in O(1). Returns the raw
// bytes (not hex) — match the kid's original form. Returns a non-nil
// error if the receipt doesn't parse or has no kid.
func ExtractKID(receiptBytes []byte) ([]byte, error) {
	parsed, err := parseCOSESign1(receiptBytes)
	if err != nil {
		return nil, fmt.Errorf("receipt: parse: %w", err)
	}
	// The protected header is a serialized CBOR map. Decode only
	// the fields we care about rather than a full shape.
	var prot map[int]any
	if err := cbor.Unmarshal(parsed.protectedBytes, &prot); err != nil {
		return nil, fmt.Errorf("receipt: parse protected header: %w", err)
	}
	kidAny, ok := prot[labelKID]
	if !ok {
		return nil, errors.New("receipt: no kid in protected header")
	}
	kid, ok := kidAny.([]byte)
	if !ok {
		return nil, fmt.Errorf("receipt: kid is not []byte (type %T)", kidAny)
	}
	return kid, nil
}

// ComputeLeafHash returns the RFC 6962 §2.1 / RFC 9162 leaf hash:
// SHA-256(0x00 || entry). Exposed so callers (e.g., the ans-verify
// CLI) can display the expected leaf hash alongside the badge-
// reported leaf hash for cross-checking.
func ComputeLeafHash(entry []byte) []byte {
	h := rfc9162LeafHash(entry)
	out := make([]byte, len(h))
	copy(out, h[:])
	return out
}

// --- parsing internals (port of reference verify.go) ---

type coseSign1Parsed struct {
	protectedBytes []byte
	unprotected    map[int]any
	payload        []byte
	signature      []byte
}

// parseCOSESign1 accepts both tag-18-wrapped and untagged 4-element
// array forms. Matches the reference's permissive parser.
func parseCOSESign1(data []byte) (*coseSign1Parsed, error) {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err == nil && tag.Number == 18 {
		return decodeCOSEContent(tag.Content)
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("data is neither tag-18 nor CBOR array: %w", err)
	}
	return decodeCOSERaw(arr)
}

func decodeCOSEContent(content any) (*coseSign1Parsed, error) {
	re, err := cbor.Marshal(content)
	if err != nil {
		return nil, err
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(re, &arr); err != nil {
		return nil, err
	}
	return decodeCOSERaw(arr)
}

func decodeCOSERaw(arr []cbor.RawMessage) (*coseSign1Parsed, error) {
	if len(arr) != 4 {
		return nil, fmt.Errorf("COSE_Sign1 must have 4 elements, got %d", len(arr))
	}
	out := &coseSign1Parsed{}
	if err := cbor.Unmarshal(arr[0], &out.protectedBytes); err != nil {
		return nil, fmt.Errorf("protected header: %w", err)
	}
	var rawUnp map[any]any
	if err := cbor.Unmarshal(arr[1], &rawUnp); err != nil {
		return nil, fmt.Errorf("unprotected header: %w", err)
	}
	out.unprotected = normalizeIntMap(rawUnp)
	// Payload — attached bytes or nil. Try bytes first; fall through
	// to nil for detached.
	var payloadPtr *[]byte
	if err := cbor.Unmarshal(arr[2], &payloadPtr); err == nil && payloadPtr != nil {
		out.payload = *payloadPtr
	}
	if err := cbor.Unmarshal(arr[3], &out.signature); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return out, nil
}

func normalizeIntMap(raw map[any]any) map[int]any {
	out := make(map[int]any, len(raw))
	for k, v := range raw {
		intKey := toInt(k)
		if nested, ok := v.(map[any]any); ok {
			out[intKey] = normalizeIntMap(nested)
		} else {
			out[intKey] = v
		}
	}
	return out
}

// toInt narrows a CBOR-decoded numeric to int. The values it sees
// (COSE labels, claim IDs, small enums) are bounded well within int
// range — the conversions are safe in this context. Tessera-style
// leaf indexes are handled via toUint64, not this helper.
//
//nolint:gosec // G115: callers feed bounded small-ints (label codes, claim IDs)
func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case int32:
		return int(n)
	case uint32:
		return int(n)
	case int8:
		return int(n)
	case uint8:
		return int(n)
	case int16:
		return int(n)
	case uint16:
		return int(n)
	case uint:
		return int(n)
	default:
		return 0
	}
}

type extractedProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      [][]byte
	RootHash  []byte
}

// InclusionProofView is the public projection of the receipt's
// embedded RFC 9162 inclusion proof. Returned by ExtractInclusionProof
// so consumers outside this package — notably the RA's tlclient,
// which needs the tree-size + leaf hash to bind a receipt into a
// signed agent attestation — don't have to re-implement CBOR
// COSE_Sign1 parsing.
type InclusionProofView struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      [][]byte
	RootHash  []byte
}

// ExtractInclusionProof parses a SCITT COSE_Sign1 receipt and
// returns the inclusion proof embedded in its unprotected VDP
// header. Errors propagate from the COSE parser (invalid CBOR,
// wrong tag) and from the VDP decoder (missing fields, wrong
// types).
//
// Does NOT verify the signature — that's the caller's job via
// receipt.Verify. ExtractInclusionProof is purely structural.
func ExtractInclusionProof(receiptBytes []byte) (*InclusionProofView, error) {
	parsed, err := parseCOSESign1(receiptBytes)
	if err != nil {
		return nil, err
	}
	p, err := extractInclusionProof(parsed.unprotected)
	if err != nil {
		return nil, err
	}
	return &InclusionProofView{
		TreeSize:  p.TreeSize,
		LeafIndex: p.LeafIndex,
		Path:      p.Path,
		RootHash:  p.RootHash,
	}, nil
}

func extractInclusionProof(unprotected map[int]any) (*extractedProof, error) {
	vdpRaw, ok := unprotected[labelVDP]
	if !ok {
		return nil, fmt.Errorf("unprotected header missing VDP (label %d)", labelVDP)
	}
	vdpMap, ok := vdpRaw.(map[int]any)
	if !ok {
		return nil, errors.New("VDP is not a map")
	}
	p := &extractedProof{}

	if v, ok := vdpMap[inclusionProofTreeSize]; ok {
		p.TreeSize = toUint64(v)
	} else {
		return nil, errors.New("VDP missing treeSize")
	}
	if v, ok := vdpMap[inclusionProofLeafIndex]; ok {
		p.LeafIndex = toUint64(v)
	} else {
		return nil, errors.New("VDP missing leafIndex")
	}
	pathRaw, ok := vdpMap[inclusionProofHashPath]
	if !ok {
		return nil, errors.New("VDP missing hashPath")
	}
	path, err := toByteSlices(pathRaw)
	if err != nil {
		return nil, fmt.Errorf("VDP hashPath: %w", err)
	}
	p.Path = path

	rootRaw, ok := vdpMap[inclusionProofRootHash]
	if !ok {
		return nil, errors.New("VDP missing rootHash")
	}
	rootBytes, ok := rootRaw.([]byte)
	if !ok {
		return nil, errors.New("VDP rootHash is not bytes")
	}
	p.RootHash = rootBytes
	return p, nil
}

// toUint64 narrows a CBOR-decoded numeric to uint64. Inputs are
// tree-size / leaf-index values which are non-negative by the
// transparency-log model — Tessera issues monotonically increasing
// 0-based indexes and tree-sizes are counts.
//
//nolint:gosec // G115: caller-supplied values are tree positions, always ≥ 0
func toUint64(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		return uint64(n)
	case int:
		return uint64(n)
	case uint:
		return uint64(n)
	default:
		return 0
	}
}

func toByteSlices(v any) ([][]byte, error) {
	switch val := v.(type) {
	case [][]byte:
		return val, nil
	case []any:
		out := make([][]byte, len(val))
		for i, e := range val {
			b, ok := e.([]byte)
			if !ok {
				return nil, fmt.Errorf("path element %d is not bytes", i)
			}
			out[i] = b
		}
		return out, nil
	}
	return nil, fmt.Errorf("hashPath unexpected type %T", v)
}

// --- RFC 9162 Merkle math ---

func rfc9162LeafHash(entry []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// rfc9162RootFromProof walks the inclusion proof per RFC 9162 §2.1.3.2.
func rfc9162RootFromProof(leafHash [sha256.Size]byte, leafIndex, treeSize uint64, path [][]byte) ([sha256.Size]byte, error) {
	if treeSize == 0 {
		return [sha256.Size]byte{}, errors.New("tree size is zero")
	}
	if leafIndex >= treeSize {
		return [sha256.Size]byte{}, fmt.Errorf("leaf index %d >= tree size %d", leafIndex, treeSize)
	}

	fn := leafIndex
	sn := treeSize - 1
	r := leafHash

	for _, p := range path {
		if len(p) != sha256.Size {
			return [sha256.Size]byte{}, fmt.Errorf("path element wrong length: %d", len(p))
		}
		if fn&1 == 1 || fn == sn {
			r = hashChildren(p, r[:])
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = hashChildren(r[:], p)
		}
		fn >>= 1
		sn >>= 1
	}
	if fn != 0 {
		return [sha256.Size]byte{}, errors.New("proof path too short")
	}
	return r, nil
}

func hashChildren(left, right []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// --- signature verification ---

func verifySignature(parsed *coseSign1Parsed, pub *ecdsa.PublicKey) error {
	// Sig_structure1 = [ "Signature1", body_protected, external_aad(empty),
	//                    payload(attached) ]
	payload := parsed.payload
	sigStructure := []any{
		"Signature1",
		parsed.protectedBytes,
		[]byte{},
		payload,
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return fmt.Errorf("encode Sig_structure mode: %w", err)
	}
	sigBytes, err := em.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("encode Sig_structure: %w", err)
	}
	digest := sha256.Sum256(sigBytes)

	if len(parsed.signature) != 64 {
		return fmt.Errorf("invalid ES256 signature length %d", len(parsed.signature))
	}
	r := new(big.Int).SetBytes(parsed.signature[:32])
	s := new(big.Int).SetBytes(parsed.signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("ECDSA signature invalid")
	}
	return nil
}

// --- PEM helper ---

func parsePublicKeyPEM(s string) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(pemDecode(s))
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("PEM key is not ECDSA")
	}
	return ec, nil
}
