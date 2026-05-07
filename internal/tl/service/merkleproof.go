package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/transparency-dev/tessera/client"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	"github.com/godaddy/ans/internal/tl/logstore"
)

// MerkleProof is the JSON-friendly inclusion proof returned by the
// badge and audit endpoints. Shape mirrors the reference TL
// swagger's MerkleProof schema so external verifiers built against
// the reference can consume ours unchanged.
//
// Encoding rules (pinned by reference):
//
//   - LeafHash   — hex of SHA-256(0x00 || canonical envelope) — RFC 6962.
//   - Path[i]    — standard-base64 of each sibling hash from leaf to root.
//   - RootHash   — standard-base64 of the tree root at TreeSize.
//   - TreeSize   — the tree size the proof is constructed against.
//   - TreeVersion — always 1 for now; reference carries a TODO to
//     roll this forward on breaking tree changes.
type MerkleProof struct {
	LeafHash      string   `json:"leafHash,omitempty"`
	LeafIndex     *int64   `json:"leafIndex,omitempty"`
	Path          []string `json:"path,omitempty"`
	RootHash      string   `json:"rootHash,omitempty"`
	RootSignature string   `json:"rootSignature,omitempty"`
	TreeSize      int64    `json:"treeSize,omitempty"`
	TreeVersion   int64    `json:"treeVersion,omitempty"`
}

// ErrProofLeafNotCovered means the latest checkpoint doesn't yet
// cover this leaf — Tessera hasn't integrated a checkpoint that
// spans the leaf's index. Callers can retry later once the
// checkpoint ticker runs.
var ErrProofLeafNotCovered = errors.New("merkleproof: leaf not covered by latest checkpoint")

// BuildMerkleProof assembles an inclusion proof for a specific
// event. Returns ErrProofLeafNotCovered if the latest checkpoint
// hasn't integrated far enough to cover the event's leaf index —
// callers (notably the badge handler) decide whether to 503, omit
// the proof, or return a cached older one.
func BuildMerkleProof(ctx context.Context, log *logstore.Log, rec *sqlitetl.EventRecord) (*MerkleProof, error) {
	reader := log.Reader()
	cpBytes, err := reader.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("merkleproof: read checkpoint: %w", err)
	}
	size, rootHash, err := parseSumdbCheckpoint(cpBytes)
	if err != nil {
		return nil, fmt.Errorf("merkleproof: parse checkpoint: %w", err)
	}
	if rec.LeafIndex >= size {
		return nil, ErrProofLeafNotCovered
	}

	builder, err := client.NewProofBuilder(ctx, size, reader.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("merkleproof: new builder: %w", err)
	}
	rawPath, err := builder.InclusionProof(ctx, rec.LeafIndex)
	if err != nil {
		return nil, fmt.Errorf("merkleproof: inclusion proof: %w", err)
	}

	pathB64 := make([]string, len(rawPath))
	for i, p := range rawPath {
		pathB64[i] = base64.StdEncoding.EncodeToString(p)
	}
	li := int64(rec.LeafIndex) //nolint:gosec  // leaf indices fit in int64 for the life of the project

	// LeafHash is stored as hex on the row — the reference's
	// MerkleProof also carries it as hex (verifiers who recompute
	// SHA-256(0x00 || canonical) produce the same hex).
	return &MerkleProof{
		LeafHash:    rec.LeafHashHex,
		LeafIndex:   &li,
		Path:        pathB64,
		RootHash:    base64.StdEncoding.EncodeToString(rootHash),
		TreeSize:    int64(size), //nolint:gosec  // same reasoning as LeafIndex
		TreeVersion: 1,
	}, nil
}

// parseSumdbCheckpoint extracts tree size + root hash from a
// sumdb-note checkpoint. The format is documented in RFC 9162 §4.1
// and is what Tessera writes: three header lines (origin, size,
// base64 root hash) followed by a blank line then signatures.
//
// We only need size and root hash here — signatures are handled
// separately when a caller wants to include the note-signer's proof
// signature in the MerkleProof.RootSignature field (Stage-3 work).
func parseSumdbCheckpoint(note []byte) (uint64, []byte, error) {
	// Reuse the service-local parser for consistency with the cache.
	size, rootHex, err := parseCheckpointHeader(note)
	if err != nil {
		return 0, nil, err
	}
	rootBytes, err := hex.DecodeString(rootHex)
	if err != nil {
		return 0, nil, fmt.Errorf("decode root hex: %w", err)
	}
	return size, rootBytes, nil
}
