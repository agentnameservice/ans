package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	"github.com/godaddy/ans/internal/tl/receipt"
)

// decodeStdBase64 is a tiny convenience around StdEncoding.DecodeString
// that returns a useful error message.
func decodeStdBase64(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode %q: %w", s, err)
	}
	return raw, nil
}

// ErrLeafNotYetCovered is returned when a receipt is requested for
// a leaf that has been appended but is not yet covered by a signed
// checkpoint. Callers should retry after the configured checkpoint
// interval; the TL handler maps this to 503 with Retry-After.
var ErrLeafNotYetCovered = errors.New("tl: leaf not yet covered by a signed checkpoint")

// Receipt is the wire representation handed to the handler: raw
// COSE_Sign1 bytes + the content-type the handler should stamp on
// the response. Keeping the content-type in the return value means
// the service is authoritative for the wire format — if a future
// change swaps to JSON-WebSignature or a v2 COSE variant, only this
// file changes.
type Receipt struct {
	Bytes       []byte
	ContentType string
}

// ReceiptService issues and caches SCITT COSE_Sign1 receipts.
//
// Each receipt contains an RFC 9162 inclusion proof (built via the
// shared BuildMerkleProof helper) and the JCS-canonical envelope
// bytes of the target event as the attached COSE payload. Signed by
// the TL's receipt-signing key (ECDSA P-256 / ES256).
//
// Receipts are cached in `tl_receipts` keyed by `(leaf_index,
// tree_size)` — a new checkpoint advances tree_size, which
// invalidates old receipts' usability as "current" but keeps them
// valid as historical receipts against their original tree size.
type ReceiptService struct {
	log       *LogService
	receipts  *sqlitetl.ReceiptStore
	generator receipt.Generator
}

// NewReceiptService constructs a ReceiptService.
//
// The generator is created via internal/tl/receipt.NewKeyManagerGenerator
// at wire-up time (`cmd/ans-tl/main.go`) so this service doesn't
// need to know about KeyManager details.
func NewReceiptService(log *LogService, receipts *sqlitetl.ReceiptStore, generator receipt.Generator) *ReceiptService {
	return &ReceiptService{log: log, receipts: receipts, generator: generator}
}

// ForAgent returns a receipt for the most recent event of an agent.
// Uses the cache if a receipt exists for the current (leafIndex,
// treeSize) pair; otherwise builds a new one, caches, and returns.
func (s *ReceiptService) ForAgent(ctx context.Context, agentID string) (*Receipt, error) {
	rec, err := s.log.LatestEventByAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	return s.buildOrFetch(ctx, rec)
}

// ForLeafIndex returns a receipt for a specific leaf.
func (s *ReceiptService) ForLeafIndex(ctx context.Context, idx uint64) (*Receipt, error) {
	rec, err := s.log.EventByLeafIndex(ctx, idx)
	if err != nil {
		return nil, err
	}
	return s.buildOrFetch(ctx, rec)
}

func (s *ReceiptService) buildOrFetch(ctx context.Context, rec *sqlitetl.EventRecord) (*Receipt, error) {
	// Build the Merkle proof — shared with the badge handler via
	// the BuildMerkleProof helper, so the receipt's proof is always
	// consistent with the badge's merkleProof field.
	proof, err := BuildMerkleProof(ctx, s.log.log, rec)
	if err != nil {
		if errors.Is(err, ErrProofLeafNotCovered) {
			return nil, ErrLeafNotYetCovered
		}
		return nil, err
	}

	// Cache lookup by (leafIndex, treeSize). If a receipt was already
	// minted for this exact pair it's byte-identical payload-wise
	// (same event bytes + same proof); the CBOR signature isn't
	// deterministic but the receipt is still cryptographically valid.
	treeSize := uint64(proof.TreeSize) //nolint:gosec  // int64→uint64 always safe for tree sizes
	if cached, cerr := s.receipts.FindByAgentID(ctx, rec.AgentID, treeSize); cerr == nil && cached != nil {
		return &Receipt{
			Bytes:       cached.ReceiptBlob,
			ContentType: receipt.MediaType,
		}, nil
	}

	// Convert the JSON-friendly MerkleProof into the receipt
	// package's byte-oriented InclusionProof. proof.RootHash is
	// standard-base64 in MerkleProof for JSON consumers; we stored
	// the raw bytes in the store, but the helper only returns the
	// encoded form. Re-decode.
	rootBytes, err := decodeStdBase64(proof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("receipt: decode root hash: %w", err)
	}
	path := make([][]byte, len(proof.Path))
	for i, p := range proof.Path {
		raw, err := decodeStdBase64(p)
		if err != nil {
			return nil, fmt.Errorf("receipt: decode path[%d]: %w", i, err)
		}
		path[i] = raw
	}
	var leafIndex uint64
	if proof.LeafIndex != nil {
		// Tree leaf indexes are non-negative by construction; the
		// int64→uint64 cast is safe in this domain.
		leafIndex = uint64(*proof.LeafIndex) //nolint:gosec // G115: leaf index always ≥ 0
	}
	ip := &receipt.InclusionProof{
		TreeSize:  treeSize,
		LeafIndex: leafIndex,
		Path:      path,
		RootHash:  rootBytes,
	}

	coseBytes, err := s.generator.GenerateReceipt(ctx, ip, []byte(rec.RawEvent))
	if err != nil {
		return nil, fmt.Errorf("receipt: generate: %w", err)
	}

	// Cache best-effort — failure here doesn't prevent returning the
	// receipt we just computed. The next request will recompute.
	_ = s.receipts.Store(ctx, rec.LeafIndex, rec.AgentID, treeSize, coseBytes)

	return &Receipt{
		Bytes:       coseBytes,
		ContentType: receipt.MediaType,
	}, nil
}
