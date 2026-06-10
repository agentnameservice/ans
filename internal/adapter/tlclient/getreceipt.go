package tlclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/godaddy/ans/internal/tl/receipt"
)

// MerkleProof is the inclusion-proof view returned by GetReceipt.
// All byte fields are raw (NOT base64) — the receipt CBOR already
// stores them as bstr, and the caller doesn't gain anything from a
// second round-trip through base64. LeafHash is RFC 6962
// SHA-256(0x00 || canonical_event) computed locally from the
// receipt's attached payload.
type MerkleProof struct {
	TreeSize  uint64
	LeafIndex uint64
	LeafHash  []byte
	RootHash  []byte
	Path      [][]byte
}

// Sentinel errors callers match with errors.Is.
//
//   - ErrTLLeafUncommitted — the TL acknowledged the leaf append but
//     no signed checkpoint yet covers it. Maps from the TL's
//     503 + code=TL_LEAF_UNCOMMITTED response. Translated by the
//     attestation service into the same wire shape on the RA's
//     503 response, preserving the original code so verifiers see
//     a stable error vocabulary.
//   - ErrTLAgentNotFound — the TL has no event history for this
//     agentId, mapped from a 404 on /v1/agents/{id}/receipt.
//     Distinct from "RA never registered this agent"; the RA
//     service decides which 404 to surface.
//   - ErrTLNotReachable — every other transport/server failure. The
//     RA's attestation handler maps this to 503 TL_NOT_REACHABLE per
//     spec.
var (
	ErrTLLeafUncommitted = errors.New("tlclient: leaf appended but no covering checkpoint yet")
	ErrTLAgentNotFound   = errors.New("tlclient: tl has no events for agent")
	ErrTLNotReachable    = errors.New("tlclient: tl is not reachable")
)

// problemJSON mirrors the RFC 7807 problem-details shape every TL
// handler emits on failure. Only `Code` is load-bearing here — the
// other fields are echoed for log diagnosis.
type problemJSON struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

// GetReceipt fetches the SCITT COSE_Sign1 receipt for an agent and
// derives the inclusion-proof view from its embedded VDP header.
//
// Side effect of using the receipt's own VDP rather than a separate
// /v1/agents/{id} (badge) call: one network round-trip instead of
// two, and the proof + receipt are guaranteed to be from the same
// signed checkpoint generation. If we fetched them independently
// they could disagree mid-tick (the badge proof references one
// checkpoint, the receipt's VDP another) and the resulting
// attestation would be internally inconsistent.
//
// Returns:
//
//   - receiptBytes — the binary CBOR COSE_Sign1, ready to embed
//     verbatim into the attestation's `tl.receipt` field.
//   - proof — tree size, leaf index, leaf hash, root hash, sibling
//     path. LeafHash is recomputed locally as a self-check; if the
//     TL's payload bytes don't hash to the leaf the proof claims, the
//     caller should treat the response as compromised.
//
// Errors are classified into the three sentinels above so the
// attestation service can map cleanly to spec-defined 4xx/5xx codes.
func (c *Client) GetReceipt(ctx context.Context, agentID string) ([]byte, *MerkleProof, error) {
	if agentID == "" {
		return nil, nil, errors.New("tlclient: agentID required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v1/agents/"+agentID+"/receipt", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("tlclient: build request: %w", err)
	}
	req.Header.Set("Accept", receipt.MediaType)
	if c.apiKey != "" {
		// The TL's GetReceipt route is unauthenticated in the
		// reference, but if a deployment fronts it with an auth
		// proxy our existing apiKey lets us pass through cleanly.
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrTLNotReachable, err)
	}
	defer resp.Body.Close()

	// 64 KiB cap on a typical 1-2 KiB receipt; a single-leaf demo log
	// produces <300 bytes. Acts as a sanity guard against the TL
	// streaming an unbounded body — cf. the same defense in
	// cmd/ans-verify's walker.
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode == http.StatusOK:
		return decodeReceiptResponse(rawBody)
	case resp.StatusCode == http.StatusNotFound:
		return nil, nil, ErrTLAgentNotFound
	case resp.StatusCode == http.StatusServiceUnavailable:
		// The TL returns 503 for either "leaf not yet covered" or
		// a generic operational failure; distinguish by parsing the
		// problem-details `code`.
		var p problemJSON
		if jerr := json.Unmarshal(rawBody, &p); jerr == nil && p.Code == "TL_LEAF_UNCOMMITTED" {
			return nil, nil, ErrTLLeafUncommitted
		}
		return nil, nil, fmt.Errorf("%w: tl returned 503 with body %q", ErrTLNotReachable, rawBody)
	case resp.StatusCode >= 500:
		return nil, nil, fmt.Errorf("%w: tl returned %d", ErrTLNotReachable, resp.StatusCode)
	default:
		// 4xx other than 404 is treated as not-reachable from the RA's
		// perspective: the RA isn't supposed to construct invalid
		// requests against the TL, so a 4xx means something structural
		// is broken. Map to 503 rather than letting it surface as a
		// 500 to the attestation caller.
		return nil, nil, fmt.Errorf("%w: tl returned unexpected status %d", ErrTLNotReachable, resp.StatusCode)
	}
}

// decodeReceiptResponse parses the receipt bytes and derives the
// inclusion proof view. Split out so it can be unit-tested directly
// against a hand-rolled receipt without standing up an httptest
// server.
func decodeReceiptResponse(body []byte) ([]byte, *MerkleProof, error) {
	if len(body) == 0 {
		return nil, nil, fmt.Errorf("%w: tl returned empty receipt body", ErrTLNotReachable)
	}
	proof, err := receipt.ExtractInclusionProof(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse receipt VDP: %w", ErrTLNotReachable, err)
	}
	payload, err := receipt.ExtractPayload(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: extract receipt payload: %w", ErrTLNotReachable, err)
	}
	leafHash := receipt.ComputeLeafHash(payload)
	return body, &MerkleProof{
		TreeSize:  proof.TreeSize,
		LeafIndex: proof.LeafIndex,
		LeafHash:  leafHash,
		RootHash:  proof.RootHash,
		Path:      proof.Path,
	}, nil
}
