package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"

	"github.com/agentnameservice/ans/internal/lognote"
	"github.com/agentnameservice/ans/internal/tl/receipt"
)

// maxResponseBytes caps any single HTTP body the walker is willing
// to read. Sized for a full 256-leaf tile of ~64 KiB envelopes
// (16 MiB) with headroom; protects against a hostile or buggy TL
// streaming an unbounded body and OOMing the verifier.
const maxResponseBytes = 32 * 1024 * 1024

// agentIDPattern is the allowed shape for an agentId interpolated
// into a /v1/agents/{id}/... URL. Restricting to UUID syntax means a
// malicious TL leaf can't smuggle path traversal or query-string
// fragments through verifyMatches. The RA only ever issues UUIDs, so
// rejecting anything else is a no-cost defense.
var agentIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AgentMatch is one agent leaf that matched the provider filter
// during a tile-walk enumeration. LeafBytes is the JCS-canonical
// envelope bytes that were actually appended to the log — kept so
// the verify step can cross-check that the receipt's payload equals
// what we walked off the tile (defense against leaf substitution).
type AgentMatch struct {
	LeafIndex uint64
	AgentID   string
	AnsName   string
	Host      string
	EventType string
	LeafBytes []byte
}

// Terminal lifecycle states — events with these eventTypes are not
// considered "live" by reduceToLive. Kept as a small set rather than
// a "live whitelist" so that any new active-state event type added
// to the schema later (e.g. AGENT_SUSPENDED → reactivated) isn't
// silently filtered out by this client.
var terminalEventTypes = map[string]bool{
	"AGENT_REVOKED":    true,
	"AGENT_DEPRECATED": true,
}

// providerMatches reports whether host belongs to providerSuffix —
// either an exact match (case-insensitive, trailing dot tolerated)
// or a strict subdomain (`host = "x.suffix"`).
//
// Empty inputs never match. The "x.suffix" rule rejects accidental
// substring matches like "evilsuffix.com" vs "suffix.com".
func providerMatches(host, providerSuffix string) bool {
	if host == "" || providerSuffix == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	s := strings.ToLower(strings.TrimSuffix(providerSuffix, "."))
	if h == s {
		return true
	}
	return strings.HasSuffix(h, "."+s)
}

// agentIdentity is the subset of an envelope the walker needs to
// decide whether a leaf matches the provider filter.
type agentIdentity struct {
	AgentID   string
	AnsName   string
	Host      string
	EventType string
}

// extractAgentIdentity pulls the identity fields needed for provider
// filtering out of a leaf's JCS-canonical envelope JSON. V1 and V2
// envelopes share the `payload.producer.event.{ansName, eventType,
// agent.host}` path, so a single decoder serves both lanes.
//
// Returns ok=false when the bytes don't parse as JSON or neither
// ansName nor agent.host is populated (which lets the caller skip
// non-event leaves without surfacing an error).
func extractAgentIdentity(envelope []byte) (agentIdentity, bool) {
	var env struct {
		Payload struct {
			Producer struct {
				Event struct {
					AnsID     string `json:"ansId"`
					AnsName   string `json:"ansName"`
					EventType string `json:"eventType"`
					Agent     struct {
						Host string `json:"host"`
					} `json:"agent"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return agentIdentity{}, false
	}
	e := env.Payload.Producer.Event
	if e.AnsName == "" && e.Agent.Host == "" {
		return agentIdentity{}, false
	}
	return agentIdentity{
		AgentID:   e.AnsID,
		AnsName:   e.AnsName,
		Host:      e.Agent.Host,
		EventType: e.EventType,
	}, true
}

// decodeEntryBundle parses a c2sp tlog-tiles entry bundle into its
// leaf byte-slices, hiding the tessera api dependency behind a thin
// helper so the walker logic is easy to unit-test against synthetic
// bundles.
func decodeEntryBundle(raw []byte) ([][]byte, error) {
	var b api.EntryBundle
	if err := b.UnmarshalText(raw); err != nil {
		return nil, err
	}
	return b.Entries, nil
}

// walkProviderAgents enumerates every leaf in [0, treeSize) by
// fetching entry tiles from baseURL, decoding each leaf envelope,
// and returning the subset whose agent.host falls under
// providerSuffix.
//
// Tile fetches run concurrently bounded by concurrency (clamped to
// [1, 64]). Matches are emitted in log (leaf-index) order regardless
// of fetch completion order so downstream consumers can treat the
// result as a stable timeline. concurrency=0 selects a sensible
// default for the caller.
//
// Note: this is a per-leaf scan, not per-agent deduplication. An
// agent that has multiple events in the log will appear multiple
// times. Lifecycle reduction is reduceToLive's job — keeps the
// walker's contract narrow ("every matching leaf, in order").
func walkProviderAgents(
	ctx context.Context,
	client *http.Client,
	baseURL, providerSuffix string,
	treeSize uint64,
	concurrency int,
) ([]AgentMatch, error) {
	if treeSize == 0 {
		return nil, nil
	}
	concurrency = clampConcurrency(concurrency)

	const w = uint64(layout.EntryBundleWidth) // 256
	nTiles := (treeSize + w - 1) / w

	// Per-tile result slot: either parsed entries or the first error.
	// Indexed by tile position so we can emit matches in log order
	// without sorting later. Slots a worker never reaches stay
	// zero-value; the post-loop scan treats that as "fetch was
	// cancelled" and prefers the captured firstErr.
	type tileResult struct {
		entries [][]byte
		err     error
	}
	results := make([]tileResult, nTiles)

	jobs := make(chan uint64, concurrency)
	var wg sync.WaitGroup
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// firstErr captures the actual triggering error so the caller
	// sees the root cause, not whichever tile happens to be lowest-
	// indexed when other slots are still zero from an early cancel.
	var firstErr atomic.Pointer[error]
	recordErr := func(err error) {
		// CompareAndSwap-style: only the first failing worker wins.
		firstErr.CompareAndSwap(nil, &err)
		cancel()
	}

	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tileIdx := range jobs {
				if wctx.Err() != nil {
					// Drain remaining jobs without doing work so the
					// producer's `jobs <- tileIdx` send completes for
					// every tile, otherwise close(jobs) deadlocks.
					continue
				}
				partial := layout.PartialTileSize(0, tileIdx, treeSize)
				path := layout.EntriesPath(tileIdx, partial)
				raw, err := httpGetBytes(wctx, client, baseURL+"/"+path)
				if err != nil {
					wrapped := fmt.Errorf("fetch %s: %w", path, err)
					results[tileIdx] = tileResult{err: wrapped}
					recordErr(wrapped)
					continue
				}
				entries, err := decodeEntryBundle(raw)
				if err != nil {
					wrapped := fmt.Errorf("decode %s: %w", path, err)
					results[tileIdx] = tileResult{err: wrapped}
					recordErr(wrapped)
					continue
				}
				// Tile-size guard: a full tile MUST be EntryBundleWidth
				// entries; a partial tile MUST be exactly `partial`. A
				// hostile or buggy TL serving a truncated or oversized
				// bundle would otherwise slip through silently — the
				// checkpoint signature only binds the tree shape, not
				// the bytes of any individual tile. Fail closed.
				wantLen := uint64(layout.EntryBundleWidth)
				if partial != 0 {
					wantLen = uint64(partial)
				}
				if uint64(len(entries)) != wantLen {
					wrapped := fmt.Errorf("%s: bundle has %d entries, want %d", path, len(entries), wantLen)
					results[tileIdx] = tileResult{err: wrapped}
					recordErr(wrapped)
					continue
				}
				results[tileIdx] = tileResult{entries: entries}
			}
		}()
	}
	// Producer: stop enqueueing on cancel so a failure in one worker
	// doesn't force the producer to push N more indices into the
	// channel before close(jobs) unblocks. Workers still drain any
	// already-queued indices via their wctx.Err() check.
producer:
	for tileIdx := range nTiles {
		select {
		case jobs <- tileIdx:
		case <-wctx.Done():
			break producer
		}
	}
	close(jobs)
	wg.Wait()

	// Prefer the captured first error (most accurate root cause).
	// Fall back to the caller's ctx error so an external timeout or
	// cancel returns a non-nil error even when no fetch reported one.
	if perr := firstErr.Load(); perr != nil {
		return nil, *perr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	matches := make([]AgentMatch, 0)
	for tileIdx, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		base := uint64(tileIdx) * w
		for i, leaf := range r.entries {
			id, ok := extractAgentIdentity(leaf)
			if !ok {
				continue
			}
			if !providerMatches(id.Host, providerSuffix) {
				continue
			}
			matches = append(matches, AgentMatch{
				LeafIndex: base + uint64(i),
				AgentID:   id.AgentID,
				AnsName:   id.AnsName,
				Host:      id.Host,
				EventType: id.EventType,
				LeafBytes: leaf,
			})
		}
	}
	return matches, nil
}

// clampConcurrency normalizes user input. 0 → 8 (the default), then
// floor at 1 and ceiling at 64 so a misconfigured CLI flag can't
// either deadlock the walker or DOS the TL.
func clampConcurrency(c int) int {
	const def, lo, hi = 8, 1, 64
	if c == 0 {
		return def
	}
	if c < lo {
		return lo
	}
	if c > hi {
		return hi
	}
	return c
}

// reduceToLive collapses a per-leaf match list into one row per
// AnsName, keeping the most recent leaf, then drops agents whose
// latest event puts them in a terminal lifecycle state (revoked /
// deprecated). This is the answer to "what agents currently live
// under provider X" — distinct from the raw walker output which is
// "every event ever logged under provider X".
//
// Matches with an empty AnsName are passed through individually so
// the caller doesn't lose data from a malformed legacy leaf.
func reduceToLive(matches []AgentMatch) []AgentMatch {
	latest := make(map[string]AgentMatch, len(matches))
	out := make([]AgentMatch, 0, len(matches))
	for _, m := range matches {
		if m.AnsName == "" {
			out = append(out, m)
			continue
		}
		if prev, ok := latest[m.AnsName]; !ok || m.LeafIndex > prev.LeafIndex {
			latest[m.AnsName] = m
		}
	}
	for _, m := range latest {
		if terminalEventTypes[m.EventType] {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LeafIndex < out[j].LeafIndex })
	return out
}

// VerifyResult is the outcome of one per-match receipt verification.
type VerifyResult struct {
	Match AgentMatch
	OK    bool
	Err   error
}

// verifyMatches fetches and verifies the SCITT COSE receipt for each
// match, running concurrency workers in parallel. Results are
// returned in match-input order. A missing agentId is a hard error
// for that match — the receipt URL is keyed by agentId, so without
// one we can't even attempt a fetch.
//
// verifyOne is injected so callers can swap the verification logic
// in tests; production callers pass makeReceiptVerifier(keys).
//
// The function returns nil error overall — per-match failures are
// surfaced via VerifyResult.Err so the caller can decide whether a
// partial failure is fatal or informational.
func verifyMatches(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	matches []AgentMatch,
	verifyOne func(receiptBytes []byte) error,
	concurrency int,
) []VerifyResult {
	if len(matches) == 0 {
		return nil
	}
	concurrency = clampConcurrency(concurrency)

	out := make([]VerifyResult, len(matches))
	jobs := make(chan int, concurrency)
	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				m := matches[idx]
				if m.AgentID == "" {
					out[idx] = VerifyResult{Match: m, Err: errors.New("match has no agentId")}
					continue
				}
				if !agentIDPattern.MatchString(m.AgentID) {
					// Defense in depth: the agentId came from a TL
					// leaf we don't fully trust at this point in the
					// pipeline. Anything that isn't a UUID can't be a
					// real RA-issued id, so refuse to interpolate it
					// into a URL.
					out[idx] = VerifyResult{Match: m, Err: fmt.Errorf("agentId %q is not a valid UUID", m.AgentID)}
					continue
				}
				rec, err := httpGetBytes(ctx, client, baseURL+"/v1/agents/"+m.AgentID+"/receipt")
				if err != nil {
					out[idx] = VerifyResult{Match: m, Err: fmt.Errorf("fetch receipt: %w", err)}
					continue
				}
				if err := verifyOne(rec); err != nil {
					out[idx] = VerifyResult{Match: m, Err: fmt.Errorf("verify: %w", err)}
					continue
				}
				// Leaf-substitution guard: the receipt's payload IS
				// the canonical envelope bytes that were appended to
				// the log. If they don't match the bytes we walked
				// off the tile, the TL served a forged tile for a
				// real agentId — receipt-only verification would
				// silently pass. Skip the check when the walker
				// didn't capture LeafBytes (legacy callers).
				if m.LeafBytes != nil {
					payload, perr := receipt.ExtractPayload(rec)
					if perr != nil {
						out[idx] = VerifyResult{Match: m, Err: fmt.Errorf("extract receipt payload: %w", perr)}
						continue
					}
					if !bytes.Equal(payload, m.LeafBytes) {
						out[idx] = VerifyResult{Match: m, Err: errors.New("receipt payload does not match tile leaf (possible leaf substitution)")}
						continue
					}
				}
				out[idx] = VerifyResult{Match: m, OK: true}
			}
		}()
	}
	for i := range matches {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

// makeReceiptVerifier returns a closure that tries each key against
// a receipt and returns nil on the first success. Used by callers
// that have already loaded /root-keys; tests substitute their own
// stub directly into verifyMatches.
func makeReceiptVerifier(keys []*ecdsa.PublicKey) func([]byte) error {
	return func(b []byte) error {
		if len(keys) == 0 {
			return errors.New("no verification keys available")
		}
		var lastErr error
		for _, k := range keys {
			err := receipt.Verify(b, k)
			if err == nil {
				return nil
			}
			lastErr = err
		}
		return lastErr
	}
}

// checkpointTreeSize fetches /v1/log/checkpoint and returns the
// declared logSize WITHOUT verifying the checkpoint signature.
// Retained for tests and for callers that don't have the verifier
// keys handy; production list-mode uses verifiedCheckpoint instead.
func checkpointTreeSize(ctx context.Context, client *http.Client, baseURL string) (uint64, error) {
	body, err := httpGetBytes(ctx, client, baseURL+"/v1/log/checkpoint")
	if err != nil {
		return 0, err
	}
	var cp struct {
		LogSize uint64 `json:"logSize"`
	}
	if err := json.Unmarshal(body, &cp); err != nil {
		return 0, fmt.Errorf("decode checkpoint json: %w", err)
	}
	return cp.LogSize, nil
}

// verifiedCheckpoint fetches /checkpoint (raw C2SP signed note),
// verifies the signature against one of keysByHash, and returns the
// parsed origin/size/rootHash.
//
// Without this step, a hostile TL could return a smaller logSize on
// /v1/log/checkpoint than the real tree contains and the walker
// would never fetch the tiles holding agents the attacker wants
// hidden — a textbook omission attack against a transparency log.
//
// Parsing and signature verification live in internal/lognote so this
// binary links the verification path without the log-writer dependency
// tree (logstore + Tessera).
func verifiedCheckpoint(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	keysByHash map[string]*ecdsa.PublicKey,
) (*lognote.Checkpoint, error) {
	if len(keysByHash) == 0 {
		return nil, errors.New("no verification keys available")
	}
	body, err := httpGetBytes(ctx, client, baseURL+"/checkpoint")
	if err != nil {
		return nil, fmt.Errorf("fetch /checkpoint: %w", err)
	}
	return lognote.VerifyCheckpointNote(body, keysByHash)
}

// httpGetBytes is a minimal GET helper for the walker. Distinct from
// main.go's fetchBinary because that one returns the content-type the
// status-token path needs; the walker only ever wants the body.
//
// Bodies are capped at maxResponseBytes — a hostile or buggy TL
// streaming an unbounded response cannot OOM the verifier. Hitting
// the cap is surfaced as an explicit error rather than a silent
// truncation so callers don't decode partial JSON / partial tiles.
func httpGetBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// LimitReader+1 trick: read one byte past the cap so we can tell
	// "exactly at the cap" from "tried to overflow it".
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, fmt.Errorf("response body exceeds %d-byte cap", maxResponseBytes)
	}
	return body, nil
}

// listMain implements the `ans-verify list` subcommand: walk the log
// from index 0..treeSize, decoding each leaf envelope and printing
// the ones whose agent.host falls under -provider.
func listMain(args []string) {
	// ContinueOnError lets us print a consistent custom usage and
	// exit with code 1 on parse failure. flag.ExitOnError calls
	// os.Exit(2) internally before Parse returns, so the err-check
	// below would never fire.
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr,
			"usage: ans-verify list -provider <host> [-url <tl>] [-live=false] [-verify] [-concurrency N]")
		fs.PrintDefaults()
	}
	var (
		baseURL     string
		provider    string
		live        bool
		doVerify    bool
		concurrency int
	)
	fs.StringVar(&baseURL, "url", "http://localhost:18081",
		"Base URL of the transparency log")
	fs.StringVar(&provider, "provider", "",
		"Provider host suffix to filter on (e.g. darknetian.com)")
	fs.BoolVar(&live, "live", true,
		"Collapse to one row per agent and drop revoked/deprecated agents")
	fs.BoolVar(&doVerify, "verify", false,
		"After listing, fetch and verify each matched agent's SCITT receipt")
	fs.IntVar(&concurrency, "concurrency", 8,
		"Number of parallel HTTP workers (1-64)")
	if err := fs.Parse(args); err != nil {
		// fs.Usage already printed (Parse calls it on error).
		os.Exit(1)
	}
	if provider == "" {
		fs.Usage()
		os.Exit(1)
	}
	baseURL = strings.TrimRight(baseURL, "/")
	client := &http.Client{Timeout: 30 * time.Second}
	ctx := context.Background()

	// Always fetch /root-keys first — both the checkpoint signature
	// verification AND the per-match receipt verification depend on
	// them, so a missing-keys failure should fail fast before we do
	// any walking.
	keys, keysByHash, err := fetchRootKeys(baseURL)
	if err != nil {
		fatalf("fetch root-keys: %v", err)
	}
	cp, err := verifiedCheckpoint(ctx, client, baseURL, keysByHash)
	if err != nil {
		fatalf("verified checkpoint: %v", err)
	}
	matches, err := walkProviderAgents(ctx, client, baseURL, provider, cp.Size, concurrency)
	if err != nil {
		fatalf("walk: %v", err)
	}
	rawCount := len(matches)
	if live {
		matches = reduceToLive(matches)
	}

	fmt.Printf("=== ANS provider walk ===\n")
	fmt.Printf("TL Base URL: %s\n", baseURL)
	fmt.Printf("Provider:    %s\n", provider)
	fmt.Printf("Origin:      %s\n", cp.Origin)
	fmt.Printf("Tree size:   %d leaves (checkpoint signature ✓)\n", cp.Size)
	if live {
		fmt.Printf("Matched:     %d live agents (from %d raw leaves)\n\n",
			len(matches), rawCount)
	} else {
		fmt.Printf("Matched:     %d leaves\n\n", len(matches))
	}
	for _, m := range matches {
		// %q on every TL-supplied string to neutralize newlines and
		// terminal-control characters that could spoof output.
		fmt.Printf("  [%d] ansName=%q host=%q eventType=%q agentId=%q\n",
			m.LeafIndex, m.AnsName, m.Host, m.EventType, m.AgentID)
	}

	if !doVerify {
		return
	}
	results := verifyMatches(ctx, client, baseURL, matches, makeReceiptVerifier(keys), concurrency)
	var passed, failed int
	fmt.Println("\n── Receipt verification ──")
	for _, r := range results {
		if r.OK {
			passed++
			fmt.Printf("  ✓ ansName=%q agentId=%q\n", r.Match.AnsName, r.Match.AgentID)
			continue
		}
		failed++
		fmt.Printf("  ✗ ansName=%q agentId=%q: %v\n", r.Match.AnsName, r.Match.AgentID, r.Err)
	}
	fmt.Printf("\nVerified %d/%d receipts (%d failed)\n", passed, passed+failed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
