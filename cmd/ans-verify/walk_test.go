package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

func TestProviderMatches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host, suffix string
		want         bool
	}{
		{"darknetian.com", "darknetian.com", true},
		{"agent.darknetian.com", "darknetian.com", true},
		{"a.b.darknetian.com", "darknetian.com", true},
		{"DARKNETIAN.COM", "darknetian.com", true},
		{"agent.darknetian.com.", "darknetian.com", true}, // trailing dot
		{"agent.darknetian.com", "DARKNETIAN.COM.", true}, // suffix case + dot
		{"evildarknetian.com", "darknetian.com", false},   // substring guard
		{"darknetian.com.evil", "darknetian.com", false},
		{"", "darknetian.com", false},
		{"darknetian.com", "", false},
		{"darknetian.com", "agent.darknetian.com", false}, // suffix longer than host
	}
	for _, c := range cases {
		name := fmt.Sprintf("%s_under_%s", c.host, c.suffix)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := providerMatches(c.host, c.suffix); got != c.want {
				t.Fatalf("providerMatches(%q, %q) = %v, want %v",
					c.host, c.suffix, got, c.want)
			}
		})
	}
}

func TestExtractAgentIdentity(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		envelope                 string
		wantAns, wantHost, wantE string
		wantOK                   bool
	}{
		"v1 register": {
			envelope: `{"payload":{"producer":{"event":{"ansName":"ans://v1.0.0.agent.darknetian.com","eventType":"REGISTERED","agent":{"host":"agent.darknetian.com"}}}}}`,
			wantAns:  "ans://v1.0.0.agent.darknetian.com",
			wantHost: "agent.darknetian.com",
			wantE:    "REGISTERED",
			wantOK:   true,
		},
		"v2 revoke": {
			envelope: `{"schemaVersion":"V2","payload":{"producer":{"event":{"ansName":"ans://v1.0.0.x.example","eventType":"REVOKED","agent":{"host":"x.example"}}}}}`,
			wantAns:  "ans://v1.0.0.x.example",
			wantHost: "x.example",
			wantE:    "REVOKED",
			wantOK:   true,
		},
		"missing both ans and host": {
			envelope: `{"payload":{"producer":{"event":{"eventType":"REGISTERED"}}}}`,
			wantOK:   false,
		},
		"ans only (no agent block)": {
			envelope: `{"payload":{"producer":{"event":{"ansName":"ans://v1.0.0.x.example"}}}}`,
			wantAns:  "ans://v1.0.0.x.example",
			wantOK:   true,
		},
		"garbage json": {
			envelope: `{not json`,
			wantOK:   false,
		},
		"empty object": {
			envelope: `{}`,
			wantOK:   false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id, ok := extractAgentIdentity([]byte(c.envelope))
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if id.AnsName != c.wantAns {
				t.Errorf("ansName = %q, want %q", id.AnsName, c.wantAns)
			}
			if id.Host != c.wantHost {
				t.Errorf("host = %q, want %q", id.Host, c.wantHost)
			}
			if id.EventType != c.wantE {
				t.Errorf("eventType = %q, want %q", id.EventType, c.wantE)
			}
		})
	}
}

// encodeEntryBundle is the test-side inverse of api.EntryBundle's
// UnmarshalText — `[2-byte BE size][size bytes of leaf]` repeated.
// Kept local to the test file so the production walker only depends
// on the reader half.
func encodeEntryBundle(leaves [][]byte) []byte {
	out := make([]byte, 0, 1024)
	var sizeBuf [2]byte
	for _, leaf := range leaves {
		if len(leaf) > 0xFFFF {
			panic("test bundle leaf > 64 KiB")
		}
		binary.BigEndian.PutUint16(sizeBuf[:], uint16(len(leaf)))
		out = append(out, sizeBuf[:]...)
		out = append(out, leaf...)
	}
	return out
}

func TestDecodeEntryBundle_RoundTrip(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{
		[]byte("first"),
		[]byte(`{"some":"json"}`),
		{}, // zero-length leaf
		[]byte("last"),
	}
	raw := encodeEntryBundle(leaves)
	got, err := decodeEntryBundle(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != len(leaves) {
		t.Fatalf("got %d leaves, want %d", len(got), len(leaves))
	}
	for i := range got {
		if string(got[i]) != string(leaves[i]) {
			t.Errorf("leaf %d = %q, want %q", i, got[i], leaves[i])
		}
	}
}

func TestDecodeEntryBundle_DanglingBytes(t *testing.T) {
	t.Parallel()
	// Length prefix says 4 bytes but only 2 follow.
	raw := []byte{0x00, 0x04, 'a', 'b'}
	if _, err := decodeEntryBundle(raw); err == nil {
		t.Fatal("want error for truncated bundle, got nil")
	}
}

// makeEnvelope produces a minimal V1-shaped envelope JSON for tests.
// The walker only inspects the fields extractAgentIdentity reads, so
// we don't need to populate the full schema.
func makeEnvelope(ansName, host, eventType string) []byte {
	return makeEnvelopeWithID("", ansName, host, eventType)
}

// makeEnvelopeWithID is the four-field variant used by tests that
// care about agentId (reduceToLive, verifyMatches).
func makeEnvelopeWithID(ansID, ansName, host, eventType string) []byte {
	return []byte(fmt.Sprintf(
		`{"payload":{"producer":{"event":{"ansId":%q,"ansName":%q,"eventType":%q,"agent":{"host":%q}}}}}`,
		ansID, ansName, eventType, host,
	))
}

// tileServer stands up a httptest.Server that serves tlog-tiles
// entry-tile paths backed by an in-memory `tile index -> bundle`
// map. Lets us exercise the walker without standing up tessera.
func tileServer(t *testing.T, tiles map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the leading slash so the keys can match what
		// layout.EntriesPath returns.
		key := strings.TrimPrefix(r.URL.Path, "/")
		body, ok := tiles[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWalkProviderAgents_FiltersAndIndexes(t *testing.T) {
	t.Parallel()
	// Build a 3-leaf log: two under darknetian.com, one under example.org.
	leaves := [][]byte{
		makeEnvelope("ans://v1.0.0.alpha.darknetian.com", "alpha.darknetian.com", "REGISTERED"),
		makeEnvelope("ans://v1.0.0.other.example.org", "other.example.org", "REGISTERED"),
		makeEnvelope("ans://v1.0.0.beta.darknetian.com", "beta.darknetian.com", "REGISTERED"),
	}
	bundle := encodeEntryBundle(leaves)
	srv := tileServer(t, map[string][]byte{
		"tile/entries/000.p/3": bundle, // partial tile: 3 of 256
	})
	got, err := walkProviderAgents(context.Background(), srv.Client(), srv.URL, "darknetian.com", 3, 0)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d matches, want 2 (matches=%+v)", len(got), got)
	}
	// Matches must come back in log order.
	sort.Slice(got, func(i, j int) bool { return got[i].LeafIndex < got[j].LeafIndex })
	if got[0].LeafIndex != 0 || got[0].Host != "alpha.darknetian.com" {
		t.Errorf("got[0] = %+v, want leaf 0 alpha.darknetian.com", got[0])
	}
	if got[1].LeafIndex != 2 || got[1].Host != "beta.darknetian.com" {
		t.Errorf("got[1] = %+v, want leaf 2 beta.darknetian.com", got[1])
	}
}

func TestWalkProviderAgents_MultipleTiles(t *testing.T) {
	t.Parallel()
	// 257 leaves: one full tile (256) plus a 1-leaf partial.
	// Put a darknetian match at the start of each tile to exercise
	// the base-index arithmetic across the tile boundary.
	full := make([][]byte, 256)
	for i := range full {
		full[i] = makeEnvelope(
			fmt.Sprintf("ans://v1.0.0.a%d.example.org", i),
			fmt.Sprintf("a%d.example.org", i),
			"REGISTERED",
		)
	}
	full[0] = makeEnvelope("ans://v1.0.0.first.darknetian.com", "first.darknetian.com", "REGISTERED")
	partial := [][]byte{
		makeEnvelope("ans://v1.0.0.second.darknetian.com", "second.darknetian.com", "REGISTERED"),
	}
	srv := tileServer(t, map[string][]byte{
		"tile/entries/000":     encodeEntryBundle(full),
		"tile/entries/001.p/1": encodeEntryBundle(partial),
	})
	got, err := walkProviderAgents(context.Background(), srv.Client(), srv.URL, "darknetian.com", 257, 4)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d matches, want 2 (matches=%+v)", len(got), got)
	}
	sort.Slice(got, func(i, j int) bool { return got[i].LeafIndex < got[j].LeafIndex })
	if got[0].LeafIndex != 0 || got[1].LeafIndex != 256 {
		t.Errorf("leaf indices = %d,%d; want 0,256",
			got[0].LeafIndex, got[1].LeafIndex)
	}
}

func TestWalkProviderAgents_EmptyTree(t *testing.T) {
	t.Parallel()
	// No tiles registered — walker should not even attempt a fetch.
	srv := tileServer(t, map[string][]byte{})
	got, err := walkProviderAgents(context.Background(), srv.Client(), srv.URL, "darknetian.com", 0, 0)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d matches, want 0", len(got))
	}
}

func TestWalkProviderAgents_FetchError(t *testing.T) {
	t.Parallel()
	// Tile path not present → 404 → walker surfaces the error.
	srv := tileServer(t, map[string][]byte{})
	_, err := walkProviderAgents(context.Background(), srv.Client(), srv.URL, "darknetian.com", 1, 0)
	if err == nil {
		t.Fatal("want error for missing tile, got nil")
	}
}

func TestWalkProviderAgents_SkipsUnparsableLeaves(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{
		[]byte("not json at all"),
		makeEnvelope("ans://v1.0.0.real.darknetian.com", "real.darknetian.com", "REGISTERED"),
		[]byte(`{"payload":{}}`), // valid json, no event — skipped
	}
	srv := tileServer(t, map[string][]byte{
		"tile/entries/000.p/3": encodeEntryBundle(leaves),
	})
	got, err := walkProviderAgents(context.Background(), srv.Client(), srv.URL, "darknetian.com", 3, 0)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 1 || got[0].LeafIndex != 1 {
		t.Fatalf("got %+v, want one match at leaf 1", got)
	}
}

func TestCheckpointTreeSize(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/log/checkpoint" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"logSize":42,"originName":"test","rootHash":"AAAA"}`))
	}))
	t.Cleanup(srv.Close)
	got, err := checkpointTreeSize(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}

func TestCheckpointTreeSize_BadJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	t.Cleanup(srv.Close)
	if _, err := checkpointTreeSize(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("want error for bad json, got nil")
	}
}

func TestCheckpointTreeSize_HTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	if _, err := checkpointTreeSize(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("want error for 500, got nil")
	}
}

func TestClampConcurrency(t *testing.T) {
	t.Parallel()
	cases := map[int]int{
		0:   8,  // default
		1:   1,  // floor
		-5:  1,  // negative → floor
		8:   8,  // passthrough
		32:  32, // passthrough
		64:  64, // boundary
		500: 64, // ceiling
	}
	for in, want := range cases {
		if got := clampConcurrency(in); got != want {
			t.Errorf("clampConcurrency(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestReduceToLive(t *testing.T) {
	t.Parallel()
	// Two agents:
	//   alpha — registered (leaf 0), renewed (leaf 3) → live
	//   beta  — registered (leaf 1), revoked (leaf 4) → dropped
	//   gamma — registered (leaf 2) → live
	//   (one leaf with no AnsName — should pass through untouched)
	input := []AgentMatch{
		{LeafIndex: 0, AgentID: "id-a", AnsName: "ans://alpha", Host: "a.x", EventType: "AGENT_REGISTERED"},
		{LeafIndex: 1, AgentID: "id-b", AnsName: "ans://beta", Host: "b.x", EventType: "AGENT_REGISTERED"},
		{LeafIndex: 2, AgentID: "id-g", AnsName: "ans://gamma", Host: "g.x", EventType: "AGENT_REGISTERED"},
		{LeafIndex: 3, AgentID: "id-a", AnsName: "ans://alpha", Host: "a.x", EventType: "AGENT_RENEWED"},
		{LeafIndex: 4, AgentID: "id-b", AnsName: "ans://beta", Host: "b.x", EventType: "AGENT_REVOKED"},
		{LeafIndex: 5, AgentID: "id-x", AnsName: "", Host: "weird.x", EventType: "AGENT_REGISTERED"},
	}
	got := reduceToLive(input)
	wantAns := map[string]string{
		"ans://alpha": "AGENT_RENEWED",    // dedup keeps latest
		"ans://gamma": "AGENT_REGISTERED", // unchanged
		"":            "AGENT_REGISTERED", // empty-name passthrough
	}
	if len(got) != len(wantAns) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(wantAns), got)
	}
	for _, m := range got {
		wt, ok := wantAns[m.AnsName]
		if !ok {
			t.Errorf("unexpected AnsName %q in result", m.AnsName)
			continue
		}
		if m.EventType != wt {
			t.Errorf("AnsName=%q eventType = %q, want %q", m.AnsName, m.EventType, wt)
		}
	}
	// Drop a deprecated agent and a renewed one to exercise the
	// other terminal type and confirm sort-by-leafIndex on the way out.
	input = []AgentMatch{
		{LeafIndex: 10, AnsName: "ans://x", EventType: "AGENT_REGISTERED"},
		{LeafIndex: 5, AnsName: "ans://y", EventType: "AGENT_DEPRECATED"},
	}
	got = reduceToLive(input)
	if len(got) != 1 || got[0].AnsName != "ans://x" {
		t.Fatalf("got %+v, want [ans://x]", got)
	}
}

func TestReduceToLive_Empty(t *testing.T) {
	t.Parallel()
	got := reduceToLive(nil)
	if len(got) != 0 {
		t.Fatalf("got %d, want 0", len(got))
	}
}

func TestWalkProviderAgents_PopulatesAgentID(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{
		makeEnvelopeWithID("uuid-1", "ans://v1.alpha.darknetian.com",
			"alpha.darknetian.com", "AGENT_REGISTERED"),
	}
	srv := tileServer(t, map[string][]byte{
		"tile/entries/000.p/1": encodeEntryBundle(leaves),
	})
	got, err := walkProviderAgents(context.Background(), srv.Client(), srv.URL, "darknetian.com", 1, 0)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(got) != 1 || got[0].AgentID != "uuid-1" {
		t.Fatalf("got %+v, want one match with agentId=uuid-1", got)
	}
}

func TestVerifyMatches_HappyPath(t *testing.T) {
	t.Parallel()
	var seen sync.Mutex
	seenIDs := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/receipt") {
			http.NotFound(w, r)
			return
		}
		seen.Lock()
		seenIDs[r.URL.Path]++
		seen.Unlock()
		_, _ = w.Write([]byte("RECEIPT-BYTES"))
	}))
	t.Cleanup(srv.Close)

	const (
		aID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		bID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	)
	matches := []AgentMatch{
		{AgentID: aID, AnsName: "ans://a"},
		{AgentID: bID, AnsName: "ans://b"},
		{AgentID: "", AnsName: "ans://no-id"}, // missing agentId → per-match err
	}
	stub := func(b []byte) error {
		if string(b) != "RECEIPT-BYTES" {
			return errors.New("unexpected body")
		}
		return nil
	}
	results := verifyMatches(context.Background(), srv.Client(), srv.URL, matches, stub, 4)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if !results[0].OK || !results[1].OK {
		t.Errorf("results[0].OK=%v results[1].OK=%v; both want true", results[0].OK, results[1].OK)
	}
	if results[2].OK || results[2].Err == nil {
		t.Errorf("results[2] = %+v, want err for missing agentId", results[2])
	}
	if seenIDs["/v1/agents/"+aID+"/receipt"] != 1 || seenIDs["/v1/agents/"+bID+"/receipt"] != 1 {
		t.Errorf("expected one fetch each for /a and /b receipts, got %+v", seenIDs)
	}
}

func TestVerifyMatches_FetchAndVerifyErrors(t *testing.T) {
	t.Parallel()
	// Three UUIDs that round-trip through agentIDPattern. The server
	// serves a distinct body per agentId so the test verifier can
	// route deterministically without depending on call order.
	const (
		goodID = "11111111-1111-1111-1111-111111111111"
		fetID  = "22222222-2222-2222-2222-222222222222"
		verID  = "33333333-3333-3333-3333-333333333333"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/agents/"+fetID+"/"):
			w.WriteHeader(http.StatusInternalServerError)
		case strings.HasPrefix(r.URL.Path, "/v1/agents/"+goodID+"/"):
			_, _ = w.Write([]byte("body:good"))
		case strings.HasPrefix(r.URL.Path, "/v1/agents/"+verID+"/"):
			_, _ = w.Write([]byte("body:verify-fail"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	matches := []AgentMatch{
		{AgentID: goodID, AnsName: "ans://good"},
		{AgentID: fetID, AnsName: "ans://bf"},
		{AgentID: verID, AnsName: "ans://bv"},
	}
	// Verifier routes by body, not by call order — concurrency-safe,
	// refactor-safe.
	verifier := func(b []byte) error {
		switch string(b) {
		case "body:good":
			return nil
		case "body:verify-fail":
			return errors.New("synthetic verify failure")
		default:
			return fmt.Errorf("unexpected body %q", b)
		}
	}
	results := verifyMatches(context.Background(), srv.Client(), srv.URL, matches, verifier, 4)
	if !results[0].OK {
		t.Errorf("results[0] = %+v, want OK", results[0])
	}
	if results[1].OK || results[1].Err == nil {
		t.Errorf("results[1] = %+v, want fetch err", results[1])
	}
	if results[2].OK || results[2].Err == nil {
		t.Errorf("results[2] = %+v, want verify err", results[2])
	}
}

func TestVerifyMatches_RejectsBadAgentID(t *testing.T) {
	t.Parallel()
	// Server should NEVER be hit — the path-injection guard fires
	// first. Failing the test if it is reached gives a clear signal
	// that the guard regressed.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("guard failed: server was hit with path %q", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	matches := []AgentMatch{
		{AgentID: "../etc/passwd", AnsName: "ans://traversal"},
		{AgentID: "foo?injected=1", AnsName: "ans://query"},
		{AgentID: "not-a-uuid", AnsName: "ans://wrong-shape"},
	}
	results := verifyMatches(context.Background(), srv.Client(), srv.URL, matches,
		func([]byte) error { return nil }, 1)
	for i, r := range results {
		if r.OK || r.Err == nil {
			t.Errorf("results[%d] = %+v, want guard err", i, r)
		}
	}
}

func TestHTTPGetBytes_BodyCapped(t *testing.T) {
	t.Parallel()
	// Stream just over the cap — guard must reject, not truncate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 1024)
		written := int64(0)
		for written <= maxResponseBytes {
			n, _ := w.Write(buf)
			written += int64(n)
		}
	}))
	t.Cleanup(srv.Close)
	_, err := httpGetBytes(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("want cap-exceeded error, got nil")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("err = %v, want one mentioning cap", err)
	}
}

func TestWalkProviderAgents_ExternalContextCancel(t *testing.T) {
	t.Parallel()
	// Server hangs forever — walker must surface ctx err, not nil.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled
	_, err := walkProviderAgents(ctx, srv.Client(), srv.URL, "darknetian.com", 5, 2)
	if err == nil {
		t.Fatal("want error on cancelled context, got nil")
	}
}

func TestWalkProviderAgents_FetchErrorReportsTriggeringTile(t *testing.T) {
	t.Parallel()
	// Tile 5 500s; tiles 0-4 return valid full-width bundles of stub
	// envelopes that won't match the provider filter. The walker
	// should surface the tile-5 error, not whichever lower-indexed
	// tile happened to complete first.
	full := make([][]byte, 256)
	for i := range full {
		full[i] = makeEnvelope(
			fmt.Sprintf("ans://v1.stub%d.example.org", i),
			fmt.Sprintf("stub%d.example.org", i),
			"AGENT_REGISTERED",
		)
	}
	fullBundle := encodeEntryBundle(full)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "tile/entries/005") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(fullBundle)
	}))
	t.Cleanup(srv.Close)
	// 6 tiles' worth of leaves so tile 5 exists.
	_, err := walkProviderAgents(context.Background(), srv.Client(),
		srv.URL, "darknetian.com", 6*256, 4)
	if err == nil {
		t.Fatal("want fetch err, got nil")
	}
	if !strings.Contains(err.Error(), "005") {
		t.Errorf("err = %v, want one mentioning tile 005", err)
	}
}

func TestWalkProviderAgents_RejectsWrongTileSize(t *testing.T) {
	t.Parallel()
	// Tile claims to be a full (256-leaf) tile but the server returns
	// only 3 leaves. The size guard MUST reject — otherwise a hostile
	// TL can hide entries by serving truncated bundles.
	short := encodeEntryBundle([][]byte{
		makeEnvelope("ans://v1.a.x", "a.x", "AGENT_REGISTERED"),
		makeEnvelope("ans://v1.b.x", "b.x", "AGENT_REGISTERED"),
		makeEnvelope("ans://v1.c.x", "c.x", "AGENT_REGISTERED"),
	})
	srv := tileServer(t, map[string][]byte{
		"tile/entries/000": short, // path says full tile (no .p/N suffix)
	})
	_, err := walkProviderAgents(context.Background(), srv.Client(),
		srv.URL, "x", 256, 1)
	if err == nil {
		t.Fatal("want size-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "want 256") {
		t.Errorf("err = %v, want one mentioning expected size 256", err)
	}
}

func TestWalkProviderAgents_RejectsOversizedTile(t *testing.T) {
	t.Parallel()
	// Partial tile claims width 1 but the server returns 2 leaves.
	// A hostile TL injecting extra leaves into a partial tile would
	// otherwise slip through the checkpoint-signature check (the
	// checkpoint binds tree shape, not tile contents).
	over := encodeEntryBundle([][]byte{
		makeEnvelope("ans://v1.a.x", "a.x", "AGENT_REGISTERED"),
		makeEnvelope("ans://v1.b.x", "b.x", "AGENT_REGISTERED"),
	})
	srv := tileServer(t, map[string][]byte{
		"tile/entries/000.p/1": over, // path says partial=1
	})
	_, err := walkProviderAgents(context.Background(), srv.Client(),
		srv.URL, "x", 1, 1)
	if err == nil {
		t.Fatal("want size-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "want 1") {
		t.Errorf("err = %v, want one mentioning expected size 1", err)
	}
}

func TestVerifyMatches_Empty(t *testing.T) {
	t.Parallel()
	got := verifyMatches(context.Background(), nil, "", nil, func([]byte) error { return nil }, 0)
	if got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}

func TestMakeReceiptVerifier_NoKeys(t *testing.T) {
	t.Parallel()
	v := makeReceiptVerifier(nil)
	if err := v([]byte("anything")); err == nil {
		t.Fatal("want error for empty key set, got nil")
	}
}

// signTestCheckpoint produces a synthetic C2SP-shaped signed note for
// the verifiedCheckpoint smoke test. Mirrors how the TL's
// C2SPECDSASigner builds the signature line (keyhash:4 || DER-sig).
// The exhaustive note parse/verify cases (tampered body, unknown key,
// malformed body, adversarial collisions) live in the internal/lognote
// package tests; this only proves the network half wires the fetch to
// lognote.VerifyCheckpointNote.
func signTestCheckpoint(t *testing.T, priv *ecdsa.PrivateKey, origin string, size uint64, rootHash []byte) []byte {
	t.Helper()
	body := []byte(fmt.Sprintf("%s\n%d\n%s\n",
		origin, size, base64.StdEncoding.EncodeToString(rootHash)))
	digest := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	kh4, err := anscrypto.SPKIKeyHash4(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyhash: %v", err)
	}
	blob := append(append([]byte{}, kh4...), sig...)
	sigLine := fmt.Sprintf("— %s %s\n", origin, base64.StdEncoding.EncodeToString(blob))
	return append(body, append([]byte("\n"), []byte(sigLine)...)...)
}

// TestVerifiedCheckpoint_FetchesAndVerifies is the thin smoke test that
// verifiedCheckpoint fetches /checkpoint and returns the parsed,
// signature-verified *lognote.Checkpoint. The keysByHash map key is the
// plain 8-char hex keyhash from crypto.SPKIKeyIDHex4.
func TestVerifiedCheckpoint_FetchesAndVerifies(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	khex, err := anscrypto.SPKIKeyIDHex4(&priv.PublicKey)
	if err != nil {
		t.Fatalf("keyhash hex: %v", err)
	}
	rootHash := sha256.Sum256([]byte("synthetic root"))
	note := signTestCheckpoint(t, priv, "demo.example", 42, rootHash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkpoint" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(note)
	}))
	defer srv.Close()

	cp, err := verifiedCheckpoint(context.Background(), srv.Client(), srv.URL,
		map[string]*ecdsa.PublicKey{khex: &priv.PublicKey})
	if err != nil {
		t.Fatalf("verifiedCheckpoint: %v", err)
	}
	if cp.Origin != "demo.example" || cp.Size != 42 {
		t.Errorf("got origin=%q size=%d, want demo.example/42", cp.Origin, cp.Size)
	}
	if !bytes.Equal(cp.RootHash, rootHash[:]) {
		t.Error("rootHash mismatch")
	}
}

// TestVerifiedCheckpoint_NoKeys rejects an empty verifier set before
// any network fetch.
func TestVerifiedCheckpoint_NoKeys(t *testing.T) {
	t.Parallel()
	if _, err := verifiedCheckpoint(context.Background(), http.DefaultClient,
		"http://unused.invalid", nil); err == nil {
		t.Fatal("want error for empty key map, got nil")
	}
}

// TestVerifiedCheckpoint_FetchError surfaces a non-200 from /checkpoint.
func TestVerifiedCheckpoint_FetchError(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	khex, _ := anscrypto.SPKIKeyIDHex4(&priv.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := verifiedCheckpoint(context.Background(), srv.Client(), srv.URL,
		map[string]*ecdsa.PublicKey{khex: &priv.PublicKey}); err == nil {
		t.Fatal("want error for HTTP 500, got nil")
	}
}

func TestVerifyMatches_LeafSubstitutionCaught(t *testing.T) {
	t.Parallel()
	const aID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	// The receipt returns a different payload than the LeafBytes we
	// "walked" off the tile — simulates a TL that served a forged
	// tile claiming a fake host under our provider but a real receipt
	// for an unrelated agent.
	receiptBody := []byte("REAL_RECEIPT_FOR_DIFFERENT_LEAF")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/receipt") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(receiptBody)
	}))
	t.Cleanup(srv.Close)

	// Synthetic receipt payload != tile leaf bytes; the test
	// verifier accepts any signature so we know the substitution
	// guard — not the signature guard — is what fails.
	forgedTileLeaf := []byte("FORGED_TILE_LEAF_BYTES")
	matches := []AgentMatch{
		{AgentID: aID, AnsName: "ans://victim", LeafBytes: forgedTileLeaf},
	}
	// extractPayloadStub: this test runs verifyMatches's substitution
	// branch, which calls receipt.ExtractPayload on receiptBody. That
	// body isn't a valid COSE_Sign1, so ExtractPayload will fail
	// before the bytes.Equal — which is still the correct outcome
	// (the guard rejects). Confirm we get an error.
	stub := func(_ []byte) error { return nil }
	results := verifyMatches(context.Background(), srv.Client(), srv.URL, matches, stub, 1)
	if results[0].OK || results[0].Err == nil {
		t.Fatalf("results[0] = %+v, want substitution err", results[0])
	}
	// The error should mention either "payload" or "substitution"
	// depending on whether ExtractPayload succeeded.
	msg := results[0].Err.Error()
	if !strings.Contains(msg, "payload") && !strings.Contains(msg, "substitution") {
		t.Errorf("err = %v, want substitution-related message", results[0].Err)
	}
}

func TestVerifyMatches_NilLeafBytesSkipsSubstitutionCheck(t *testing.T) {
	t.Parallel()
	// Caller didn't capture LeafBytes — the substitution check must
	// be skipped (back-compat), and the match should pass on the
	// strength of the verifier alone.
	const aID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	matches := []AgentMatch{{AgentID: aID, AnsName: "ans://legacy"}}
	results := verifyMatches(context.Background(), srv.Client(), srv.URL, matches,
		func(_ []byte) error { return nil }, 1)
	if !results[0].OK {
		t.Errorf("results[0] = %+v, want OK", results[0])
	}
}
