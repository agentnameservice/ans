package poller_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/finder/feed"
	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/poller"
)

// syncBuffer is a goroutine-safe bytes.Buffer for capturing log output
// from the poller's background goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// cursorErrIndex fails Cursor reads, exercising the RunOnce cursor-read
// error branch.
type cursorErrIndex struct{ index.Catalog }

func (cursorErrIndex) Cursor(context.Context) (index.Cursor, error) {
	return index.Cursor{}, errors.New("cursor read boom")
}

func TestPoller_CursorReadErrorAborts(t *testing.T) {
	t.Parallel()
	idx := cursorErrIndex{Catalog: newIndex(t)}
	fc := &fakeClient{pages: []feed.EventPageResponse{{Items: []feed.EventItem{registeredItem("a.example.com", "a")}}}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(time.Now()))
	runRound(t, p)
	// No fetch should have happened — the round bailed at the cursor read.
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.calls != 0 {
		t.Errorf("cursor-read failure should abort before fetching, got %d calls", fc.calls)
	}
}

// saveCursorErrIndex fails SaveCursor, exercising that error branch.
type saveCursorErrIndex struct{ index.Catalog }

func (saveCursorErrIndex) SaveCursor(context.Context, index.Cursor) error {
	return errors.New("save boom")
}

func TestPoller_SaveCursorErrorAborts(t *testing.T) {
	t.Parallel()
	idx := saveCursorErrIndex{Catalog: newIndex(t)}
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{registeredItem("a.example.com", "a")}, LastLogID: "log-a"},
	}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(time.Now()))
	// Must not panic or loop forever; the round bails after the save error.
	runRound(t, p)
}

func TestPoller_TickerDrivesSecondRound(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{registeredItem("a.example.com", "a")}}, // round 1 tail
		{Items: []feed.EventItem{registeredItem("b.example.com", "b")}}, // round 2 tail
	}}
	p := poller.New(fc, idx, poller.Config{Interval: 30 * time.Millisecond, PageSize: 100}, silent,
		fixedClock(time.Now()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Run(ctx); close(done) }()
	// Poll for the immediate round plus at least one ticker round to
	// land in the index instead of sleeping a fixed window: on a loaded
	// runner a fixed sleep flakes, while polling just stretches the
	// wait. Reading while the poller writes is safe — the store pins a
	// single connection, so this Search serializes with the writes.
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := idx.Search(context.Background(), index.SearchQuery{Text: "", Limit: 50},
			time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
		if err == nil && len(res.Results) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("ticker should have driven a second round ingesting both agents, got %d (err=%v)",
				len(res.Results), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestHTTPFeedClient_LongErrorBodyTruncated(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(long))
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	_, err := c.FetchEvents(context.Background(), "", 10)
	if err == nil {
		t.Fatal("expected error")
	}
	// The error message embeds a truncated, single-line snippet.
	if !strings.Contains(err.Error(), "…") {
		t.Errorf("expected truncated snippet in error, got %q", err.Error())
	}
}

func TestNewHTTPFeedClient_UnparseableURL(t *testing.T) {
	t.Parallel()
	// A control character makes url.Parse fail outright.
	if _, err := poller.NewHTTPFeedClient("https://exa\x7fmple.com", false, time.Second); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNewHTTPFeedClient_DefaultTimeout(t *testing.T) {
	t.Parallel()
	// Zero timeout is replaced by a default; construction still succeeds.
	if _, err := poller.NewHTTPFeedClient("https://feed.example.org", false, 0); err != nil {
		t.Fatalf("zero timeout should default, got %v", err)
	}
}

func TestHTTPFeedClient_RefusesRedirect(t *testing.T) {
	t.Parallel()
	// A feed that 30x-redirects must be refused (L14): following it could
	// downgrade https→http or point ingestion elsewhere.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "http://evil.example.org/v1/agents/events", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	if _, err := c.FetchEvents(context.Background(), "", 10); err == nil {
		t.Fatal("expected error on feed redirect")
	}
}

func TestHTTPFeedClient_RejectsOverCapBody(t *testing.T) {
	t.Parallel()
	// A body just over the 16 MiB cap is rejected with an explicit
	// over-cap error rather than a confusing JSON-decode failure (L20).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write a valid-JSON-prefix then pad past the cap so the read trips
		// the limit before decoding.
		_, _ = w.Write([]byte(`{"items":[`))
		chunk := bytes.Repeat([]byte("a"), 1<<20)
		for range 17 { // 17 MiB > 16 MiB cap
			_, _ = w.Write(chunk)
		}
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 30*time.Second)
	_, err := c.FetchEvents(context.Background(), "", 10)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected over-cap error, got %v", err)
	}
}

// TestPoller_Feed429IsTransient pins the production-contract behavior: a
// 429 (throttled) from the feed is treated like any other non-2xx — a
// transient fetch error that does NOT advance or reset the cursor and
// does NOT wedge ingestion. The OSS RA feed never emits 429 locally
// (it documents 200/422/500), but the production contract does, so the
// poller must not depend on 429 being absent nor treat 4xx as permanent.
// Driven through the REAL HTTP client + poll loop against a 429 server.
func TestPoller_Feed429IsTransient(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"title":"throttled","code":"RATE_LIMIT_EXCEEDED"}`))
	}))
	defer srv.Close()

	idx := newIndex(t)
	// Seed a prior cursor so we can prove a 429 round leaves it untouched
	// (neither advanced nor reset to empty).
	const priorCursor = "log-prior"
	if err := idx.SaveCursor(context.Background(), index.Cursor{LastLogID: priorCursor}); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}

	client, err := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	p := poller.New(client, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(time.Now()))

	runRound(t, p)

	c, _ := idx.Cursor(context.Background())
	if c.LastLogID != priorCursor {
		t.Errorf("429 must not move the cursor: got %q, want %q", c.LastLogID, priorCursor)
	}
	// A 429 round records no successful poll (the round-trip failed).
	if !c.LastPollOK.IsZero() {
		t.Errorf("429 round must not record a successful poll: %v", c.LastPollOK)
	}

	// Ingestion is not wedged: a subsequent successful poll still applies.
	good := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{registeredItem("a.example.com", "alpha")}},
	}}
	p2 := poller.New(good, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(time.Now()))
	runRound(t, p2)
	res, _ := idx.Search(context.Background(), index.SearchQuery{Text: "alpha", Limit: 10},
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(res.Results) != 1 {
		t.Errorf("a 429 must not wedge ingestion; later poll should ingest, got %d results", len(res.Results))
	}
}

// TestPoller_DuplicateFallbackURLDoesNotWedge is the NEW-1 regression
// guard at the poll level: a contract-legal event with two same-protocol
// endpoints that both omit metaDataUrl projects to two entries with the
// identical well-known fallback URL. Apply must fold the duplicate and
// the round must ADVANCE the cursor — not wedge ingestion on a valid
// registration.
func TestPoller_DuplicateFallbackURLDoesNotWedge(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	// Two MCP endpoints, neither with metaDataUrl → both project to
	// https://dup.example.com/.well-known/mcp.json.
	item := registeredItem("dup.example.com", "dupagent")
	item.Endpoints = []feed.AgentEndpoint{
		{AgentURL: "https://dup.example.com/mcp-a", Protocol: feed.ProtocolMCP},
		{AgentURL: "https://dup.example.com/mcp-b", Protocol: feed.ProtocolMCP},
	}
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{item}, LastLogID: "log-dupagent"},
	}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(time.Now()))

	runRound(t, p)

	// Cursor advanced (ingestion not wedged).
	c, _ := idx.Cursor(context.Background())
	if c.LastLogID != "log-dupagent" {
		t.Fatalf("cursor did not advance past a duplicate-fallback-URL event: %q", c.LastLogID)
	}
	// The agent is indexed (one row survived the dedup).
	res, _ := idx.Search(context.Background(), index.SearchQuery{Text: "dupagent", Limit: 10},
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 indexed row after dedup, got %d", len(res.Results))
	}
}

// noProgressClient always returns a page that claims more (LastLogID set)
// but carries zero items and echoes the SAME cursor back — the hot-loop
// trap the M6 progress guard must break.
type noProgressClient struct {
	mu    sync.Mutex
	calls int
}

func (c *noProgressClient) FetchEvents(_ context.Context, afterLogID string, _ int) (feed.EventPageResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	// Always reports the same non-empty cursor with no items.
	cursor := afterLogID
	if cursor == "" {
		cursor = "stuck"
	}
	return feed.EventPageResponse{Items: nil, LastLogID: cursor}, nil
}

func TestPoller_NoProgressGuardBreaksRound(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &noProgressClient{}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(time.Now()))

	runRound(t, p)

	// The guard must stop after a bounded number of fetches, not hot-loop.
	// First fetch (cursor "") advances to "stuck" and persists; the second
	// fetch returns "stuck" again with no progress → break. So exactly two
	// fetches, never an unbounded spin.
	fc.mu.Lock()
	calls := fc.calls
	fc.mu.Unlock()
	if calls > 3 {
		t.Fatalf("progress guard failed to break the drain loop: %d fetches", calls)
	}
}

func TestPoller_WedgeEscalationAfterRepeatedFailures(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	// A client that always errors keeps the cursor stuck at "" → the wedge
	// counter climbs across rounds and must escalate at the threshold.
	buf := &syncBuffer{}
	logger := zerolog.New(buf)
	p := poller.New(&alwaysErrClient{}, idx, poller.Config{Interval: time.Hour, PageSize: 100},
		logger, fixedClock(time.Now()))

	// Drive exactly the wedge threshold (5) of consecutive failing rounds
	// synchronously; the escalation line must appear on the last one.
	for range 5 {
		p.RunOnce(context.Background())
	}

	if !strings.Contains(buf.String(), "ingestion wedged at logId") {
		t.Errorf("expected wedge escalation line after repeated failures; log was:\n%s", buf.String())
	}
}

// alwaysErrClient fails every fetch, to drive the wedge counter.
type alwaysErrClient struct{}

func (alwaysErrClient) FetchEvents(_ context.Context, _ string, _ int) (feed.EventPageResponse, error) {
	return feed.EventPageResponse{}, errors.New("feed down")
}

func TestPoller_TombstoneNoOpLogsWarn(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	// Seed an Active registration dated AFTER the revoke that will follow,
	// so the revoke suppresses zero rows (clock step-back) → WARN.
	reg := registeredItem("a.example.com", "alpha")
	reg.CreatedAt = "2025-03-01T00:00:00Z"
	rev := feed.EventItem{
		LogID:     "log-revoke",
		EventType: feed.EventTypeAgentRevoked,
		CreatedAt: "2025-01-01T00:00:00Z", // older than the registration
		AgentID:   reg.AgentID,
		AnsName:   reg.AnsName,
		AgentHost: reg.AgentHost,
		Version:   reg.Version,
	}
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{reg, rev}},
	}}
	buf := &syncBuffer{}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100},
		zerolog.New(buf), fixedClock(time.Now()))

	runRound(t, p)

	if !strings.Contains(buf.String(), "revocation suppressed no rows") {
		t.Errorf("expected tombstone no-op WARN; log was:\n%s", buf.String())
	}
	// The agent is indeed still discoverable (the WARN is justified).
	res, _ := idx.Search(context.Background(), index.SearchQuery{Text: "alpha", Limit: 10},
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(res.Results) != 1 {
		t.Errorf("expected the agent to remain active, got %d", len(res.Results))
	}
}

func TestPoller_IdleRoundLogsDebugNotInfo(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &fakeClient{pages: []feed.EventPageResponse{{}}} // empty tail page
	buf := &syncBuffer{}
	// Level set to INFO so a DEBUG idle line is filtered out entirely.
	logger := zerolog.New(buf).Level(zerolog.InfoLevel)
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, logger, fixedClock(time.Now()))

	runRound(t, p)

	if strings.Contains(buf.String(), "ingested") {
		t.Errorf("idle round must not log an INFO 'ingested' line; log was:\n%s", buf.String())
	}
}

func TestPoller_IngestingRoundLogsInfo(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{registeredItem("a.example.com", "alpha")}},
	}}
	buf := &syncBuffer{}
	logger := zerolog.New(buf).Level(zerolog.InfoLevel)
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, logger, fixedClock(time.Now()))

	runRound(t, p)

	if !strings.Contains(buf.String(), "ingested") {
		t.Errorf("an ingesting round must log INFO 'ingested'; log was:\n%s", buf.String())
	}
}
