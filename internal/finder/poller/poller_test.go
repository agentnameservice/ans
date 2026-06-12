package poller_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/store/sqlitefinder"
	"github.com/godaddy/ans/internal/finder/feed"
	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/poller"
	"github.com/godaddy/ans/internal/finder/project"
)

// fakeClient serves a scripted sequence of feed pages. Each call to
// FetchEvents returns the next page; recorded args let tests assert the
// cursor was passed.
type fakeClient struct {
	mu        sync.Mutex
	pages     []feed.EventPageResponse
	errs      []error // parallel to pages; non-nil entry returns an error
	calls     int
	gotCursor []string
}

func (f *fakeClient) FetchEvents(_ context.Context, afterLogID string, _ int) (feed.EventPageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotCursor = append(f.gotCursor, afterLogID)
	i := f.calls
	f.calls++
	if i < len(f.errs) && f.errs[i] != nil {
		return feed.EventPageResponse{}, f.errs[i]
	}
	if i < len(f.pages) {
		return f.pages[i], nil
	}
	// Past the scripted pages: empty tail so the loop stops.
	return feed.EventPageResponse{}, nil
}

func newIndex(t *testing.T) index.Catalog {
	t.Helper()
	s, err := sqlitefinder.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func registeredItem(host, label string) feed.EventItem {
	return feed.EventItem{
		LogID:            "log-" + label,
		EventType:        feed.EventTypeAgentRegistered,
		CreatedAt:        "2025-01-01T00:00:00Z",
		AgentID:          "550e8400-e29b-41d4-a716-446655440000",
		AnsName:          "ans://v1.0.0." + host,
		AgentHost:        host,
		AgentDisplayName: label,
		Version:          "1.0.0",
		Endpoints: []feed.AgentEndpoint{{
			AgentURL: "https://" + host + "/mcp",
			Protocol: feed.ProtocolMCP,
		}},
	}
}

var silent = zerolog.Nop()

func fixedClock(ts time.Time) poller.Clock { return func() time.Time { return ts } }

// runRound runs exactly one poll round by cancelling the context after a
// short delay; New+Run does the immediate first round before the ticker.
func runRound(t *testing.T, p *poller.Poller) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = p.Run(ctx)
		close(done)
	}()
	// The immediate first round runs synchronously at Run entry, before
	// the ticker; give it a moment, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not stop after cancel")
	}
}

func TestPoller_IngestsAndAdvancesCursor(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &fakeClient{
		pages: []feed.EventPageResponse{
			{Items: []feed.EventItem{registeredItem("a.example.com", "alpha")}, LastLogID: "log-alpha"},
			{Items: []feed.EventItem{registeredItem("b.example.com", "beta")}}, // tail: no cursor
		},
	}
	pollAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	p := poller.New(fc, idx, poller.Config{
		Interval:       time.Hour, // never ticks during the test
		PageSize:       100,
		ProjectOptions: project.Options{TLBaseURL: "https://tl.example.org", AllowHTTP: false},
	}, silent, fixedClock(pollAt))

	runRound(t, p)

	// Both events ingested.
	res, err := idx.Search(context.Background(), index.SearchQuery{Text: "", Limit: 50},
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Results) != 2 {
		t.Fatalf("ingested %d entries, want 2", len(res.Results))
	}

	// Cursor advanced; lastPollOK recorded.
	c, _ := idx.Cursor(context.Background())
	if c.LastLogID != "log-beta" {
		t.Errorf("cursor lastLogID: got %q, want log-beta (tail page's last item)", c.LastLogID)
	}
	if !c.LastPollOK.Equal(pollAt) {
		t.Errorf("lastPollOK: got %v, want %v", c.LastPollOK, pollAt)
	}

	// Second page was fetched with the first page's cursor.
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.gotCursor) < 2 || fc.gotCursor[1] != "log-alpha" {
		t.Errorf("second fetch cursor: got %v, want log-alpha", fc.gotCursor)
	}
}

func TestPoller_EmptyFeedRecordsPollOK(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &fakeClient{pages: []feed.EventPageResponse{{}}} // empty tail page
	pollAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent, fixedClock(pollAt))

	runRound(t, p)

	c, _ := idx.Cursor(context.Background())
	if !c.LastPollOK.Equal(pollAt) {
		t.Errorf("empty feed should still record a successful poll: got %v", c.LastPollOK)
	}
}

func TestPoller_StructuralErrorAbortsRoundWithoutAdvancing(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	// A malformed event (bad UUID) makes FromEvent return a structural
	// error → the page must abort and the cursor must NOT advance.
	bad := registeredItem("a.example.com", "alpha")
	bad.AgentID = "not-a-uuid"
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{bad}, LastLogID: "log-alpha"},
	}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent,
		fixedClock(time.Now()))

	runRound(t, p)

	c, _ := idx.Cursor(context.Background())
	if c.LastLogID != "" {
		t.Errorf("cursor advanced past a structurally invalid event: %q", c.LastLogID)
	}
	if !c.LastPollOK.IsZero() {
		t.Errorf("a failed round must not record poll success: %v", c.LastPollOK)
	}
}

func TestPoller_SkipDoesNotAbort(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	// An unknown eventType is a Skip, not a structural error: the page
	// applies, the cursor advances, and the good event in the same page is
	// ingested.
	unknown := registeredItem("a.example.com", "alpha")
	unknown.EventType = "AGENT_TELEPORTED"
	good := registeredItem("b.example.com", "beta")
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{unknown, good}, LastLogID: "log-beta"},
	}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent,
		fixedClock(time.Now()))

	runRound(t, p)

	c, _ := idx.Cursor(context.Background())
	if c.LastLogID != "log-beta" {
		t.Errorf("cursor should advance past a skip: %q", c.LastLogID)
	}
	res, _ := idx.Search(context.Background(), index.SearchQuery{Text: "beta", Limit: 10},
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(res.Results) != 1 {
		t.Errorf("good event in skip-bearing page not ingested: %d", len(res.Results))
	}
}

func TestPoller_FetchErrorDoesNotAdvance(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	fc := &fakeClient{errs: []error{errors.New("network down")}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent,
		fixedClock(time.Now()))

	runRound(t, p)

	c, _ := idx.Cursor(context.Background())
	if c.LastLogID != "" || !c.LastPollOK.IsZero() {
		t.Errorf("fetch error should leave cursor untouched: %+v", c)
	}
}

func TestPoller_RevokeSuppressesPriorRegistration(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	reg := registeredItem("a.example.com", "alpha")
	rev := feed.EventItem{
		LogID:     "log-revoke",
		EventType: feed.EventTypeAgentRevoked,
		CreatedAt: "2025-02-01T00:00:00Z",
		AgentID:   reg.AgentID,
		AnsName:   reg.AnsName,
		AgentHost: reg.AgentHost,
		Version:   reg.Version,
	}
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{reg, rev}},
	}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent,
		fixedClock(time.Now()))

	runRound(t, p)

	res, _ := idx.Search(context.Background(), index.SearchQuery{Text: "alpha", Limit: 10},
		time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(res.Results) != 0 {
		t.Errorf("revoke in the same page should suppress the registration: %d", len(res.Results))
	}
}

// failingIndex returns an error from Apply, to drive the apply-error path.
type failingIndex struct {
	index.Catalog
}

func (failingIndex) Apply(context.Context, []project.ProjectedEntry) (index.ApplyReport, error) {
	return index.ApplyReport{}, errors.New("apply boom")
}

func TestPoller_ApplyErrorDoesNotAdvance(t *testing.T) {
	t.Parallel()
	base := newIndex(t)
	idx := failingIndex{Catalog: base}
	fc := &fakeClient{pages: []feed.EventPageResponse{
		{Items: []feed.EventItem{registeredItem("a.example.com", "alpha")}, LastLogID: "log-alpha"},
	}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour, PageSize: 100}, silent,
		fixedClock(time.Now()))

	runRound(t, p)

	c, _ := base.Cursor(context.Background())
	if c.LastLogID != "" {
		t.Errorf("apply error should not advance cursor: %q", c.LastLogID)
	}
}

func TestPoller_DefaultsPageSize(t *testing.T) {
	t.Parallel()
	idx := newIndex(t)
	// PageSize 0 → defaulted to 100; a single empty page round still works.
	fc := &fakeClient{pages: []feed.EventPageResponse{{}}}
	p := poller.New(fc, idx, poller.Config{Interval: time.Hour}, silent, nil) // nil clock → time.Now
	runRound(t, p)
	c, _ := idx.Cursor(context.Background())
	if c.LastPollOK.IsZero() {
		t.Errorf("expected a recorded poll with defaulted config")
	}
}
