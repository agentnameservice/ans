package poller_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/finder/poller"
)

func TestNewHTTPFeedClient_URLPolicy(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		url       string
		allowHTTP bool
		wantErr   bool
	}{
		"https ok":            {"https://feed.example.org", false, false},
		"http rejected":       {"http://feed.example.org", false, true},
		"http allowed in dev": {"http://localhost:18080", true, false},
		"trailing slash ok":   {"https://feed.example.org/", false, false},
		"empty":               {"", false, true},
		"not absolute":        {"/v1/agents/events", false, true},
		"userinfo rejected":   {"https://user:pass@feed.example.org", false, true},
		"query rejected":      {"https://feed.example.org?x=1", false, true},
		"fragment rejected":   {"https://feed.example.org#f", false, true},
		"ftp scheme rejected": {"ftp://feed.example.org", false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := poller.NewHTTPFeedClient(tc.url, tc.allowHTTP, time.Second)
			if tc.wantErr != (err != nil) {
				t.Errorf("url=%q allowHTTP=%v: err=%v, wantErr=%v", tc.url, tc.allowHTTP, err, tc.wantErr)
			}
		})
	}
}

func TestHTTPFeedClient_FetchEvents(t *testing.T) {
	t.Parallel()
	var gotPath, gotQuery, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"logId":"log-1","eventType":"AGENT_REGISTERED",` +
			`"createdAt":"2025-01-01T00:00:00Z","agentId":"550e8400-e29b-41d4-a716-446655440000",` +
			`"ansName":"ans://v1.0.0.a.example.com","agentHost":"a.example.com","version":"1.0.0"}],` +
			`"lastLogId":"log-1"}`))
	}))
	defer srv.Close()

	// httptest serves http; use allowHTTP to accept it.
	c, err := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	page, err := c.FetchEvents(context.Background(), "cursor-7", 25)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotPath != "/v1/agents/events" {
		t.Errorf("path: %q", gotPath)
	}
	if gotQuery != "lastLogId=cursor-7&limit=25" {
		t.Errorf("query: %q", gotQuery)
	}
	if gotAccept != "application/json" {
		t.Errorf("accept: %q", gotAccept)
	}
	if len(page.Items) != 1 || page.Items[0].LogID != "log-1" {
		t.Errorf("items: %+v", page.Items)
	}
	if page.LastLogID != "log-1" {
		t.Errorf("lastLogID: %q", page.LastLogID)
	}
}

func TestHTTPFeedClient_FirstPageOmitsCursor(t *testing.T) {
	t.Parallel()
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	if _, err := c.FetchEvents(context.Background(), "", 0); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// Empty cursor and zero limit → no query string at all.
	if gotQuery != "" {
		t.Errorf("first-page query should be empty, got %q", gotQuery)
	}
}

func TestHTTPFeedClient_Non2xxIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"title":"unavailable"}`))
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	if _, err := c.FetchEvents(context.Background(), "", 10); err == nil {
		t.Fatal("expected error on 503")
	}
}

func TestHTTPFeedClient_BadJSONIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	if _, err := c.FetchEvents(context.Background(), "", 10); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestHTTPFeedClient_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	c, _ := poller.NewHTTPFeedClient(srv.URL, true, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.FetchEvents(ctx, "", 10); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
