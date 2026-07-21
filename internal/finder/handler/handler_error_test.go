package handler_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/finder/handler"
	"github.com/godaddy/ans/internal/finder/index"
	"github.com/godaddy/ans/internal/finder/project"
)

// stubIndex is a minimal index.Catalog whose behavior each test field
// overrides. Unset methods return zero values / nil errors.
type stubIndex struct {
	searchErr  error
	exploreErr error
	cursor     index.Cursor
	cursorErr  error
}

func (s stubIndex) Apply(context.Context, []project.ProjectedEntry) (index.ApplyReport, error) {
	return index.ApplyReport{}, nil
}
func (s stubIndex) Search(context.Context, index.SearchQuery, time.Time) (index.SearchResults, error) {
	return index.SearchResults{}, s.searchErr
}
func (s stubIndex) Explore(context.Context, index.ExploreQuery, time.Time) (index.ExploreResults, error) {
	return index.ExploreResults{Facets: map[string]index.Facet{}}, s.exploreErr
}
func (s stubIndex) Cursor(context.Context) (index.Cursor, error)   { return s.cursor, s.cursorErr }
func (s stubIndex) SaveCursor(context.Context, index.Cursor) error { return nil }
func (s stubIndex) Close() error                                   { return nil }

func stubServer(t *testing.T, idx index.Catalog, cfg handler.Config) *httptest.Server {
	t.Helper()
	h := handler.New(idx, cfg, handler.NewRateLimiter(0, 0), zerolog.Nop(), nil)
	r := chi.NewRouter()
	h.Mount(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func TestSearch_IndexErrorIs500(t *testing.T) {
	t.Parallel()
	srv := stubServer(t, stubIndex{searchErr: errors.New("search boom")},
		handler.Config{MaxPageSize: 100, DefaultPageSize: 10})
	status, body := post(t, srv, "/v1/search", `{"query":{"text":"x"}}`)
	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", status)
	}
	if body["code"] != "INTERNAL_ERROR" {
		t.Errorf("code: %v", body["code"])
	}
	// The underlying error message must not leak to the anonymous caller.
	if d, _ := body["detail"].(string); strings.Contains(d, "boom") {
		t.Errorf("internal detail leaked: %q", d)
	}
}

func TestExplore_IndexErrorIs500(t *testing.T) {
	t.Parallel()
	srv := stubServer(t, stubIndex{exploreErr: errors.New("explore boom")}, handler.Config{})
	status, body := post(t, srv, "/v1/explore", `{"query":{},"resultType":{"facets":[{"field":"type"}]}}`)
	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", status)
	}
	if body["code"] != "INTERNAL_ERROR" {
		t.Errorf("code: %v", body["code"])
	}
}

func TestSearch_StaleCursorErrorOmitsSignal(t *testing.T) {
	t.Parallel()
	// Search succeeds but the staleness cursor read fails; the response
	// must still be 200 and simply omit staleSince.
	srv := stubServer(t, stubIndex{cursorErr: errors.New("cursor boom")}, handler.Config{
		MaxPageSize: 100, DefaultPageSize: 10, StaleBound: time.Minute,
	})
	status, body := post(t, srv, "/v1/search", `{"query":{"text":"x"}}`)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (cursor error must not fail the response)", status)
	}
	if _, present := body["staleSince"]; present {
		t.Errorf("cursor error should omit staleSince: %v", body["staleSince"])
	}
}

func TestSearch_NeverPolledReportsZeroStale(t *testing.T) {
	t.Parallel()
	// StaleBound set, cursor present but never polled (zero time) → the
	// signal reports the zero time so a client sees "no ingestion yet".
	srv := stubServer(t, stubIndex{cursor: index.Cursor{}}, handler.Config{
		MaxPageSize: 100, DefaultPageSize: 10, StaleBound: time.Minute,
	})
	status, body := post(t, srv, "/v1/search", `{"query":{"text":"x"}}`)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if body["staleSince"] != "0001-01-01T00:00:00Z" {
		t.Errorf("never-polled staleSince: %v, want zero time", body["staleSince"])
	}
}
