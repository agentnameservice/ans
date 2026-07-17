package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// stubReader is a port.FeedReader the handler tests drive through a
// real EventsService.
type stubReader struct {
	rows  []port.FeedRow
	err   error
	lastQ port.FeedQuery
}

func (s *stubReader) ReadFeed(_ context.Context, q port.FeedQuery) ([]port.FeedRow, error) {
	s.lastQ = q
	if s.err != nil {
		return nil, s.err
	}
	return s.rows, nil
}

func newEventsHandler(rows []port.FeedRow) (*V1EventsHandler, *stubReader) {
	reader := &stubReader{rows: rows}
	return NewV1EventsHandler(service.NewEventsService(reader), zerolog.Nop()), reader
}

func feedPayload() []byte {
	inner, _ := json.Marshal(map[string]any{
		"ansId":     "a",
		"ansName":   "ans://v1.0.0.a.example.com",
		"eventType": "AGENT_REGISTERED",
		"timestamp": "2025-01-08T12:30:00Z",
		"agent":     map[string]any{"host": "a.example.com", "version": "1.0.0"},
	})
	payload, _ := json.Marshal(service.OutboxPayload{
		InnerEventCanonical: inner,
		ProducerSignature:   "h..s",
	})
	return payload
}

func TestV1EventsHandler_ReturnsPage(t *testing.T) {
	h, _ := newEventsHandler([]port.FeedRow{
		{LogID: "log-1", EventType: "AGENT_REGISTERED", AgentID: "550e8400-e29b-41d4-a716-446655440000", PayloadJSON: feedPayload()},
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/events", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var page service.EventPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 1 || page.LastLogID != "log-1" {
		t.Errorf("page = %+v", page)
	}
}

func TestV1EventsHandler_EmptyPageIsArray(t *testing.T) {
	h, _ := newEventsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/events", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// json.Encoder appends a newline; trim it for the comparison.
	if got := trimNewline(body); got != `{"items":[]}` {
		t.Errorf("empty page body = %q, want {\"items\":[]}", got)
	}
}

func TestV1EventsHandler_ParsesQueryParams(t *testing.T) {
	h, reader := newEventsHandler(nil)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/agents/events?limit=50&lastLogId=cursor-9&providerId=PC_1", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if reader.lastQ.Limit != 50 {
		t.Errorf("limit passed = %d, want 50", reader.lastQ.Limit)
	}
	if reader.lastQ.AfterLogID != "cursor-9" {
		t.Errorf("cursor passed = %q, want cursor-9", reader.lastQ.AfterLogID)
	}
	if reader.lastQ.ProviderFilter != "PC_1" {
		t.Errorf("providerFilter passed = %q, want PC_1", reader.lastQ.ProviderFilter)
	}
}

func TestV1EventsHandler_DefaultLimit(t *testing.T) {
	h, reader := newEventsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/events", nil)
	h.List(httptest.NewRecorder(), req)
	if reader.lastQ.Limit != service.EventsFeedDefaultLimit {
		t.Errorf("default limit = %d, want %d", reader.lastQ.Limit, service.EventsFeedDefaultLimit)
	}
}

func TestV1EventsHandler_InvalidLimit(t *testing.T) {
	cases := []struct {
		name  string
		limit string
	}{
		{"zero", "0"},
		{"negative", "-1"},
		{"over max", "201"},
		{"non-numeric", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, reader := newEventsHandler(nil)
			req := httptest.NewRequest(http.MethodGet, "/v1/agents/events?limit="+tc.limit, nil)
			rec := httptest.NewRecorder()
			h.List(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("error content-type = %q, want application/problem+json", ct)
			}
			var p Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if p.Code != "INVALID_LIMIT" {
				t.Errorf("problem code = %q, want INVALID_LIMIT", p.Code)
			}
			// The reader must not be touched on a rejected request.
			if reader.lastQ.Limit != 0 {
				t.Errorf("reader should not be called on invalid limit")
			}
		})
	}
}

func TestV1EventsHandler_ServiceErrorIs500_NoLeakButLogged(t *testing.T) {
	// The reader fails with an error carrying internal/storage detail.
	// The anonymous feed must NOT echo that text to the client, but the
	// cause MUST be recorded server-side (not swallowed).
	const internalCause = "sqlite/feed: connection to /var/lib/ans/ra.db refused"
	reader := &stubReader{err: errors.New(internalCause)}

	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)
	h := NewV1EventsHandler(service.NewEventsService(reader), logger)

	req := httptest.NewRequest(http.MethodGet, "/v1/agents/events", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("error content-type = %q, want application/problem+json", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	// Body: generic, no internal text.
	for _, leak := range []string{"sqlite", "/var/lib", "refused", "feed:"} {
		if strings.Contains(p.Detail, leak) {
			t.Errorf("500 detail leaks internal string %q: %q", leak, p.Detail)
		}
	}
	if p.Detail == "" {
		t.Error("500 detail should be a generic non-empty message")
	}
	// Log: the real cause IS recorded server-side.
	logged := logBuf.String()
	if !strings.Contains(logged, internalCause) {
		t.Errorf("internal cause not logged server-side; log was: %q", logged)
	}
	if !strings.Contains(logged, `"level":"error"`) {
		t.Errorf("cause should be logged at error level; log was: %q", logged)
	}
}

// TestResponder_WriteError_LogsOnlyUnexpected pins the shared seam
// directly: a caller-safe *domain.Error (maps to a 4xx) is NOT logged
// (it carries no internal detail and would be log noise), while a
// non-domain error (maps to 500) IS logged so its cause survives the
// detail sanitization. This is the regression guard for the MEDIUM:
// the sanitized 500 must never swallow the cause.
func TestResponder_WriteError_LogsOnlyUnexpected(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantCode  int
		wantLog   bool
		causeText string
	}{
		{
			name:     "domain validation error: 422, not logged",
			err:      domain.NewValidationError("BAD", "bad input"),
			wantCode: http.StatusUnprocessableEntity,
			wantLog:  false,
		},
		{
			name:     "domain not-found: 404, not logged",
			err:      domain.NewNotFoundError("NF", "missing"),
			wantCode: http.StatusNotFound,
			wantLog:  false,
		},
		{
			name:      "unexpected error: 500, logged",
			err:       errors.New("internal: disk on fire"),
			wantCode:  http.StatusInternalServerError,
			wantLog:   true,
			causeText: "disk on fire",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			re := newResponder(zerolog.New(&buf))
			rec := httptest.NewRecorder()
			re.writeError(rec, tc.err)

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			gotLog := buf.Len() > 0
			if gotLog != tc.wantLog {
				t.Errorf("logged = %v, want %v (log: %q)", gotLog, tc.wantLog, buf.String())
			}
			if tc.wantLog && !strings.Contains(buf.String(), tc.causeText) {
				t.Errorf("log missing cause %q: %q", tc.causeText, buf.String())
			}
		})
	}
}

func TestV1EventsHandler_MaxLimitAccepted(t *testing.T) {
	h, reader := newEventsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/agents/events?limit=200", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if reader.lastQ.Limit != 200 {
		t.Errorf("limit = %d, want 200", reader.lastQ.Limit)
	}
}

// TestV1EventsRoute_DoesNotClashWithAgentIDWildcard proves chi routes
// the static /v1/agents/events segment to the events handler even
// though /v1/agents/{agentId} is also registered — chi prefers static
// segments over wildcards. This guards the route-registration claim in
// cmd/ans-ra/main.go.
func TestV1EventsRoute_DoesNotClashWithAgentIDWildcard(t *testing.T) {
	h, _ := newEventsHandler(nil)
	r := chi.NewRouter()
	hit := ""
	r.Get("/v1/agents/{agentId}", func(w http.ResponseWriter, req *http.Request) {
		hit = "detail:" + chi.URLParam(req, "agentId")
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/v1/agents/events", func(w http.ResponseWriter, req *http.Request) {
		hit = "events"
		h.List(w, req)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/agents/events", nil))
	if hit != "events" {
		t.Fatalf("/v1/agents/events routed to %q, want the events handler", hit)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("events route status = %d, want 200", rec.Code)
	}

	// A real agentId still reaches the detail route.
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/v1/agents/550e8400-e29b-41d4-a716-446655440000", nil))
	if hit != "detail:550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("agentId route hit = %q", hit)
	}
}

func trimNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}
	return s
}
