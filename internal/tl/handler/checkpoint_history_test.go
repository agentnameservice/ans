package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetCheckpointHistory_BadParams covers each of the validation
// branches in parseHistoryInput. The empty-log existing test only
// exercises the happy path; this table-driven version walks every
// reject branch to lock down the 422 contract for malformed query
// values. Pre-coverage parseHistoryInput sat at 37.5%; with these
// cases it lands at 100% — the remaining branches are all
// `q.Get(...)` "" early-skips, which the empty-log test already
// covers.
func TestGetCheckpointHistory_BadParams(t *testing.T) {
	tb := newTLTestbed(t)

	cases := []struct {
		name  string
		query string
	}{
		{"limit-non-integer", "limit=abc"},
		{"limit-zero", "limit=0"},
		{"offset-negative", "offset=-1"},
		{"offset-non-integer", "offset=xyz"},
		{"fromSize-zero", "fromSize=0"},
		{"fromSize-non-integer", "fromSize=zzz"},
		{"toSize-zero", "toSize=0"},
		{"toSize-non-integer", "toSize=qq"},
		{"since-not-rfc3339", "since=yesterday"},
		{"order-invalid", "order=SIDEWAYS"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/v1/log/checkpoint/history?"+tc.query, nil)
			rec := httptest.NewRecorder()
			tb.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status: got %d want 422; body=%s", rec.Code, rec.Body)
			}
		})
	}
}

// TestGetCheckpointHistory_AllValidParams exercises the success path
// with every recognized query parameter populated. With no
// checkpoints written yet the list is empty, but parseHistoryInput
// itself sees each branch's non-error case — covering offset/from/
// to/since/order assignment lines.
func TestGetCheckpointHistory_AllValidParams(t *testing.T) {
	tb := newTLTestbed(t)
	q := "limit=5&offset=0&fromSize=1&toSize=99&since=2026-01-01T00:00:00Z&order=ASC"
	req := httptest.NewRequest(http.MethodGet, "/v1/log/checkpoint/history?"+q, nil)
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rec.Code, rec.Body)
	}
}
