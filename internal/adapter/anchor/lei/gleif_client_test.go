package lei

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// gleifLevel1Body is the JSON:API envelope shape api.gleif.org returns
// for a Level 1 record. Tests build a stub server that returns this.
const gleifLevel1Body = `{
  "data": {
    "type": "lei-records",
    "id": "529900T8BM49AURSDO55",
    "attributes": {
      "lei": "529900T8BM49AURSDO55",
      "entity": {
        "legalName": {"name": "Example Bank Inc.", "language": "en"},
        "status": "ACTIVE",
        "legalAddress": {"country": "US"},
        "jurisdiction": "US-DE"
      },
      "registration": {
        "status": "ISSUED",
        "lastUpdateDate": "2026-01-15T10:30:00Z"
      }
    }
  }
}`

func TestGLEIFHTTPClient_LookupRecord_Active(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lei-records/529900T8BM49AURSDO55" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if accept := r.Header.Get("Accept"); !strings.Contains(accept, "json") {
			t.Errorf("missing or wrong Accept header: %q", accept)
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(gleifLevel1Body))
	}))
	defer srv.Close()

	c := NewGLEIFHTTPClient().WithBaseURL(srv.URL)
	rec, err := c.LookupRecord(context.Background(), "529900T8BM49AURSDO55")
	if err != nil {
		t.Fatalf("LookupRecord: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
	if rec.LEI != "529900T8BM49AURSDO55" {
		t.Errorf("LEI: got %q", rec.LEI)
	}
	if rec.EntityName != "Example Bank Inc." {
		t.Errorf("EntityName: got %q", rec.EntityName)
	}
	if rec.EntityStatus != "ACTIVE" {
		t.Errorf("EntityStatus: got %q", rec.EntityStatus)
	}
	if rec.Jurisdiction != "US-DE" {
		t.Errorf("Jurisdiction: got %q", rec.Jurisdiction)
	}
	want, _ := time.Parse(time.RFC3339, "2026-01-15T10:30:00Z")
	if !rec.UpdatedAt.Equal(want) {
		t.Errorf("UpdatedAt: got %v, want %v", rec.UpdatedAt, want)
	}
	if len(rec.AttestationJWK) != 0 {
		t.Error("AttestationJWK should be empty for Level 1 records")
	}
}

func TestGLEIFHTTPClient_LookupRecord_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"status":"404"}]}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewGLEIFHTTPClient().WithBaseURL(srv.URL)
	rec, err := c.LookupRecord(context.Background(), "529900T8BM49AURSDO55")
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil record on 404, got %+v", rec)
	}
}

func TestGLEIFHTTPClient_LookupRecord_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewGLEIFHTTPClient().WithBaseURL(srv.URL)
	rec, err := c.LookupRecord(context.Background(), "529900T8BM49AURSDO55")
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if rec != nil {
		t.Errorf("expected nil record on error, got %+v", rec)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestGLEIFHTTPClient_LookupRecord_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	c := NewGLEIFHTTPClient().WithBaseURL(srv.URL)
	_, err := c.LookupRecord(context.Background(), "529900T8BM49AURSDO55")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGLEIFHTTPClient_LookupRecord_MissingLEI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(`{"data":{"type":"lei-records","id":"x","attributes":{}}}`))
	}))
	defer srv.Close()

	c := NewGLEIFHTTPClient().WithBaseURL(srv.URL)
	_, err := c.LookupRecord(context.Background(), "529900T8BM49AURSDO55")
	if err == nil {
		t.Fatal("expected error when response is missing data.attributes.lei")
	}
}

func TestGLEIFHTTPClient_LookupRecord_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		_, _ = w.Write([]byte(gleifLevel1Body))
	}))
	defer srv.Close()

	c := NewGLEIFHTTPClient().WithBaseURL(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := c.LookupRecord(ctx, "529900T8BM49AURSDO55")
	if err == nil {
		t.Fatal("expected error on context timeout")
	}
}

func TestGLEIFHTTPClient_BaseURLTrailingSlashStripped(t *testing.T) {
	c := NewGLEIFHTTPClient().WithBaseURL("https://example.test/")
	if !strings.HasSuffix(c.baseURL, "test") {
		t.Errorf("trailing slash not stripped: baseURL=%q", c.baseURL)
	}
}

func TestGLEIFHTTPClient_DefaultBaseURL(t *testing.T) {
	c := NewGLEIFHTTPClient()
	if c.baseURL != gleifAPIBaseURL {
		t.Errorf("default base URL: got %q, want %q", c.baseURL, gleifAPIBaseURL)
	}
	if c.http.Timeout == 0 {
		t.Error("HTTP client should have a non-zero timeout")
	}
}
