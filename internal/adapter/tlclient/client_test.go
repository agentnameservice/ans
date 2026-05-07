package tlclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/tlclient"
)

func TestAppend_Created(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing/wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Signature") != "detached..jws" {
			t.Errorf("missing/wrong X-Signature: %q", r.Header.Get("X-Signature"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("wrong Content-Type: %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"logId":"01900000-0000-7000-8000-000000000001","message":"Event logged successfully","success":true,"leafIndex":7,"leafHashHex":"abc","duplicate":false,"treeSize":8}`))
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "test-key", 5*time.Second)
	res, err := c.Append(context.Background(), "V2", []byte(`{"eventType":"AGENT_ACTIVE"}`), "detached..jws")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if res.LeafIndex != 7 {
		t.Errorf("leafIndex: got %d want 7", res.LeafIndex)
	}
	if res.Duplicate {
		t.Error("duplicate should be false")
	}
	if res.LogID == "" {
		t.Error("logId should propagate from the TL response")
	}
	if !res.Success {
		t.Error("success should be true on new-append 200")
	}
}

func TestAppend_DuplicateOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // idempotent retry
		_, _ = w.Write([]byte(`{"logId":"01900000-0000-7000-8000-000000000001","message":"Event already logged","success":true,"leafIndex":3,"leafHashHex":"xyz","duplicate":true,"treeSize":8}`))
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", 5*time.Second)
	res, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	if err != nil {
		t.Fatalf("200 OK should not error: %v", err)
	}
	if !res.Duplicate {
		t.Error("duplicate should be true")
	}
	if res.Message != "Event already logged" {
		t.Errorf("duplicate message: got %q", res.Message)
	}
}

func TestAppend_422IsPermanent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"MISMATCH_SIGNATURE"}`))
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", 5*time.Second)
	_, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	if err == nil {
		t.Fatal("expected error for 422")
	}
	if !tlclient.IsPermanent(err) {
		t.Fatalf("422 should be permanent; got %T: %v", err, err)
	}
	if tlclient.IsTransient(err) {
		t.Fatalf("422 should NOT be transient; got %T", err)
	}
}

func TestAppend_500IsTransient(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", 5*time.Second)
	_, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	if !tlclient.IsTransient(err) {
		t.Fatalf("500 should be transient; got %T: %v", err, err)
	}
}

func TestAppend_429IsTransient(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", 5*time.Second)
	_, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	if !tlclient.IsTransient(err) {
		t.Fatalf("429 should be transient; got %T: %v", err, err)
	}
}

func TestAppend_TransportErrorIsTransient(t *testing.T) {
	t.Parallel()
	// Unreachable port — should yield a transport error.
	c := tlclient.New("http://127.0.0.1:1", "k", 100*time.Millisecond)
	_, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	if !tlclient.IsTransient(err) {
		t.Fatalf("transport failure should be transient; got %T: %v", err, err)
	}
	var te *tlclient.TransientError
	if !errors.As(err, &te) {
		t.Fatalf("could not unwrap to *TransientError: %v", err)
	}
	if te.Status != 0 {
		t.Errorf("transport failure Status should be 0; got %d", te.Status)
	}
}

func TestAppend_RejectsEmptyBody(t *testing.T) {
	t.Parallel()
	c := tlclient.New("http://example.invalid", "k", time.Second)
	_, err := c.Append(context.Background(), "V2", nil, "sig")
	if err == nil {
		t.Fatal("expected error for empty body")
	}
	// Not transient/permanent — it's a client-side arg check.
	if tlclient.IsTransient(err) || tlclient.IsPermanent(err) {
		t.Fatalf("empty-body error shouldn't be classified: %T", err)
	}
}

func TestAppend_RejectsEmptySignature(t *testing.T) {
	t.Parallel()
	c := tlclient.New("http://example.invalid", "k", time.Second)
	_, err := c.Append(context.Background(), "V2", []byte(`{}`), "")
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestAppend_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := c.Append(ctx, "V2", []byte(`{"e":1}`), "sig")
	if !tlclient.IsTransient(err) {
		t.Fatalf("cancelled request should be transient; got %T: %v", err, err)
	}
}

func TestAppend_303IsTransient(t *testing.T) {
	t.Parallel()
	// Redirect response — the TL shouldn't redirect for POST, but
	// if something did, our classifier should treat it as a surprise
	// worth retrying.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", time.Second)
	_, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	// httptest doesn't auto-follow on POST by default with this client.
	// The classifier in `default:` handles 3xx → transient.
	if err != nil && !tlclient.IsTransient(err) {
		t.Fatalf("3xx should be transient; got %T: %v", err, err)
	}
}

func TestAppend_GarbageBodyIsNotSuccess(t *testing.T) {
	t.Parallel()
	// 201 with unparseable body — we error out (not silent).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c := tlclient.New(srv.URL, "k", time.Second)
	_, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig")
	if err == nil {
		t.Fatal("expected error on un-parseable success body")
	}
}

// TestAppend_URLRoutingBySchemaVersion confirms the client picks the
// matching ingest lane for each schema version — V1 bodies go to
// `/v1/internal/agents/event`, V2 bodies to `/v2/internal/agents/event`.
// Regression guard: a previous implementation hard-coded the V1 URL
// and silently sent V2 envelopes there, which the TL rejected with
// a 422 that looked like a signature failure.
func TestAppend_URLRoutingBySchemaVersion(t *testing.T) {
	t.Parallel()
	// `gotPath` is written by the httptest server's handler goroutine
	// and read by the test goroutine after each Append returns. Even
	// though net/http's internals happen to establish a happens-before
	// edge through their connection-handling channels (so -race passes
	// today), relying on a third-party library's internal sync to
	// publish a write is a fragile contract — guard explicitly.
	var (
		mu      sync.Mutex
		gotPath string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"leafIndex":0,"leafHashHex":"a","duplicate":false,"treeSize":1}`))
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "k", time.Second)

	readPath := func() string {
		mu.Lock()
		defer mu.Unlock()
		return gotPath
	}

	if _, err := c.Append(context.Background(), "V1", []byte(`{"e":1}`), "sig"); err != nil {
		t.Fatalf("V1 append: %v", err)
	}
	if p := readPath(); p != "/v1/internal/agents/event" {
		t.Errorf("V1 path: got %q, want /v1/internal/agents/event", p)
	}

	if _, err := c.Append(context.Background(), "V2", []byte(`{"e":1}`), "sig"); err != nil {
		t.Fatalf("V2 append: %v", err)
	}
	if p := readPath(); p != "/v2/internal/agents/event" {
		t.Errorf("V2 path: got %q, want /v2/internal/agents/event", p)
	}
}

// TestAppend_UnknownSchemaVersion errors before hitting the network
// rather than defaulting to one lane. Defaulting would hide
// configuration bugs; the explicit error points operators at the
// offending outbox row.
func TestAppend_UnknownSchemaVersion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("client should never hit the server with an unknown schemaVersion")
	}))
	defer srv.Close()
	c := tlclient.New(srv.URL, "k", time.Second)
	if _, err := c.Append(context.Background(), "V9", []byte(`{"e":1}`), "sig"); err == nil {
		t.Fatal("expected error on unknown schemaVersion")
	}
}
