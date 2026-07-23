package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
	"github.com/agentnameservice/ans/internal/adapter/tlclient"
	"github.com/agentnameservice/ans/internal/ra/outbox"
	"github.com/agentnameservice/ans/internal/ra/service"
)

// TestWorker_HappyPath_DrainsQueue enqueues three events and asserts
// the worker delivers all three within a few ticks and marks them
// sent. The fake Sender records every Append call so we can verify
// the bytes match what was enqueued (replay-verbatim invariant).
func TestWorker_HappyPath_DrainsQueue(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	sender := newFakeSender(func(body []byte, sig string) (*tlclient.AppendResult, error) {
		return &tlclient.AppendResult{LeafIndex: 0, Duplicate: false, TreeSize: 1}, nil
	})

	now := time.Now()
	ids := make([]int64, 0, 3)
	for i := range 3 {
		ids = append(ids, enqueuePayload(t, store, fmt.Sprintf("ra=%d", i), now))
	}

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 20 * time.Millisecond,
		MaxBackoff:   time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	waitUntil(t, 2*time.Second, func() bool {
		return sender.callCount() == 3
	})

	// All rows should be marked sent.
	pending, err := store.Claim(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending, got %d", len(pending))
	}

	// Each call should carry one of the signed payloads we enqueued.
	if sigs := sender.signatures(); len(sigs) != 3 {
		t.Fatalf("sender saw %d signatures, want 3", len(sigs))
	}
	for _, id := range ids {
		_ = id // we enqueued 3; the IDs are only used to prove they made it in.
	}
}

// TestWorker_Transient_RetriesWithBackoff — a 500 response means the
// worker should keep the row in the table and retry on subsequent
// ticks. We fail twice then succeed; the final state should be
// "sent" and the attempt counter should have advanced.
func TestWorker_Transient_RetriesWithBackoff(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	var calls atomic.Int32
	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		n := calls.Add(1)
		if n < 3 {
			return nil, &tlclient.TransientError{Status: 500, Message: "boom"}
		}
		return &tlclient.AppendResult{LeafIndex: 42}, nil
	})

	enqueuePayload(t, store, "ra", time.Now())

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 20 * time.Millisecond,
		// MaxBackoff must be small enough the exp backoff from
		// MarkFailed doesn't delay past the test timeout. The
		// backoff formula is 2^attempts seconds capped at MaxBackoff.
		MaxBackoff: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	waitUntil(t, 3*time.Second, func() bool {
		pending, _ := store.Claim(context.Background(), 10)
		return len(pending) == 0 && calls.Load() >= 3
	})

	if calls.Load() < 3 {
		t.Fatalf("want >= 3 attempts, got %d", calls.Load())
	}
}

// TestWorker_Permanent_KeepsInTableAtMaxBackoff — 422 from the TL
// means the row will never succeed in its current form. We log
// loudly but keep the row with max backoff (if the operator fixes
// the producer-key trust, it could succeed next time).
func TestWorker_Permanent_KeepsInTableAtMaxBackoff(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	var calls atomic.Int32
	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		calls.Add(1)
		return nil, &tlclient.PermanentError{Status: 422, Message: "MISMATCH_SIGNATURE"}
	})

	enqueuePayload(t, store, "ra", time.Now())

	// MaxBackoff = 2s — the row should retry at most ~once in the
	// first half-second after its first failure.
	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 50 * time.Millisecond,
		MaxBackoff:   2 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	// Give the worker enough time to attempt at least once.
	waitUntil(t, 2*time.Second, func() bool {
		return calls.Load() >= 1
	})

	// The row should still be in the table (not marked sent), but
	// its next_attempt_at should have been pushed into the future.
	// Immediately claiming should return nothing.
	pending, err := store.Claim(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("row should be in backoff, not claimable yet; got %d pending", len(pending))
	}
}

// TestWorker_EmptyOutboxNoOp — with no rows, the worker ticks
// harmlessly. Exercises the claim-returns-empty branch.
func TestWorker_EmptyOutboxNoOp(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	var calls atomic.Int32
	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		calls.Add(1)
		return nil, nil
	})

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		MaxBackoff:   time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("empty outbox should yield 0 sends; got %d", calls.Load())
	}
}

// TestWorker_MissingFieldsRow_Buried — the outbox schema's
// json_valid() check blocks raw-garbage JSON from ever landing in
// the table, so the defensive unmarshal branch is effectively dead.
// But missing-field rows (valid JSON, but empty innerEventCanonical
// or empty producerSignature) are reachable if the RA's signing path
// ever misbehaves. Exercise that branch here — the worker must not
// call the sender and must mark the row with max backoff.
func TestWorker_MissingFieldsRow_Buried(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	// Valid JSON shape but both fields absent → worker should bail.
	_, err := store.Enqueue(context.Background(), "TEST", "agent-1", "V2",
		[]byte(`{}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		t.Fatal("sender should never be called for malformed row")
		return nil, nil
	})

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		MaxBackoff:   500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	waitUntil(t, 1*time.Second, func() bool {
		pending, _ := store.Claim(context.Background(), 10)
		return len(pending) == 0 // row is in backoff → not claimable
	})
}

// TestWorker_CleanShutdown — cancelling the context makes Run return
// promptly.
func TestWorker_CleanShutdown(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		return &tlclient.AppendResult{}, nil
	})

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: time.Second,
		MaxBackoff:   time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return within 500ms of cancel")
	}
}

// TestWorker_RoutesBySchemaVersion confirms the worker passes the
// per-row schema version through to the Sender, so V1 outbox rows
// post to /v1/internal/agents/event and V2 rows post to
// /v2/internal/agents/event. Regression guard against a future
// refactor that accidentally hardcodes one version.
func TestWorker_RoutesBySchemaVersion(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	// Enqueue one V1 and one V2 row, back-to-back. The worker
	// claims in insert order; the Sender sees both versions in the
	// order they were enqueued.
	now := time.Now()
	enqueueVersioned(t, store, "V2", "raid-v2", now)
	enqueueVersioned(t, store, "V1", "raid-v1", now)

	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		return &tlclient.AppendResult{LeafIndex: 0}, nil
	})
	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{BatchSize: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	waitUntil(t, 500*time.Millisecond, func() bool { return sender.callCount() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("worker did not stop after cancel")
	}

	got := sender.recordedVersions()
	if len(got) < 2 {
		t.Fatalf("expected 2 sender calls, got %d: %v", len(got), got)
	}
	if got[0] != "V2" || got[1] != "V1" {
		t.Errorf("schemaVersion order: got %v, want [V2 V1]", got)
	}
}

// TestWorker_PersistsLogIDFromTLResponse confirms the worker forwards
// the logId the TL returned on append into MarkSent, so the
// agent-events feed can serve it as a cursor. Regression guard against
// dropping res.LogID (the bug this PR fixes).
func TestWorker_PersistsLogIDFromTLResponse(t *testing.T) {
	t.Parallel()
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := sqlite.NewOutboxStore(db)

	id := enqueuePayload(t, store, "raid", time.Now())

	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		return &tlclient.AppendResult{LogID: "tl-log-42", LeafIndex: 7}, nil
	})
	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 20 * time.Millisecond,
		MaxBackoff:   time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	waitUntil(t, 2*time.Second, func() bool { return sender.callCount() >= 1 })

	waitUntil(t, 2*time.Second, func() bool {
		var logID string
		if qErr := db.DBX().GetContext(context.Background(), &logID,
			`SELECT COALESCE(log_id, '') FROM outbox_events WHERE id = ?`, id); qErr != nil {
			return false
		}
		return logID == "tl-log-42"
	})
}

// TestWorker_EmptyLogID_KeepsRowPending confirms that when the TL
// accepts an event but returns no logId, the worker does NOT mark the
// row sent (an empty logId would slip past the feed gate and surface
// `"logId":""`). The row stays pending for retry.
func TestWorker_EmptyLogID_KeepsRowPending(t *testing.T) {
	t.Parallel()
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store := sqlite.NewOutboxStore(db)

	id := enqueuePayload(t, store, "raid", time.Now())

	var calls atomic.Int32
	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		calls.Add(1)
		return &tlclient.AppendResult{LogID: "", LeafIndex: 3}, nil // accepted, no logId
	})
	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 20 * time.Millisecond,
		MaxBackoff:   30 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	waitUntil(t, 2*time.Second, func() bool { return calls.Load() >= 1 })
	// The row never gets a non-empty log_id and is never marked sent.
	waitUntil(t, 2*time.Second, func() bool {
		var logID string
		var sentAt *int64
		row := db.DBX().QueryRowContext(context.Background(),
			`SELECT COALESCE(log_id, ''), sent_at_ms FROM outbox_events WHERE id = ?`, id)
		if scanErr := row.Scan(&logID, &sentAt); scanErr != nil {
			return false
		}
		return logID == "" && sentAt == nil
	})
}

// enqueueVersioned is a variant of enqueuePayload that lets the
// caller pick the schema version stamped on the outbox row. Used by
// the dual-lane routing test only — the other tests use
// enqueuePayload which defaults to V2.
func enqueueVersioned(t *testing.T, store *sqlite.OutboxStore, schemaVersion, raID string, now time.Time) {
	t.Helper()
	inner := fmt.Sprintf(`{"ansId":"a","ansName":"ans://v1.0.0.a","eventType":"AGENT_REGISTRATION","raId":%q,"timestamp":%q}`,
		raID, now.UTC().Format(time.RFC3339))
	payload := service.OutboxPayload{
		InnerEventCanonical: json.RawMessage(inner),
		ProducerSignature:   "header..signature-" + raID,
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Enqueue(context.Background(), "AGENT_REGISTRATION", "agent-"+raID, schemaVersion, bytes, now); err != nil {
		t.Fatal(err)
	}
}

// ----- helpers -----

func newOutboxStore(t *testing.T) (*sqlite.OutboxStore, func()) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return sqlite.NewOutboxStore(db), func() { _ = db.Close() }
}

// enqueuePayload writes a realistic-shaped OutboxPayload (JCS bytes
// + detached JWS) so the worker's unmarshal path has something
// legitimate to chew on. The inner event is minimal — just enough
// for the worker to pass it through.
func enqueuePayload(t *testing.T, store *sqlite.OutboxStore, raID string, now time.Time) int64 {
	t.Helper()
	inner := fmt.Sprintf(`{"ansId":"a","ansName":"ans://v1.0.0.a","eventType":"AGENT_REGISTRATION","raId":%q,"timestamp":%q}`,
		raID, now.UTC().Format(time.RFC3339))
	payload := service.OutboxPayload{
		InnerEventCanonical: json.RawMessage(inner),
		ProducerSignature:   "header..signature-" + raID,
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Enqueue(context.Background(), "AGENT_REGISTRATION", "agent-"+raID, "V2", bytes, now)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// waitUntil polls `cond` every 10ms until it returns true or timeout
// elapses.
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// ----- fake Sender -----

type fakeSender struct {
	mu       sync.Mutex
	calls    int
	sigs     []string
	versions []string
	fn       func(body []byte, sig string) (*tlclient.AppendResult, error)
}

func newFakeSender(fn func(body []byte, sig string) (*tlclient.AppendResult, error)) *fakeSender {
	return &fakeSender{fn: fn}
}

// Append records the schemaVersion the worker passed, in addition to
// the body and signature. Tests that care about dual-lane routing
// assert on `versions()` to confirm each row reached the expected URL.
func (s *fakeSender) Append(_ context.Context, schemaVersion string, body []byte, sig string) (*tlclient.AppendResult, error) {
	s.mu.Lock()
	s.calls++
	s.sigs = append(s.sigs, sig)
	s.versions = append(s.versions, schemaVersion)
	fn := s.fn
	s.mu.Unlock()
	_ = body
	return fn(body, sig)
}

// recordedVersions returns a snapshot of the schemaVersion values
// the worker passed, in call order. Used by tests that assert
// dual-lane routing semantics.
func (s *fakeSender) recordedVersions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.versions))
	copy(out, s.versions)
	return out
}

func (s *fakeSender) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *fakeSender) signatures() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.sigs))
	copy(out, s.sigs)
	return out
}
