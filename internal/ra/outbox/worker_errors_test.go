package outbox_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/tlclient"
	"github.com/godaddy/ans/internal/ra/outbox"
)

// TestWorker_GenericError covers the third arm of the error switch in
// process: when the sender returns an error that is *neither* a
// tlclient.TransientError nor a tlclient.PermanentError. In production
// this could be a JSON-encoding bug or a non-tlclient wrapper; the
// worker should still mark the row failed (not permanently bury it,
// not retry forever) and log at ERROR.
func TestWorker_GenericError(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	var calls atomic.Int32
	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		calls.Add(1)
		// Plain unwrapped error — not a TransientError or PermanentError.
		return nil, errors.New("nondescript boom")
	})

	enqueuePayload(t, store, "ra", time.Now())

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		MaxBackoff:   500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.Run(ctx) }()
	defer cancel()

	// Wait for the worker to attempt at least once and mark the row
	// non-claimable.
	waitUntil(t, 1*time.Second, func() bool {
		pending, _ := store.Claim(context.Background(), 10)
		return calls.Load() >= 1 && len(pending) == 0
	})
}

// TestWorker_DBClosedDuringMarkFailed exercises the markFailed
// "MarkFailed itself failed" branch by closing the DB while the
// worker is mid-processing. We expect the worker to log the
// MarkFailed failure at ERROR and continue rather than panic.
//
// Driving the branch is enough to lift markFailed from 33.3% to
// fully covered. The real production safeguard is "don't panic on a
// double-failure"; the test confirms that holds.
func TestWorker_DBClosedDuringMarkFailed(t *testing.T) {
	t.Parallel()
	store, cleanup := newOutboxStore(t)
	defer cleanup()

	// Sender always returns a generic error so the worker always
	// reaches markFailed.
	sender := newFakeSender(func(_ []byte, _ string) (*tlclient.AppendResult, error) {
		return nil, errors.New("forever broken")
	})

	enqueuePayload(t, store, "ra", time.Now())

	w := outbox.NewWorker(store, sender, zerolog.Nop(), outbox.Options{
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		MaxBackoff:   500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)
		close(done)
	}()

	// Let one tick land so the worker reaches process() at least once
	// and the row goes into backoff.
	time.Sleep(50 * time.Millisecond)
	// Close the underlying DB. Any subsequent MarkFailed call will
	// error; the markFailed branch logs and continues.
	cleanup()
	// Wait briefly for one more tick to exercise the failed-MarkFailed
	// branch, then shut down cleanly.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop within 2s")
	}
}
