// Package outbox holds the RA's outbox-delivery worker.
//
// The worker closes the RA → TL data path: every lifecycle
// transition in the RA writes a signed event row into the
// outbox_events table (see internal/ra/service/registration.go); this
// worker reads those rows and POSTs them to the TL via
// internal/adapter/tlclient.
//
// Design invariants:
//
//   - **Replay verbatim.** The outbox payload was signed exactly
//     once at enqueue time (JCS-canonical inner event + detached
//     JWS). On retries the worker MUST send those exact bytes; the
//     TL deduplicates on the content hash. Regenerating either side
//     would break dedup and invalidate the signature.
//   - **Exponential backoff, capped.** Transient failures (transport
//     errors, 5xx, 429) retry with the backoff already encoded in
//     OutboxStore.MarkFailed.
//   - **Permanent failures are logged loudly but kept in the table.**
//     A 422 from the TL (e.g., producer-signature mismatch) means
//     the current producer-key trust can't accept this event. We
//     mark the row with max backoff so it retries rarely but doesn't
//     disappear — if an operator fixes the trust store, the next
//     retry succeeds.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
	"github.com/agentnameservice/ans/internal/adapter/tlclient"
	"github.com/agentnameservice/ans/internal/ra/service"
)

// Options configures the Worker.
type Options struct {
	// BatchSize is how many rows each tick claims. Default 10.
	BatchSize int
	// PollInterval is how often the worker polls. Default 2s.
	PollInterval time.Duration
	// MaxBackoff caps the exponential backoff in OutboxStore.MarkFailed.
	// Default 5min.
	MaxBackoff time.Duration
}

// Worker drains the outbox and POSTs each event to the TL.
//
// A Worker runs as a single background goroutine. Start it via Run
// with a cancellable context; cancel the context to stop the worker
// at shutdown. Run is safe to call exactly once per Worker instance.
type Worker struct {
	store  *sqlite.OutboxStore
	client Sender
	logger zerolog.Logger
	opts   Options
}

// Sender is the subset of *tlclient.Client the worker calls. Having
// an interface makes testing straightforward — unit tests substitute
// a fake without needing a real HTTP server (though we also have
// httptest integration tests in the tlclient package).
//
// The schemaVersion argument is the value stored on the outbox row
// ("V1" or "V2"); the client uses it to pick the matching TL ingest
// URL.
type Sender interface {
	Append(ctx context.Context, schemaVersion string, body []byte, producerSig string) (*tlclient.AppendResult, error)
}

// NewWorker constructs a Worker. Zero-valued Options fields fall
// back to their defaults.
func NewWorker(store *sqlite.OutboxStore, client Sender, logger zerolog.Logger, opts Options) *Worker {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 5 * time.Minute
	}
	return &Worker{
		store:  store,
		client: client,
		logger: logger.With().Str("component", "outbox-worker").Logger(),
		opts:   opts,
	}
}

// Run blocks until ctx is cancelled, processing outbox rows on a
// ticker. Returns nil on clean shutdown.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info().
		Int("batchSize", w.opts.BatchSize).
		Dur("pollInterval", w.opts.PollInterval).
		Dur("maxBackoff", w.opts.MaxBackoff).
		Msg("outbox worker started")

	// Drain once at startup so we don't wait a tick after boot.
	w.tick(ctx)

	ticker := time.NewTicker(w.opts.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info().Msg("outbox worker stopped")
			return nil
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

// tick claims up to BatchSize rows and processes each one. Errors
// are logged but don't abort the loop — the next tick will try
// again.
func (w *Worker) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	events, err := w.store.Claim(ctx, w.opts.BatchSize)
	if err != nil {
		w.logger.Error().Err(err).Msg("claim")
		return
	}
	for i := range events {
		w.process(ctx, &events[i])
	}
}

// process sends a single outbox row to the TL and updates its status.
func (w *Worker) process(ctx context.Context, ev *sqlite.OutboxEvent) {
	log := w.logger.With().
		Int64("id", ev.ID).
		Str("eventType", ev.EventType).
		Str("agentId", ev.AgentID).
		Int("attempts", ev.Attempts).
		Logger()

	var payload service.OutboxPayload
	if err := json.Unmarshal(ev.PayloadJSON, &payload); err != nil {
		// Row is malformed — unlikely in practice (we wrote it
		// ourselves) but treat as a permanent failure so it doesn't
		// spam retries. Ops must inspect the row manually.
		log.Error().Err(err).Msg("outbox row is malformed JSON; marking failed with max backoff")
		w.markFailed(ctx, ev, fmt.Sprintf("unmarshal payload: %v", err))
		return
	}
	if len(payload.InnerEventCanonical) == 0 || payload.ProducerSignature == "" {
		log.Error().Msg("outbox row missing innerEventCanonical or producerSignature")
		w.markFailed(ctx, ev, "payload missing inner event or signature")
		return
	}

	if ev.SchemaVersion == "" {
		// Pre-migration rows default to V2 at the column level, but
		// if a row somehow lacks a version (manual insert, bad
		// fixture), bail rather than guess — guessing risks posting
		// a V2 envelope to /v1 and triggering obscure 422s.
		log.Error().Msg("outbox row has empty schema_version; marking failed")
		w.markFailed(ctx, ev, "outbox row missing schema_version")
		return
	}
	res, err := w.client.Append(ctx, ev.SchemaVersion, payload.InnerEventCanonical, payload.ProducerSignature)
	if err != nil {
		switch {
		case tlclient.IsPermanent(err):
			// Most common: producer-key trust store rejected the
			// signature. Logged at ERROR so operators see it
			// immediately. Row stays in the table with max backoff.
			log.Error().Err(err).Msg("TL rejected event permanently; row retained at max backoff")
		case tlclient.IsTransient(err):
			log.Warn().Err(err).Msg("TL append transient failure; will retry")
		default:
			log.Error().Err(err).Msg("TL append unexpected error")
		}
		w.markFailed(ctx, ev, err.Error())
		return
	}

	if res.LogID == "" {
		// The TL accepted the event but returned no logId. A
		// compliant ans-tl always echoes one (including on duplicate
		// retries), but an older or reference-shaped TL can answer 201
		// with the logId field omitted. Persisting an empty logId
		// would defeat the feed gate (`log_id IS NOT NULL` would still
		// pass on ""), surface `"logId":""` to consumers — which fails
		// their EventItem.Validate() — and, if that row is last on a
		// page, reset the client cursor to the stream head. Treat it as
		// a delivery anomaly: leave the row pending (NOT marked sent)
		// and retry with backoff. The TL dedupes on content hash, so a
		// later retry against a fixed TL records the real logId without
		// duplicating the leaf.
		log.Error().
			Uint64("leafIndex", res.LeafIndex).
			Bool("duplicate", res.Duplicate).
			Msg("TL accepted event but returned empty logId; row kept pending for retry")
		w.markFailed(ctx, ev, "TL returned empty logId")
		return
	}

	if markErr := w.store.MarkSent(ctx, ev.ID, res.LogID); markErr != nil {
		// Rare: the TL accepted the event but we couldn't update
		// the outbox row. Next tick will re-send, and the TL will
		// reply 200 OK (duplicate) since event_hash dedups. Still
		// log loudly.
		log.Error().Err(markErr).Msg("TL accepted but MarkSent failed; next retry will dedupe")
		return
	}
	log.Info().
		Uint64("leafIndex", res.LeafIndex).
		Bool("duplicate", res.Duplicate).
		Msg("delivered")
}

// markFailed wraps OutboxStore.MarkFailed with error logging. On a
// double-failure (can't mark the row), we log but don't panic — the
// next tick will re-claim and try again.
func (w *Worker) markFailed(ctx context.Context, ev *sqlite.OutboxEvent, reason string) {
	if err := w.store.MarkFailed(ctx, ev.ID, ev.Attempts+1, reason, w.opts.MaxBackoff); err != nil {
		// Only log if we were not cancelling; ctx cancellation races
		// are expected at shutdown.
		if !errors.Is(err, context.Canceled) {
			w.logger.Error().Err(err).Int64("id", ev.ID).Msg("MarkFailed")
		}
	}
}
