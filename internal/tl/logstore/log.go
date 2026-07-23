package logstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"

	"github.com/agentnameservice/ans/internal/tl/event"
)

// Config configures the Tessera-backed log.
type Config struct {
	// DataDir is the POSIX layout root (Tessera writes checkpoint,
	// tile/entries/*, tile/<level>/* here).
	DataDir string

	// Origin is the log origin string embedded in every checkpoint
	// note. Verifiers pin this.
	Origin string

	// BatchSize is how many entries Tessera batches before sealing
	// a tile. Default 256.
	BatchSize int

	// BatchMaxAge is the time before a partially-filled batch is
	// sealed. Default 1s.
	BatchMaxAge time.Duration

	// CheckpointInterval is how often a new signed checkpoint is
	// published. Default 10s.
	CheckpointInterval time.Duration
}

// Log wraps a Tessera Appender + Reader. Call Close() to flush and
// release resources on shutdown.
//
// `bgCtx` / `bgCancel` are the cancellable context handed to
// `tessera.NewAppender` and `tessera.NewPublicationAwaiter`. Tessera
// spawns long-running goroutines (the periodic checkpoint publisher
// in `storage/posix/files.go:148`, the awaiter's polling loop) that
// only exit when this context fires. Tessera's docs (commentary on
// `NewAppender`) require the caller to call the returned `shutdown`
// function FIRST to drain in-flight appends, THEN cancel the context
// to release those goroutines. `Close` does that in order.
//
// Without this, a fixture that spins up a Log inside `t.TempDir()`
// would leak goroutines past the test boundary; once `t.Cleanup`
// removes the directory, the still-running publisher emits a noisy
// stream of "publish.lock: no such file or directory" warnings against
// other tests and (under enough parallel pressure) corrupts shared
// state. See the test fixture in `internal/tl/handler/handler_test.go`.
type Log struct {
	cfg      Config
	signer   note.Signer
	appender *tessera.Appender
	reader   tessera.LogReader
	awaiter  *tessera.PublicationAwaiter
	shutdown func(context.Context) error
	bgCancel context.CancelFunc
}

// Open constructs a Tessera log over the given data directory using
// the given C2SP note.Signer as the primary checkpoint signer.
// Optional additional signers (e.g. the JWS additional-signer for
// interop) are passed via Options — Tessera appends one signature
// line per signer to each published checkpoint.
//
// Matches the reference TL's single-signer topology: one ECDSA
// P-256 key drives the primary C2SP line, the additional-signer JWS
// line, and the log's attestation + receipt + status-token signing.
func Open(ctx context.Context, cfg Config, signer note.Signer, opts ...Option) (*Log, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("logstore: DataDir required")
	}
	if cfg.Origin == "" {
		return nil, errors.New("logstore: Origin required")
	}
	if signer == nil {
		return nil, errors.New("logstore: checkpoint signer required")
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 256
	}
	if cfg.BatchMaxAge <= 0 {
		cfg.BatchMaxAge = time.Second
	}
	if cfg.CheckpointInterval <= 0 {
		cfg.CheckpointInterval = 10 * time.Second
	}

	o := options{}
	for _, apply := range opts {
		apply(&o)
	}

	driver, err := posix.New(ctx, posix.Config{Path: cfg.DataDir})
	if err != nil {
		return nil, fmt.Errorf("logstore: open posix storage %q: %w", cfg.DataDir, err)
	}

	// BatchSize is validated above to be > 0 and is set from operator
	// config; the int → uint conversion is bounded by Tessera's own
	// max-batch-size guard inside tessera.WithBatching.
	appendOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer, o.additionalSigners...).
		WithBatching(uint(cfg.BatchSize), cfg.BatchMaxAge). //nolint:gosec // G115: BatchSize > 0 enforced above
		WithCheckpointInterval(cfg.CheckpointInterval)

	// Tessera's background goroutines bind their lifetime to the
	// context passed into NewAppender / NewPublicationAwaiter. Pass a
	// cancellable child of the caller's context so Close can stop them
	// deterministically — see the type docstring for the full rationale.
	bgCtx, bgCancel := context.WithCancel(ctx)
	appender, shutdown, reader, err := tessera.NewAppender(bgCtx, driver, appendOpts)
	if err != nil {
		bgCancel()
		return nil, fmt.Errorf("logstore: new appender: %w", err)
	}

	// PublicationAwaiter polls the reader at a short interval for
	// the first checkpoint that covers a given append future. Used
	// by the TL's per-append goroutine to persist the Tessera-signed
	// checkpoint into the SQLite mirror — matches the reference
	// TL's `tesseraAwaiter`-driven StoreCheckpoint flow.
	awaiter := tessera.NewPublicationAwaiter(bgCtx, reader.ReadCheckpoint, 100*time.Millisecond)

	return &Log{
		cfg:      cfg,
		signer:   signer,
		appender: appender,
		reader:   reader,
		awaiter:  awaiter,
		shutdown: shutdown,
		bgCancel: bgCancel,
	}, nil
}

// Close drains pending appends and stops Tessera's background
// goroutines. Tessera's contract (see `NewAppender` doc): call
// `shutdown` FIRST so in-flight `Add` calls resolve and their
// covering checkpoint gets published, THEN cancel the context so the
// periodic publisher / awaiter goroutines exit.
//
// We always invoke `bgCancel` (even if shutdown errored) so a partial
// failure can't leave goroutines outliving the Log. After cancel, we
// poll the data directory's `.state` until it stops mutating — the
// publishCheckpoint goroutine does file I/O that doesn't honor ctx
// cancellation, so a cycle in flight when cancel fires will continue
// to write files for tens of milliseconds afterwards. Returning
// before that finishes leaks IO past Close, which (in tests) races
// `t.TempDir`'s RemoveAll cleanup with "directory not empty".
func (l *Log) Close(ctx context.Context) error {
	var shutdownErr error
	if l.shutdown != nil {
		shutdownErr = l.shutdown(ctx)
	}
	if l.bgCancel != nil {
		l.bgCancel()
		l.waitForBackgroundIOQuiet()
	}
	return shutdownErr
}

// waitForBackgroundIOQuiet blocks until the Tessera POSIX storage's
// `.state` directory has gone quiet — no `os.Stat` mtime change for
// `quietWindow` consecutive samples — or `maxWait` elapses. The
// `.state` dir contains the publisher's lock + treeState files, so
// it's the goroutine's only writable surface; once it's stable, the
// publishCheckpoint loop has either exited or is parked on
// `ctx.Done`. Filesystem timestamp resolution is the limiting factor
// (≥1ms on macOS APFS, ≥1ns on Linux ext4 / tmpfs), so the poll
// interval is set above that floor.
func (l *Log) waitForBackgroundIOQuiet() {
	const (
		pollInterval = 25 * time.Millisecond
		quietWindow  = 3 // consecutive stable samples
		maxWait      = 2 * time.Second
	)
	stateDir := filepath.Join(l.cfg.DataDir, "tiles", ".state")
	deadline := time.Now().Add(maxWait)
	var lastMod time.Time
	stable := 0
	for time.Now().Before(deadline) {
		info, err := os.Stat(stateDir)
		if err != nil {
			// Directory gone (test cleanup raced us, or never created).
			// Either way no more writes are possible.
			return
		}
		if info.ModTime().Equal(lastMod) {
			stable++
			if stable >= quietWindow {
				return
			}
		} else {
			lastMod = info.ModTime()
			stable = 0
		}
		time.Sleep(pollInterval)
	}
}

// Awaiter exposes the underlying tessera.PublicationAwaiter so callers
// can block until a just-appended leaf is covered by a published
// checkpoint. Used by the LogService per-append goroutine to persist
// the signed checkpoint into the SQLite mirror — same shape as the
// reference TL's `tesseraAwaiter`.
func (l *Log) Awaiter() *tessera.PublicationAwaiter { return l.awaiter }

// AppendResult is what a successful append returns.
type AppendResult struct {
	// LeafIndex is the 0-based position of the leaf in the tree.
	LeafIndex uint64

	// LeafHash is the RFC 6962 §2.1 leaf hash of the canonical
	// envelope bytes: SHA-256(0x00 || canonical). Matches Tessera's
	// internal leaf computation, so an offline verifier walking an
	// inclusion proof from this hash up to the checkpoint root will
	// agree with what Tessera stored.
	LeafHash [32]byte

	// Canonical is the JCS-canonical envelope bytes that were appended.
	// Stored in the SQLite mirror so a receipt verifier can recompute
	// the leaf hash offline without refetching from Tessera.
	Canonical []byte

	// IsDuplicate indicates Tessera's antispam detected this entry
	// already exists; LeafIndex points to the original occurrence.
	IsDuplicate bool

	// Future is the Tessera publication future for this append,
	// re-resolvable (sync.OnceValues-wrapped) so callers can hand it
	// to `Log.Awaiter().Await(...)` from a goroutine to block until
	// the covering checkpoint is published — matches the reference
	// TL's per-append AwaitPublication flow.
	Future tessera.IndexFuture
}

// Append serializes the envelope to JCS-canonical bytes and pushes it
// into the Tessera log. Tessera handles batching, sequencing, antispam,
// tile generation, and checkpoint signing internally.
//
// Accepts any `event.Signable` so V1 and V2 envelopes share this path
// byte-for-byte — Tessera doesn't care which inner-event shape is
// wrapped, only the outer JCS bytes it stores as a leaf.
//
// Preconditions: env.Signature MUST already be populated (i.e., the
// outer TL attestation has been computed). The logstore doesn't sign —
// that's the caller's job, performed before this call so the leaf
// bytes reflect the signed envelope.
//
// The returned AppendResult.Future is the memoized Tessera future;
// callers can re-resolve it (or hand it to the Awaiter) after the
// sync path returns.
func (l *Log) Append(ctx context.Context, env event.Signable) (*AppendResult, error) {
	if err := env.Validate(); err != nil {
		return nil, err
	}
	canonical, err := env.LeafBytes()
	if err != nil {
		return nil, err
	}
	leafHash, err := env.LeafHash()
	if err != nil {
		return nil, err
	}

	future := l.appender.Add(ctx, tessera.NewEntry(canonical))
	index, err := future()
	if err != nil {
		// Tessera exposes a pushback sentinel; let callers decide.
		if errors.Is(err, tessera.ErrPushback) {
			return nil, err
		}
		return nil, fmt.Errorf("logstore: append: %w", err)
	}

	return &AppendResult{
		LeafIndex:   index.Index,
		LeafHash:    leafHash,
		Canonical:   canonical,
		IsDuplicate: index.IsDup,
		Future:      future,
	}, nil
}

// Reader returns the underlying Tessera log reader, which the proof
// builder and checkpoint endpoints use directly.
func (l *Log) Reader() tessera.LogReader { return l.reader }

// Signer returns the primary checkpoint signer. Useful for the
// checkpoint-read path that needs the signer's public key to verify
// stored signatures.
func (l *Log) Signer() note.Signer { return l.signer }

// Origin returns the log origin string.
func (l *Log) Origin() string { return l.cfg.Origin }

// DataDir returns the POSIX storage root (useful for mounting an
// http.FileServer over it to serve checkpoint + tile files).
func (l *Log) DataDir() string { return l.cfg.DataDir }
