// Package service holds the Transparency Log application-layer services.
// Services coordinate the Tessera appender, the SQLite index, and the
// receipt cache; they hold no state of their own.
package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/transparency-dev/tessera"

	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/event"
	identityevent "github.com/agentnameservice/ans/internal/tl/event/identity"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
	"github.com/agentnameservice/ans/internal/tl/logstore"
)

// LogService wires the Tessera appender to the SQLite index and owns
// the envelope lifecycle on the TL side of the boundary.
//
// The reference flow this mirrors:
//
//  1. Accept a raw inner-event body + detached-JWS in X-Signature.
//  2. Verify the producer signature against the raw body.
//  3. Wrap the parsed event in an Envelope the TL owns (assigning
//     logId, recording kid and sig).
//  4. Compute the TL's own attestation signature over the envelope
//     while its outer Signature is empty.
//  5. Populate the outer Signature, JCS-canonicalize, compute the
//     RFC 6962 leaf hash, append to Tessera, and store a mirror row.
//
// The producer-key trust store and a KeyManager for the TL-attestation
// key are injected so unit tests can substitute fakes.
type LogService struct {
	log         *logstore.Log
	events      *sqlitetl.EventStore
	checkpoints *sqlitetl.CheckpointStore
	producerSig *ProducerSigVerifier
	attestKM    port.KeyManager
	attestKeyID string
	originRAID  string // RAID stamped into the TL's attestation JWS header.
	nowFn       func() time.Time
	uuidFn      func() (string, error)

	// shutdownCtx is cancelled when Close is called; the per-append
	// awaiter goroutines watch it so they drain cleanly at shutdown
	// rather than leaking past the log's lifecycle.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	wg             sync.WaitGroup
}

// AppendInput is what the HTTP handler passes in.
type AppendInput struct {
	// RawBody is the unparsed request body (the producer's inner event
	// JSON). The verifier canonicalizes it once; don't canonicalize
	// upstream or the signature will mismatch.
	RawBody []byte
	// ProducerSignature is the value of the X-Signature header — a
	// detached JWS. Empty → 422 NO_PRODUCER_SIGNATURE.
	ProducerSignature string
}

// AppendResult is returned from Append.
//
// LogID is the UUIDv7 assigned to the event on first append. On a
// duplicate retry it is the logID from the previously stored leaf —
// not a fresh UUID — so retries are idempotent against the reference
// TL's logId semantics.
type AppendResult struct {
	LogID     string
	LeafIndex uint64
	LeafHash  [32]byte
	Duplicate bool
	TreeSize  uint64
}

// NewLogService constructs a LogService.
//
// originRAID is written into the `raid` field of the TL's own
// attestation JWS headers. It names the log's identity to downstream
// verifiers and is typically the log's origin string.
func NewLogService(
	log *logstore.Log,
	events *sqlitetl.EventStore,
	checkpoints *sqlitetl.CheckpointStore,
	producerSig *ProducerSigVerifier,
	attestKM port.KeyManager,
	attestKeyID string,
	originRAID string,
) *LogService {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	return &LogService{
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
		log:            log,
		events:         events,
		checkpoints:    checkpoints,
		producerSig:    producerSig,
		attestKM:       attestKM,
		attestKeyID:    attestKeyID,
		originRAID:     originRAID,
		nowFn:          func() time.Time { return time.Now().UTC() },
		// UUIDv7: time-ordered, per the logId contract in the TL API
		// spec and the served event schemas.
		uuidFn: func() (string, error) {
			id, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			return id.String(), nil
		},
	}
}

// WithClock overrides the time source (for tests). Not safe during
// concurrent use; call during construction only.
func (s *LogService) WithClock(fn func() time.Time) { s.nowFn = fn }

// WithUUIDFn overrides the logId generator (for tests).
func (s *LogService) WithUUIDFn(fn func() (string, error)) { s.uuidFn = fn }

// AppendV2 ingests a V2-schema producer event. Wired to the
// `POST /v2/internal/agents/event` route. The RA's V2 routes
// (`/v2/ans/agents/*`) sign and submit events in this shape.
func (s *LogService) AppendV2(ctx context.Context, in AppendInput) (*AppendResult, error) {
	return s.append(ctx, in, v2Codec{})
}

// AppendV1 ingests a V1-schema producer event. Wired to the
// `POST /v1/internal/agents/event` route — the reference TL's
// original ingest path, still the only shape the reference RA emits.
// The RA's V1 routes (`/v1/agents/*`) sign and submit events in this
// shape to match the reference byte-for-byte.
func (s *LogService) AppendV1(ctx context.Context, in AppendInput) (*AppendResult, error) {
	return s.append(ctx, in, v1Codec{})
}

// AppendIdentity ingests an identity-family producer event
// (IDENTITY_*). Wired to the `POST /v1/internal/identities/event`
// route. Identity events ride the same producer-signature lane and
// land in the same Merkle tree as agent events; the dedicated route
// exists because the payload schema differs (keyed by identityId),
// and the codec's closed enum is the cross-lane guard.
func (s *LogService) AppendIdentity(ctx context.Context, in AppendInput) (*AppendResult, error) {
	return s.append(ctx, in, identityCodec{})
}

// append is the schema-agnostic ingest pipeline. The only per-version
// steps (parse, canonicalize, wrap) are delegated to the codec; every
// other step — producer-signature verify, dedup, TL attestation sign,
// Tessera append, SQLite mirror, checkpoint cache refresh — runs
// identically for V1 and V2.
func (s *LogService) append(ctx context.Context, in AppendInput, codec envelopeCodec) (*AppendResult, error) {
	// 1. Verify producer signature over the raw body.
	raID, keyID, err := s.producerSig.Verify(ctx, in.ProducerSignature, in.RawBody)
	if err != nil {
		return nil, err
	}

	// 2. Codec parses/validates/canonicalizes/wraps per schema version.
	//    The returned envelope has an empty outer Signature; we sign
	//    it in step 4.
	logID, err := s.uuidFn()
	if err != nil {
		return nil, fmt.Errorf("generate logId: %w", err)
	}
	env, innerCanonical, err := codec.ParseAndBuild(in.RawBody, raID, keyID, in.ProducerSignature, logID)
	if err != nil {
		return nil, err
	}

	// 3. Compute the dedup key on the canonical inner event. We
	//    re-canonicalize inside the codec rather than hashing
	//    in.RawBody because JCS is the contract; any whitespace or
	//    key-reordering in in.RawBody would otherwise poison dedup.
	eventHash := sqlitetl.ComputeEventHash(innerCanonical)

	if dup, existingIdx, derr := s.events.ExistsByEventHash(ctx, eventHash); derr != nil {
		return nil, derr
	} else if dup {
		rec, gerr := s.events.GetEventByLeafIndex(ctx, existingIdx)
		if gerr != nil {
			return nil, gerr
		}
		lh, lerr := rec.LeafHashBytes()
		if lerr != nil {
			return nil, lerr
		}
		// TreeSize on a duplicate is the *current* tree size, not
		// `existingIdx + 1`. If N events were appended after this
		// leaf, existingIdx + 1 understates the real tree, which
		// would lie to a client trying to fetch a receipt against a
		// specific size. Read from the mirrored checkpoint cache.
		return &AppendResult{
			LogID:     rec.LogID,
			LeafIndex: existingIdx,
			LeafHash:  lh,
			Duplicate: true,
			TreeSize:  s.currentTreeSize(ctx, existingIdx),
		}, nil
	}

	// 4. Sign the envelope — now the Signable is complete.
	signingInput, err := env.SigningInput()
	if err != nil {
		return nil, fmt.Errorf("log: signing input: %w", err)
	}
	attSig, err := anscrypto.SignDetachedJWS(
		ctx, s.attestKM, s.attestKeyID,
		anscrypto.JWSProtectedHeader{
			Typ:       "JWT",
			Timestamp: s.nowFn().Unix(),
			RAID:      s.originRAID,
		},
		signingInput,
	)
	if err != nil {
		return nil, fmt.Errorf("log: TL attestation sign: %w", err)
	}
	if err := setOuterSignature(env, attSig); err != nil {
		return nil, err
	}

	// 5. Append to Tessera — now the envelope is complete, so leaf bytes
	//    reflect the outer signature as well.
	res, err := s.log.Append(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("log: tessera append: %w", err)
	}

	// 6. Persist the mirror row. The store takes event.View, so V1
	//    and V2 both land through this single path.
	if _, err := s.events.StoreEvent(ctx, res.LeafIndex, res.LeafHash, eventHash, env, res.Canonical); err != nil {
		return nil, fmt.Errorf("log: store event: %w", err)
	}

	// 7. Persist the covering checkpoint asynchronously. Matches the
	//    reference TL's `AwaitPublication` flow: block (in a
	//    goroutine) until Tessera has signed + published a checkpoint
	//    that covers this leaf, then upsert the DB mirror. The
	//    goroutine watches the service's shutdown ctx so Close drains
	//    it rather than leaking the persistence wait.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.awaitAndStoreCheckpoint(res.Future)
	}()

	return &AppendResult{
		LogID:     logID,
		LeafIndex: res.LeafIndex,
		LeafHash:  res.LeafHash,
		Duplicate: false,
		TreeSize:  res.LeafIndex + 1,
	}, nil
}

// setOuterSignature populates the envelope's outer TL-attestation
// signature. Both V1 and V2 envelopes expose a public `Signature`
// field, so we type-switch once here rather than widening
// `event.Signable` with a `SetSignature(string)` method that would
// leak a write-side concern into every read-side consumer of View.
func setOuterSignature(env event.Signable, sig string) error {
	switch e := env.(type) {
	case *event.Envelope:
		e.Signature = sig
		return nil
	case *eventv1.Envelope:
		e.Signature = sig
		return nil
	case *identityevent.Envelope:
		e.Signature = sig
		return nil
	default:
		return fmt.Errorf("log: unknown envelope type %T", env)
	}
}

// LatestEventByAgent returns the newest event mirrored for an agent.
func (s *LogService) LatestEventByAgent(ctx context.Context, agentID string) (*sqlitetl.EventRecord, error) {
	return s.events.GetLatestByAgentID(ctx, agentID, 0)
}

// EventsByAgent returns paginated events for an agent.
func (s *LogService) EventsByAgent(ctx context.Context, agentID string, limit, offset int) ([]*sqlitetl.EventRecord, error) {
	return s.events.GetByAgentID(ctx, agentID, limit, offset, 0)
}

// EventByLeafIndex returns the event at a specific leaf.
func (s *LogService) EventByLeafIndex(ctx context.Context, idx uint64) (*sqlitetl.EventRecord, error) {
	return s.events.GetEventByLeafIndex(ctx, idx)
}

// LatestEventByIdentity returns the newest event on an identity's
// stream (the read index over the single log keyed by identityId).
func (s *LogService) LatestEventByIdentity(ctx context.Context, identityID string) (*sqlitetl.EventRecord, error) {
	return s.events.GetLatestByIdentityID(ctx, identityID)
}

// EventsByIdentity returns paginated events for an identity.
func (s *LogService) EventsByIdentity(ctx context.Context, identityID string, limit, offset int) ([]*sqlitetl.EventRecord, error) {
	return s.events.GetByIdentityID(ctx, identityID, limit, offset)
}

// LatestProofByIdentity returns the newest proof event
// (IDENTITY_VERIFIED / IDENTITY_UPDATED) for an identity — the event
// carrying the current proven key set, which the badge join surfaces
// as provenKeyThumbprints.
func (s *LogService) LatestProofByIdentity(ctx context.Context, identityID string) (*sqlitetl.EventRecord, error) {
	return s.events.GetLatestProofByIdentityID(ctx, identityID)
}

// IdentityRevoked reports whether the identity's stream contains an
// IDENTITY_REVOKED event — the terminal read-time rule (§5.6.3):
// once revoked, no later leaf changes the answer.
func (s *LogService) IdentityRevoked(ctx context.Context, identityID string) (bool, error) {
	return s.events.HasIdentityRevoked(ctx, identityID)
}

// LinkStatesByAgent returns the latest link/unlink fact per identity
// that ever named this agent.
func (s *LogService) LinkStatesByAgent(ctx context.Context, ansID string) ([]*sqlitetl.LinkState, error) {
	return s.events.LinkStatesByAgent(ctx, ansID)
}

// LinkStatesByIdentity returns the latest link/unlink fact per agent
// this identity ever named.
func (s *LogService) LinkStatesByIdentity(ctx context.Context, identityID string) ([]*sqlitetl.LinkState, error) {
	return s.events.LinkStatesByIdentity(ctx, identityID)
}

// LinkEventsByAgent returns the link/unlink events that ever named
// this agent — the per-agent association history.
func (s *LogService) LinkEventsByAgent(ctx context.Context, ansID string, limit, offset int) ([]*sqlitetl.EventRecord, error) {
	return s.events.LinkEventsByAgent(ctx, ansID, limit, offset)
}

// LatestCheckpoint returns the most recent checkpoint Tessera has
// written to disk, falling back to the DB cache on file errors.
func (s *LogService) LatestCheckpoint(ctx context.Context) ([]byte, error) {
	raw, err := readCheckpointFile(s.log.DataDir())
	if err == nil {
		return raw, nil
	}
	rec, dberr := s.checkpoints.Latest(ctx)
	if dberr != nil {
		return nil, fmt.Errorf("log: checkpoint read file: %w; db: %w", err, dberr)
	}
	return []byte(rec.CheckpointRaw), nil
}

// Origin returns the log origin string.
func (s *LogService) Origin() string { return s.log.Origin() }

// DataDir returns the POSIX storage root, used by the HTTP handler to
// serve tile and checkpoint files directly.
func (s *LogService) DataDir() string { return s.log.DataDir() }

// currentTreeSize returns the best estimate of the log's current size:
// the latest-checkpoint size if the DB has one, otherwise a
// conservative lower bound of `minSize` (the leaf index of the
// duplicate + 1). This is called from the duplicate-append path where
// we need to tell the caller the tree size their receipt should be
// fetched against.
func (s *LogService) currentTreeSize(ctx context.Context, minSize uint64) uint64 {
	rec, err := s.checkpoints.Latest(ctx)
	if err == nil && rec != nil && rec.TreeSize >= minSize+1 {
		return rec.TreeSize
	}
	return minSize + 1
}

// awaitAndStoreCheckpoint blocks on the Tessera PublicationAwaiter
// until a checkpoint covering this leaf has been signed and written,
// then persists it into the tl_checkpoints mirror. Mirrors the
// reference TL's `AwaitPublication` flow.
//
// Uses the service's shutdown ctx (not the request ctx) so a
// short-lived client request doesn't cancel the publication wait,
// but shutdown still drains the goroutine cleanly.
func (s *LogService) awaitAndStoreCheckpoint(future tessera.IndexFuture) {
	if future == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.shutdownCtx, 60*time.Second)
	defer cancel()
	_, cpBytes, err := s.log.Awaiter().Await(ctx, future)
	if err != nil || len(cpBytes) == 0 {
		return
	}
	size, rootHex, err := parseCheckpointHeader(cpBytes)
	if err != nil {
		return
	}
	rootHash, err := hex.DecodeString(rootHex)
	if err != nil {
		return
	}
	_ = s.checkpoints.Store(ctx, size, rootHash, cpBytes, s.log.Origin())
}

// Close cancels the shutdown ctx and waits for all in-flight
// per-append awaiter goroutines to drain. Call during TL shutdown
// so outstanding checkpoint-persist goroutines finish (or abort
// gracefully) before the SQLite handle is closed.
func (s *LogService) Close() {
	if s.shutdownCancel != nil {
		s.shutdownCancel()
	}
	s.wg.Wait()
}

func readCheckpointFile(dataDir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dataDir, "checkpoint"))
}

// parseCheckpointHeader extracts tree_size and hex-root-hash from a
// sumdb note checkpoint. Format (before the blank line + signatures):
//
//	<origin>
//	<size>
//	<root-hash-base64>
//	<optional extra lines>
//
// The returned root hash is hex-encoded for DB parity with the reference.
func parseCheckpointHeader(note []byte) (uint64, string, error) {
	lines := strings.Split(string(note), "\n")
	if len(lines) < 3 {
		return 0, "", errors.New("log: checkpoint too short")
	}
	var size uint64
	if _, err := fmt.Sscanf(lines[1], "%d", &size); err != nil {
		return 0, "", fmt.Errorf("log: parse tree size: %w", err)
	}
	rawRoot, err := decodeCheckpointRoot(lines[2])
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(rawRoot), nil
}

func decodeCheckpointRoot(s string) ([]byte, error) {
	// Tessera checkpoints use standard (non-URL) base64 per RFC 6962.
	return decodeB64("std", s)
}
