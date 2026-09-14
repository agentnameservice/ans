package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"

	sqlitetl "github.com/agentnameservice/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/event"
	identityevent "github.com/agentnameservice/ans/internal/tl/event/identity"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
)

// RecoverIndex restores committed leaves before the executable serves reads or
// accepts writes. Append also runs recovery after any uncertain write failure.
func (s *LogService) RecoverIndex(ctx context.Context) error {
	select {
	case s.ingestGate <- struct{}{}:
		defer func() { <-s.ingestGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	s.indexReady = false
	if err := s.recoverIndex(ctx); err != nil {
		return err
	}
	s.indexReady = true
	return nil
}

// lockIndexedRead linearizes current-state reads with append/index writes.
// After a failed mirror write, a healthy SQLite read must not mint an ACTIVE
// token from an older row while a revocation is already committed in Tessera.
func (s *LogService) lockIndexedRead(ctx context.Context) (func(), error) {
	select {
	case s.ingestGate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	unlock := func() { <-s.ingestGate }
	if !s.indexReady {
		if err := s.recoverIndex(ctx); err != nil {
			unlock()
			return nil, fmt.Errorf("log: recover event index before read: %w", err)
		}
		s.indexReady = true
	}
	return unlock, nil
}

func (s *LogService) duplicateResult(ctx context.Context, rec *sqlitetl.EventRecord) (*AppendResult, error) {
	hash, err := rec.LeafHashBytes()
	if err != nil {
		return nil, err
	}
	return &AppendResult{
		LogID: rec.LogID, LeafIndex: rec.LeafIndex, LeafHash: hash,
		Duplicate: true, TreeSize: s.currentTreeSize(ctx, rec.LeafIndex),
	}, nil
}

// checkAgentState checks the database before any append. An unchanged state
// retried with fresh timestamps maps to its original leaf. Renewal is repeatable
// when its certificate/attestation state changes; a UNIQUE(FQDN,version,status)
// constraint would incorrectly suppress every renewal after the first.
//
//nolint:nilnil // A nil record and nil error mean the new state is eligible for append.
func (s *LogService) checkAgentState(ctx context.Context, env event.Signable, canonical []byte) (*sqlitetl.EventRecord, error) {
	if _, ok := env.(*identityevent.Envelope); ok {
		return nil, nil
	}
	name, err := domain.ParseAnsName(env.AnsName())
	if err != nil || name.String() != env.AnsName() ||
		name.FQDN() != strings.TrimSuffix(strings.ToLower(env.AgentFQDN()), ".") {
		return nil, domain.NewValidationError("INVALID_EVENT", "agent host must match the canonical versioned ANS name")
	}
	var incoming struct {
		RaID  string `json:"raId"`
		Agent struct {
			Version string `json:"version"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(canonical, &incoming); err != nil {
		return nil, err
	}
	if incoming.Agent.Version != name.Version().String() {
		return nil, domain.NewValidationError("INVALID_EVENT", "agent version must match the versioned ANS name")
	}
	rec, err := s.events.LatestAgentState(ctx, env.AnsName(), env.AgentID())
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rec.AnsName != env.AnsName() || rec.AgentID != env.AgentID() || rec.AgentFQDN != env.AgentFQDN() {
		return nil, domain.NewValidationError("AGENT_STATE_CONFLICT", "versioned FQDN is already bound to a different agent")
	}
	previous, err := innerEventBytes([]byte(rec.RawEvent))
	if err != nil {
		return nil, err
	}
	oldState, err := eventStateBytes(previous)
	if err != nil {
		return nil, err
	}
	newState, err := eventStateBytes(canonical)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(oldState, newState) {
		return rec, nil
	}
	var prior struct {
		RaID      string `json:"raId"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(previous, &prior); err != nil {
		return nil, err
	}
	if incoming.RaID != prior.RaID {
		return nil, domain.NewValidationError("AGENT_STATE_CONFLICT", "agent lifecycle belongs to a different producer")
	}
	if rec.EventType == string(event.TypeAgentRevoked) ||
		env.EventType() == string(event.TypeAgentRegistered) ||
		(rec.EventType == env.EventType() && env.EventType() != string(event.TypeAgentRenewed)) ||
		(rec.EventType == string(event.TypeAgentDeprecated) && env.EventType() != string(event.TypeAgentRevoked)) {
		return nil, domain.NewValidationError("AGENT_STATE_CONFLICT", "event duplicates or reverses an existing lifecycle state")
	}
	oldTime, oldErr := time.Parse(time.RFC3339, prior.Timestamp)
	newTime, newErr := time.Parse(time.RFC3339, env.Timestamp())
	if oldErr != nil || newErr != nil {
		return nil, domain.NewValidationError("INVALID_EVENT", "event timestamp is invalid")
	}
	if newTime.Before(oldTime) {
		return nil, domain.NewValidationError("STALE_AGENT_EVENT", "event predates the current agent state")
	}
	return nil, nil
}

func eventStateBytes(raw []byte) ([]byte, error) {
	var state map[string]json.RawMessage
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	delete(state, "timestamp")
	delete(state, "issuedAt")
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	return anscrypto.Canonicalize(raw)
}

func innerEventBytes(raw []byte) ([]byte, error) {
	var wrapper struct {
		Payload struct {
			Producer struct {
				Event json.RawMessage `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, err
	}
	return anscrypto.Canonicalize(wrapper.Payload.Producer.Event)
}

// recoverIndex repairs committed Tessera leaves missing from SQLite before
// accepting more writes. It includes unpublished but integrated leaves, so a
// restart or failed mirror INSERT cannot turn a retry into another append.
// It never regenerates a log ID, timestamp, signature, or canonical leaf.
func (s *LogService) recoverIndex(ctx context.Context) error {
	next, err := s.events.FirstUnindexedLeaf(ctx)
	if err != nil {
		return err
	}
	reader := s.log.Reader()
	size, err := reader.IntegratedSize(ctx)
	if err != nil {
		return err
	}
	indexedSize, err := s.events.IndexedSize(ctx)
	if err != nil {
		return err
	}
	if indexedSize > size {
		return fmt.Errorf("index extends beyond the integrated log: index=%d log=%d", indexedSize, size)
	}
	for next < size {
		bundle, err := client.GetEntryBundle(ctx, reader.ReadEntryBundle, next/layout.EntryBundleWidth, size)
		if err != nil {
			return err
		}
		offset := next % layout.EntryBundleWidth
		if offset >= uint64(len(bundle.Entries)) {
			return fmt.Errorf("entry bundle does not contain leaf %d", next)
		}
		count := min(uint64(len(bundle.Entries))-offset, size-next)
		hashes, err := client.FetchLeafHashes(ctx, reader.ReadTile, next, count, size)
		if err != nil {
			return err
		}
		hashOffset := uint64(0)
		for offset < uint64(len(bundle.Entries)) && next < size {
			if err := s.restoreIndexedLeaf(ctx, next, bundle.Entries[offset], hashes[hashOffset]); err != nil {
				return fmt.Errorf("restore leaf %d: %w", next, err)
			}
			next++
			offset++
			hashOffset++
		}
	}
	return nil
}

func (s *LogService) restoreIndexedLeaf(ctx context.Context, index uint64, raw, tileHash []byte) error {
	hash := sha256.Sum256(append([]byte{0}, raw...))
	if !bytes.Equal(hash[:], tileHash) {
		return errors.New("entry bytes disagree with the Merkle tile")
	}
	if existing, err := s.events.GetEventByLeafIndex(ctx, index); err == nil {
		if existing.RawEvent != string(raw) {
			return errors.New("indexed bytes disagree with Tessera")
		}
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	env, err := decodeStoredEnvelope(raw)
	if err != nil {
		return err
	}
	canonical, err := env.LeafBytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return errors.New("stored leaf is not canonical")
	}
	inner, err := innerEventBytes(raw)
	if err != nil {
		return err
	}
	_, err = s.events.StoreEvent(ctx, index, hash, sqlitetl.ComputeEventHash(inner), env, raw)
	return err
}

func decodeStoredEnvelope(raw []byte) (event.Signable, error) {
	var header struct {
		SchemaVersion string `json:"schemaVersion"`
		Payload       struct {
			Producer struct {
				Event struct {
					EventType string `json:"eventType"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	var env event.Signable
	switch {
	case strings.HasPrefix(header.Payload.Producer.Event.EventType, "IDENTITY_"):
		env = &identityevent.Envelope{}
	case header.SchemaVersion == event.SchemaVersion:
		env = &event.Envelope{}
	case header.SchemaVersion == eventv1.SchemaVersion:
		env = &eventv1.Envelope{}
	default:
		return nil, fmt.Errorf("unsupported stored schema %q", header.SchemaVersion)
	}
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, err
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return env, nil
}
