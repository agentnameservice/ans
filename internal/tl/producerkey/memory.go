package producerkey

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// MemoryStore is an in-process Store backed by a map. Safe for
// concurrent reads after construction; writes via Add/Revoke take the
// mutex.
//
// Used by the Stage-1 zero-config path: the TL config names a list of
// trusted producer PEMs, they're loaded at startup, and this store
// serves them. The SQLite-backed Store in Stage 3 replaces this for
// runtime rotation without changing any caller.
type MemoryStore struct {
	mu      sync.RWMutex
	byIndex map[indexKey]string // (raID, keyID) → PEM
}

type indexKey struct {
	raID  string
	keyID string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byIndex: make(map[indexKey]string)}
}

// NewMemoryStoreFromEntries returns a MemoryStore pre-populated with
// the given entries. Duplicate (raID, keyID) pairs return an error.
func NewMemoryStoreFromEntries(entries []Entry) (*MemoryStore, error) {
	s := NewMemoryStore()
	for _, e := range entries {
		if err := s.Add(e); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Add registers a producer key. Returns an error if (raID, keyID)
// already exists; callers must Revoke the old key first to rotate.
func (s *MemoryStore) Add(e Entry) error {
	if e.RaID == "" {
		return errors.New("producerkey: raID required")
	}
	if e.KeyID == "" {
		return errors.New("producerkey: keyID required")
	}
	if e.PublicKeyPEM == "" {
		return errors.New("producerkey: publicKeyPEM required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := indexKey{raID: e.RaID, keyID: e.KeyID}
	if _, ok := s.byIndex[k]; ok {
		return fmt.Errorf("producerkey: duplicate (raID=%s, keyID=%s)", e.RaID, e.KeyID)
	}
	s.byIndex[k] = e.PublicKeyPEM
	return nil
}

// Revoke removes a producer key. Subsequent Get calls return ErrNotFound.
func (s *MemoryStore) Revoke(raID, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := indexKey{raID: raID, keyID: keyID}
	if _, ok := s.byIndex[k]; !ok {
		return ErrNotFound
	}
	delete(s.byIndex, k)
	return nil
}

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, raID, keyID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pem, ok := s.byIndex[indexKey{raID: raID, keyID: keyID}]
	if !ok {
		return "", ErrNotFound
	}
	return pem, nil
}
