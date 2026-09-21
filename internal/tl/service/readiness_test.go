package service

import (
	"context"
	"errors"
	"golang.org/x/sync/semaphore"
	"testing"
	"time"
)

func TestReadinessRejectsUnrecoveredIndex(t *testing.T) {
	s := &LogService{writerGate: make(chan struct{}, 1), indexGate: semaphore.NewWeighted(indexLockWeight)}
	if err := s.Ready(t.Context()); err == nil {
		t.Fatal("unrecovered index reported ready")
	}
}

func TestReadinessHonorsCancellationWhileWriterHoldsGate(t *testing.T) {
	s := &LogService{writerGate: make(chan struct{}, 1), indexGate: semaphore.NewWeighted(indexLockWeight), indexReady: true}
	if err := s.indexGate.Acquire(t.Context(), indexLockWeight); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Ready(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("busy writer did not honor cancellation: %v", err)
	}
}

func TestHealthyIndexedReadersCanOverlap(t *testing.T) {
	s := &LogService{writerGate: make(chan struct{}, 1), indexGate: semaphore.NewWeighted(indexLockWeight), indexReady: true}
	first, err := s.lockIndexedRead(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	second, err := s.lockIndexedRead(ctx)
	if err != nil {
		t.Fatalf("healthy readers serialized: %v", err)
	}
	second()
}
