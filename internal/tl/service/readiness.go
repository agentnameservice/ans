package service

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Ready checks the serving invariant without repairing it as a probe side effect.
// A busy or stalled writer cannot leave readiness permanently reporting success.
func (s *LogService) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.indexGate.Acquire(ctx, 1); err != nil {
		return err
	}
	defer s.indexGate.Release(1)
	if !s.indexReady {
		return errors.New("event index requires recovery")
	}
	integrated, err := s.log.Reader().IntegratedSize(ctx)
	if err != nil {
		return fmt.Errorf("read integrated log size: %w", err)
	}
	indexed, err := s.events.IndexedSize(ctx)
	if err != nil {
		return fmt.Errorf("read index size: %w", err)
	}
	if indexed != integrated {
		return fmt.Errorf("event index size %d differs from integrated log %d", indexed, integrated)
	}
	return nil
}
