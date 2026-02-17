package memory

import (
	"context"
	"log/slog"
	"time"
)

// Scheduler periodically recalculates decay scores and expires stale memories.
type Scheduler struct {
	store    *Store
	interval time.Duration
	logger   *slog.Logger
}

// NewScheduler creates a decay scheduler with the default interval.
func NewScheduler(store *Store, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		store:    store,
		interval: DecayInterval,
		logger:   logger,
	}
}

// Run blocks until ctx is canceled. Runs UpdateDecayScores() and DeleteStale()
// on each tick. Callers must track the goroutine with a WaitGroup.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce executes a single decay + expiry cycle.
func (s *Scheduler) runOnce(ctx context.Context) {
	if n, err := s.store.UpdateDecayScores(ctx); err != nil {
		s.logger.Warn("decay update failed", "error", err)
	} else if n > 0 {
		s.logger.Debug("decay scores updated", "count", n)
	}

	if n, err := s.store.DeleteStale(ctx); err != nil {
		s.logger.Warn("stale expiry failed", "error", err)
	} else if n > 0 {
		s.logger.Info("expired stale memories", "count", n)
	}
}
