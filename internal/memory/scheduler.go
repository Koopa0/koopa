package memory

import (
	"context"
	"log/slog"
	"time"
)

// SessionCleaner is an interface for deleting old sessions.
// Implemented by session.Store. Defined here to avoid a circular import.
type SessionCleaner interface {
	DeleteOldSessions(ctx context.Context, cutoff time.Time) (int, error)
}

// Scheduler periodically recalculates decay scores and expires stale memories.
type Scheduler struct {
	store          *Store
	interval       time.Duration
	logger         *slog.Logger
	retentionDays  int
	sessionCleaner SessionCleaner
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

// SetRetention configures data retention cleanup.
// retentionDays <= 0 disables retention cleanup.
func (s *Scheduler) SetRetention(retentionDays int, cleaner SessionCleaner) {
	s.retentionDays = retentionDays
	s.sessionCleaner = cleaner
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

// runOnce executes a single decay + expiry + retention cycle.
func (s *Scheduler) runOnce(ctx context.Context) {
	if n, err := s.store.UpdateDecayScores(ctx); err != nil {
		s.logger.Warn("decay update failed", "error", err)
	} else if n > 0 {
		s.logger.Debug("decay scores updated", "count", n)
	}

	if n, err := s.store.DeleteStale(ctx); err != nil {
		s.logger.Warn("stale expiry failed", "error", err)
	} else if n > 0 {
		s.logger.Debug("expired stale memories", "count", n)
	}

	// Retention cleanup: hard-delete inactive memories and old sessions.
	if s.retentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -s.retentionDays)

		if n, err := s.store.HardDeleteInactive(ctx, cutoff); err != nil {
			s.logger.Warn("memory retention cleanup failed", "error", err)
		} else if n > 0 {
			s.logger.Debug("hard-deleted inactive memories", "count", n)
		}

		if s.sessionCleaner != nil {
			if n, err := s.sessionCleaner.DeleteOldSessions(ctx, cutoff); err != nil {
				s.logger.Warn("session retention cleanup failed", "error", err)
			} else if n > 0 {
				s.logger.Debug("deleted old sessions", "count", n)
			}
		}
	}
}
