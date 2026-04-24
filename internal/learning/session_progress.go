package learning

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionProgressAggregate is the store-level DTO for in-session aggregate
// state. Consumed by the MCP session_progress handler; assembled from
// three serial queries (stats, concept distribution, category
// distribution). The sad-path LastEndedSession lookup is a separate
// handler-level call, not part of this aggregate.
//
// Per-session rowset is tiny (2-10 attempts, 5-30 observations), so the
// queries do not need errgroup parallelism. Torn reads across the three
// queries are theoretically possible but operationally inert at this
// scale. See session_progress tool description for the read-side
// contract.
type SessionProgressAggregate struct {
	Stats        SessionProgressStats
	ConceptDist  []SessionProgressConceptCount
	CategoryDist []SessionProgressCategoryCount
}

// SessionProgressStats is the scalar aggregate: attempt count, paradigm
// split, duration totals per paradigm.
type SessionProgressStats struct {
	AttemptCount          int64 `json:"attempt_count"`
	ProblemSolvingCount   int64 `json:"problem_solving_count"`
	ImmersiveCount        int64 `json:"immersive_count"`
	ProblemSolvingMinutes int64 `json:"problem_solving_minutes"`
	ImmersiveMinutes      int64 `json:"immersive_minutes"`
}

// SessionProgressConceptCount is one row of the concept-slug distribution.
// Kind is carried as text (not concept_kind enum) because read callers treat
// it as a label; see HERMES W-10 (.agents/hermes-wishes.md) for the kind-
// column-is-dead tracking.
type SessionProgressConceptCount struct {
	Slug             string `json:"slug"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	ObservationCount int64  `json:"count"`
}

// SessionProgressCategoryCount is one row of the observation (signal,
// category) distribution.
type SessionProgressCategoryCount struct {
	SignalType       string `json:"signal_type"`
	Category         string `json:"category"`
	ObservationCount int64  `json:"count"`
}

// SessionProgress returns the in-session aggregate for the given session.
// Uses three serial queries (stats + concept dist + category dist). Each
// query errors propagate as fmt.Errorf(%w) so callers retain errors.Is
// chains for sentinel dispatch.
func (s *Store) SessionProgress(ctx context.Context, sessionID uuid.UUID) (*SessionProgressAggregate, error) {
	stats, err := s.q.SessionProgressStats(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session progress %s stats: %w", sessionID, err)
	}

	conceptRows, err := s.q.SessionProgressConceptDist(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session progress %s concept dist: %w", sessionID, err)
	}
	conceptDist := make([]SessionProgressConceptCount, len(conceptRows))
	for i := range conceptRows {
		r := &conceptRows[i]
		conceptDist[i] = SessionProgressConceptCount{
			Slug:             r.Slug,
			Name:             r.Name,
			Kind:             r.Kind,
			ObservationCount: r.ObservationCount,
		}
	}

	categoryRows, err := s.q.SessionProgressCategoryDist(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session progress %s category dist: %w", sessionID, err)
	}
	categoryDist := make([]SessionProgressCategoryCount, len(categoryRows))
	for i := range categoryRows {
		r := &categoryRows[i]
		categoryDist[i] = SessionProgressCategoryCount{
			SignalType:       r.SignalType,
			Category:         r.Category,
			ObservationCount: r.ObservationCount,
		}
	}

	return &SessionProgressAggregate{
		Stats: SessionProgressStats{
			AttemptCount:          stats.AttemptCount,
			ProblemSolvingCount:   stats.ProblemSolvingCount,
			ImmersiveCount:        stats.ImmersiveCount,
			ProblemSolvingMinutes: stats.ProblemSolvingMinutes,
			ImmersiveMinutes:      stats.ImmersiveMinutes,
		},
		ConceptDist:  conceptDist,
		CategoryDist: categoryDist,
	}, nil
}

// LastEndedSession returns the most recently ended session. Used by the
// session_progress {active: false} affordance path so the caller can
// pivot to attempt_history(session_id=...) without a second MCP call.
// Returns ErrNotFound when no session has ever been ended (new install).
func (s *Store) LastEndedSession(ctx context.Context) (*Session, error) {
	row, err := s.q.LastEndedSession(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying last ended session: %w", err)
	}
	return rowToSession(&row), nil
}
