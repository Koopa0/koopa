package learning

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// TimelineSession represents a session with attempt stats for the timeline view.
type TimelineSession struct {
	ID           uuid.UUID  `json:"id"`
	Domain       string     `json:"domain"`
	Mode         string     `json:"mode"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	AttemptCount int64      `json:"attempt_count"`
	SuccessCount int64      `json:"success_count"`
}

// rowToSession converts a db.LearningSession row into a *Session.
func rowToSession(r *db.LearningSession) *Session {
	return &Session{
		ID:              r.ID,
		Domain:          r.Domain,
		Mode:            Mode(r.SessionMode),
		AgentNoteID:     r.AgentNoteID,
		DailyPlanItemID: r.DailyPlanItemID,
		StartedAt:       r.StartedAt,
		EndedAt:         r.EndedAt,
		CreatedAt:       r.CreatedAt,
	}
}

// StartSession creates a new learning session. If a prior session is still
// active but qualifies as a zombie (no activity in >12h), it is auto-ended
// first and returned as zombieEnded so the caller can surface it in the tool
// response — this unblocks fresh sessions after an agent or process exited
// without calling end_session. A fresh (non-zombie) active session still
// produces ErrActiveExists.
func (s *Store) StartSession(ctx context.Context, domain string, mode Mode, dailyPlanItemID *uuid.UUID) (session, zombieEnded *Session, err error) {
	// First, try to reclaim any abandoned session. EndStaleActiveSession
	// returns pgx.ErrNoRows when nothing qualifies, which is the common path
	// (no active session, or active session is still fresh).
	staleRow, err := s.q.EndStaleActiveSession(ctx)
	switch {
	case err == nil:
		zombieEnded = rowToSession(&staleRow)
	case errors.Is(err, pgx.ErrNoRows):
		// no zombie to end — either no active session or it's still fresh
	default:
		return nil, nil, fmt.Errorf("checking for stale session: %w", err)
	}

	// Only NOW check for an active session. If one exists at this point it
	// is fresh (the zombie-end query would have claimed any stale one), so
	// we can safely return nil for zombieEnded — the two are mutually
	// exclusive by construction.
	if _, err := s.q.ActiveSession(ctx); err == nil {
		return nil, nil, ErrActiveExists
	}

	row, err := s.q.CreateSession(ctx, db.CreateSessionParams{
		Domain:          domain,
		SessionMode:     string(mode),
		DailyPlanItemID: dailyPlanItemID,
	})
	if err != nil {
		// uq_learning_sessions_one_active (migration 003) enforces the
		// invariant at the DB level; if a concurrent caller slipped a new
		// session between our ActiveSession check and this INSERT, 23505
		// surfaces here — map to ErrActiveExists so the caller treats it
		// identically to the in-process check above. Preserve zombieEnded
		// so callers can still audit the auto-end that did commit.
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, zombieEnded, ErrActiveExists
		}
		return nil, zombieEnded, fmt.Errorf("creating session: %w", err)
	}
	return rowToSession(&row), zombieEnded, nil
}

// SessionByID returns a single session by ID, or ErrNotFound.
func (s *Store) SessionByID(ctx context.Context, id uuid.UUID) (*Session, error) {
	row, err := s.q.SessionByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying session %s: %w", id, err)
	}
	return rowToSession(&row), nil
}

// ActiveSession returns the currently active session, or ErrNoActive.
func (s *Store) ActiveSession(ctx context.Context) (*Session, error) {
	row, err := s.q.ActiveSession(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoActive
		}
		return nil, fmt.Errorf("querying active session: %w", err)
	}
	return rowToSession(&row), nil
}

// EndSession ends the active session. Optionally links an agent_note entry.
func (s *Store) EndSession(ctx context.Context, sessionID uuid.UUID, agentNoteID *uuid.UUID) (*Session, error) {
	row, err := s.q.EndSession(ctx, db.EndSessionParams{
		ID:          sessionID,
		AgentNoteID: agentNoteID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAlreadyEnded
		}
		return nil, fmt.Errorf("ending session: %w", err)
	}
	return rowToSession(&row), nil
}

// RecentSessions returns recent sessions, optionally filtered by domain.
func (s *Store) RecentSessions(ctx context.Context, domain *string, since time.Time, limit int32) ([]Session, error) {
	rows, err := s.q.RecentSessions(ctx, db.RecentSessionsParams{
		Domain:     domain,
		Since:      since,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying recent sessions: %w", err)
	}
	result := make([]Session, len(rows))
	for i := range rows {
		result[i] = *rowToSession(&rows[i])
	}
	return result, nil
}

// SessionTimeline returns recent sessions with attempt counts for the timeline view.
func (s *Store) SessionTimeline(ctx context.Context, domain *string, since time.Time) ([]TimelineSession, error) {
	rows, err := s.q.SessionTimeline(ctx, db.SessionTimelineParams{
		Domain: domain,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying session timeline: %w", err)
	}
	result := make([]TimelineSession, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = TimelineSession{
			ID:           r.ID,
			Domain:       r.Domain,
			Mode:         r.SessionMode,
			StartedAt:    r.StartedAt,
			EndedAt:      r.EndedAt,
			AttemptCount: r.AttemptCount,
			SuccessCount: r.SuccessCount,
		}
	}
	return result, nil
}

// Streak returns the number of consecutive days with at least one completed session.
func (s *Store) Streak(ctx context.Context) (int, error) {
	n, err := s.q.SessionStreak(ctx)
	if err != nil {
		return 0, fmt.Errorf("computing session streak: %w", err)
	}
	return int(n), nil
}
