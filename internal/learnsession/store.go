package learnsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for learning sessions, attempts, and observations.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// StartSession creates a new learning session. Fails if an active session exists.
func (s *Store) StartSession(ctx context.Context, domain string, mode Mode, dailyPlanItemID *uuid.UUID) (*Session, error) {
	// Check for active session.
	if _, err := s.q.ActiveSession(ctx); err == nil {
		return nil, ErrActiveExists
	}

	row, err := s.q.CreateSession(ctx, db.CreateSessionParams{
		Domain:          domain,
		SessionMode:     string(mode),
		DailyPlanItemID: dailyPlanItemID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
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

// EndSession ends the active session. Optionally links a journal entry.
func (s *Store) EndSession(ctx context.Context, sessionID uuid.UUID, journalID *int64) (*Session, error) {
	row, err := s.q.EndSession(ctx, db.EndSessionParams{
		ID:        sessionID,
		JournalID: journalID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAlreadyEnded
		}
		return nil, fmt.Errorf("ending session: %w", err)
	}
	return rowToSession(&row), nil
}

// FindOrCreateItem upserts a learning item by domain + external_id (or title).
func (s *Store) FindOrCreateItem(ctx context.Context, domain, title string, externalID, difficulty *string) (uuid.UUID, error) {
	row, err := s.q.FindOrCreateItem(ctx, db.FindOrCreateItemParams{
		Domain:     domain,
		Title:      title,
		ExternalID: externalID,
		Difficulty: difficulty,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("finding/creating learning item: %w", err)
	}
	return row.ID, nil
}

// RecordAttempt creates an attempt and returns it.
func (s *Store) RecordAttempt(ctx context.Context, itemID, sessionID uuid.UUID, outcome string, durationMin *int32, stuckAt, approachUsed *string, metadata json.RawMessage) (*Attempt, error) {
	// Get next attempt number.
	maxNum, err := s.q.AttemptCountForItem(ctx, itemID)
	if err != nil {
		return nil, fmt.Errorf("counting attempts: %w", err)
	}

	row, err := s.q.CreateAttempt(ctx, db.CreateAttemptParams{
		LearningItemID:  itemID,
		SessionID:       &sessionID,
		AttemptNumber:   maxNum + 1,
		Outcome:         outcome,
		DurationMinutes: durationMin,
		StuckAt:         stuckAt,
		ApproachUsed:    approachUsed,
		Metadata:        metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("creating attempt: %w", err)
	}
	return &Attempt{
		ID:              row.ID,
		ItemID:          row.LearningItemID,
		SessionID:       row.SessionID,
		AttemptNumber:   row.AttemptNumber,
		Outcome:         row.Outcome,
		DurationMinutes: row.DurationMinutes,
		StuckAt:         row.StuckAt,
		ApproachUsed:    row.ApproachUsed,
		AttemptedAt:     row.AttemptedAt,
	}, nil
}

// RecordObservation creates an observation linking an attempt to a concept.
func (s *Store) RecordObservation(ctx context.Context, attemptID, conceptID uuid.UUID, signalType, category string, severity, detail *string) (*Observation, error) {
	row, err := s.q.CreateObservation(ctx, db.CreateObservationParams{
		AttemptID:  attemptID,
		ConceptID:  conceptID,
		SignalType: signalType,
		Category:   category,
		Severity:   severity,
		Detail:     detail,
	})
	if err != nil {
		return nil, fmt.Errorf("creating observation: %w", err)
	}
	return &Observation{
		ID:         row.ID,
		AttemptID:  row.AttemptID,
		ConceptID:  row.ConceptID,
		SignalType: row.SignalType,
		Category:   row.Category,
		Severity:   row.Severity,
		Detail:     row.Detail,
	}, nil
}

// FindOrCreateConcept upserts a concept by domain + slug.
func (s *Store) FindOrCreateConcept(ctx context.Context, slug, name, domain, kind string) (uuid.UUID, error) {
	row, err := s.q.FindOrCreateConcept(ctx, db.FindOrCreateConceptParams{
		Slug:   slug,
		Name:   name,
		Domain: domain,
		Kind:   kind,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("finding/creating concept: %w", err)
	}
	return row.ID, nil
}

// AttemptsBySession returns all attempts for a session with item details.
func (s *Store) AttemptsBySession(ctx context.Context, sessionID uuid.UUID) ([]Attempt, error) {
	rows, err := s.q.AttemptsBySession(ctx, &sessionID)
	if err != nil {
		return nil, fmt.Errorf("querying attempts for session %s: %w", sessionID, err)
	}
	result := make([]Attempt, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = Attempt{
			ID:              r.ID,
			ItemID:          r.LearningItemID,
			SessionID:       r.SessionID,
			AttemptNumber:   r.AttemptNumber,
			Outcome:         r.Outcome,
			DurationMinutes: r.DurationMinutes,
			StuckAt:         r.StuckAt,
			ApproachUsed:    r.ApproachUsed,
			AttemptedAt:     r.AttemptedAt,
			ItemTitle:       r.ItemTitle,
			ItemExternalID:  r.ItemExternalID,
		}
	}
	return result, nil
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

func rowToSession(r *db.LearningSession) *Session {
	return &Session{
		ID:              r.ID,
		Domain:          r.Domain,
		Mode:            Mode(r.SessionMode),
		JournalID:       r.JournalID,
		DailyPlanItemID: r.DailyPlanItemID,
		StartedAt:       r.StartedAt,
		EndedAt:         r.EndedAt,
		CreatedAt:       r.CreatedAt,
	}
}
