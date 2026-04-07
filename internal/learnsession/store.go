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

	if metadata == nil {
		metadata = json.RawMessage("{}")
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

// ConceptMasteryRow represents per-concept mastery with signal counts.
type ConceptMasteryRow struct {
	ID                uuid.UUID `json:"id"`
	Slug              string    `json:"slug"`
	Name              string    `json:"name"`
	Domain            string    `json:"domain"`
	Kind              string    `json:"kind"`
	WeaknessCount     int64     `json:"weakness_count"`
	ImprovementCount  int64     `json:"improvement_count"`
	MasteryCount      int64     `json:"mastery_count"`
	TotalObservations int64     `json:"total_observations"`
}

// ConceptMastery returns per-concept mastery with signal counts.
func (s *Store) ConceptMastery(ctx context.Context, domain *string, since time.Time) ([]ConceptMasteryRow, error) {
	rows, err := s.q.ConceptMastery(ctx, db.ConceptMasteryParams{
		Domain: domain,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying concept mastery: %w", err)
	}
	result := make([]ConceptMasteryRow, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ConceptMasteryRow{
			ID:                r.ID,
			Slug:              r.Slug,
			Name:              r.Name,
			Domain:            r.Domain,
			Kind:              r.Kind,
			WeaknessCount:     r.WeaknessCount,
			ImprovementCount:  r.ImprovementCount,
			MasteryCount:      r.MasteryCount,
			TotalObservations: r.TotalObservations,
		}
	}
	return result, nil
}

// WeaknessRow represents a cross-pattern weakness analysis row.
type WeaknessRow struct {
	ConceptSlug     string `json:"concept_slug"`
	ConceptName     string `json:"concept_name"`
	Domain          string `json:"domain"`
	Category        string `json:"category"`
	OccurrenceCount int64  `json:"occurrence_count"`
	CriticalCount   int64  `json:"critical_count"`
	ModerateCount   int64  `json:"moderate_count"`
	MinorCount      int64  `json:"minor_count"`
}

// WeaknessAnalysis returns cross-pattern weakness analysis.
func (s *Store) WeaknessAnalysis(ctx context.Context, domain *string, since time.Time) ([]WeaknessRow, error) {
	rows, err := s.q.WeaknessAnalysis(ctx, db.WeaknessAnalysisParams{
		Domain: domain,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying weakness analysis: %w", err)
	}
	result := make([]WeaknessRow, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = WeaknessRow{
			ConceptSlug:     r.ConceptSlug,
			ConceptName:     r.ConceptName,
			Domain:          r.Domain,
			Category:        r.Category,
			OccurrenceCount: r.OccurrenceCount,
			CriticalCount:   r.CriticalCount,
			ModerateCount:   r.ModerateCount,
			MinorCount:      r.MinorCount,
		}
	}
	return result, nil
}

// RetrievalItem represents an item due for spaced review.
type RetrievalItem struct {
	CardID     int64     `json:"card_id"`
	Due        time.Time `json:"due"`
	ItemID     uuid.UUID `json:"item_id"`
	Title      string    `json:"title"`
	Domain     string    `json:"domain"`
	Difficulty *string   `json:"difficulty,omitempty"`
	ExternalID *string   `json:"external_id,omitempty"`
}

// RetrievalQueue returns items due for spaced review.
func (s *Store) RetrievalQueue(ctx context.Context, domain *string, dueBefore time.Time, limit int32) ([]RetrievalItem, error) {
	rows, err := s.q.RetrievalQueue(ctx, db.RetrievalQueueParams{
		DueBefore:  dueBefore,
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying retrieval queue: %w", err)
	}
	result := make([]RetrievalItem, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = RetrievalItem{
			CardID:     r.CardID,
			Due:        r.Due,
			ItemID:     r.ItemID,
			Title:      r.Title,
			Domain:     r.Domain,
			Difficulty: r.Difficulty,
			ExternalID: r.ExternalID,
		}
	}
	return result, nil
}

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

// ItemRelation represents a relationship between two learning items.
type ItemRelation struct {
	RelationID   uuid.UUID `json:"relation_id"`
	RelationType string    `json:"relation_type"`
	SourceID     uuid.UUID `json:"source_id"`
	SourceTitle  string    `json:"source_title"`
	SourceDomain string    `json:"source_domain"`
	TargetID     uuid.UUID `json:"target_id"`
	TargetTitle  string    `json:"target_title"`
	TargetDomain string    `json:"target_domain"`
}

// ItemVariations returns the problem relationship graph for learning items.
func (s *Store) ItemVariations(ctx context.Context, domain *string, limit int32) ([]ItemRelation, error) {
	rows, err := s.q.ItemVariations(ctx, db.ItemVariationsParams{
		Domain:     domain,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying item variations: %w", err)
	}
	result := make([]ItemRelation, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = ItemRelation{
			RelationID:   r.RelationID,
			RelationType: r.RelationType,
			SourceID:     r.SourceID,
			SourceTitle:  r.SourceTitle,
			SourceDomain: r.SourceDomain,
			TargetID:     r.TargetID,
			TargetTitle:  r.TargetTitle,
			TargetDomain: r.TargetDomain,
		}
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
