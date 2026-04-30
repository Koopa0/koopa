package learning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
)

// RecordAttempt creates an attempt and returns it. paradigm + outcome must
// satisfy chk_learning_attempts_paradigm_outcome (the joint CHECK in 001) —
// callers typically resolve paradigm via MapOutcome.
func (s *Store) RecordAttempt(ctx context.Context, targetID, sessionID uuid.UUID, paradigm Paradigm, outcome string, durationMin *int32, stuckAt, approachUsed *string, metadata json.RawMessage) (*Attempt, error) {
	// Get next attempt number.
	maxNum, err := s.q.AttemptCountForLearningTarget(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("counting attempts: %w", err)
	}

	if metadata == nil {
		metadata = json.RawMessage("{}")
	}
	row, err := s.q.CreateAttempt(ctx, db.CreateAttemptParams{
		LearningTargetID: targetID,
		SessionID:        sessionID,
		AttemptNumber:    maxNum + 1,
		Paradigm:         string(paradigm),
		Outcome:          outcome,
		DurationMinutes:  durationMin,
		StuckAt:          stuckAt,
		ApproachUsed:     approachUsed,
		Metadata:         metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("creating attempt: %w", err)
	}
	return &Attempt{
		ID:               row.ID,
		LearningTargetID: row.LearningTargetID,
		SessionID:        row.SessionID,
		AttemptNumber:    row.AttemptNumber,
		Paradigm:         Paradigm(row.Paradigm),
		Outcome:          row.Outcome,
		DurationMinutes:  row.DurationMinutes,
		StuckAt:          row.StuckAt,
		ApproachUsed:     row.ApproachUsed,
		AttemptedAt:      row.AttemptedAt,
	}, nil
}

// AttemptByID returns a single attempt with its target binding.
// Returns ErrNotFound when the attempt does not exist. Used by policy
// checks that need to verify a caller-supplied attempt id resolves to a
// specific learning target (e.g. manage_plan.update_entry completion
// target-alignment audit).
func (s *Store) AttemptByID(ctx context.Context, id uuid.UUID) (*Attempt, error) {
	row, err := s.q.AttemptByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying attempt %s: %w", id, err)
	}
	return &Attempt{
		ID:               row.ID,
		LearningTargetID: row.LearningTargetID,
		SessionID:        row.SessionID,
		AttemptNumber:    row.AttemptNumber,
		Paradigm:         Paradigm(row.Paradigm),
		Outcome:          row.Outcome,
		DurationMinutes:  row.DurationMinutes,
		StuckAt:          row.StuckAt,
		ApproachUsed:     row.ApproachUsed,
		AttemptedAt:      row.AttemptedAt,
		Metadata:         row.Metadata,
	}, nil
}

// AttemptsBySession returns all attempts for a session with target details,
// oldest first. Backs the end_session summary and the by_session path of
// attempt_history.
func (s *Store) AttemptsBySession(ctx context.Context, sessionID uuid.UUID) ([]Attempt, error) {
	rows, err := s.q.AttemptsBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("querying attempts for session %s: %w", sessionID, err)
	}
	result := make([]Attempt, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = Attempt{
			ID:               r.ID,
			LearningTargetID: r.LearningTargetID,
			SessionID:        r.SessionID,
			AttemptNumber:    r.AttemptNumber,
			Paradigm:         Paradigm(r.Paradigm),
			Outcome:          r.Outcome,
			DurationMinutes:  r.DurationMinutes,
			StuckAt:          r.StuckAt,
			ApproachUsed:     r.ApproachUsed,
			AttemptedAt:      r.AttemptedAt,
			Metadata:         r.Metadata,
			TargetTitle:      r.TargetTitle,
			TargetExternalID: r.TargetExternalID,
		}
	}
	return result, nil
}

// AttemptsByLearningTarget returns recent attempts on a specific learning
// target, newest first. Primary backing query for the Improvement
// Verification Loop: "how did this target go last time?". Same shape as
// AttemptsBySession.
func (s *Store) AttemptsByLearningTarget(ctx context.Context, targetID uuid.UUID, limit int32) ([]Attempt, error) {
	rows, err := s.q.AttemptsByLearningTarget(ctx, db.AttemptsByLearningTargetParams{
		LearningTargetID: targetID,
		MaxResults:       limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying attempts for target %s: %w", targetID, err)
	}
	result := make([]Attempt, len(rows))
	for i := range rows {
		r := &rows[i]
		result[i] = Attempt{
			ID:               r.ID,
			LearningTargetID: r.LearningTargetID,
			SessionID:        r.SessionID,
			AttemptNumber:    r.AttemptNumber,
			Paradigm:         Paradigm(r.Paradigm),
			Outcome:          r.Outcome,
			DurationMinutes:  r.DurationMinutes,
			StuckAt:          r.StuckAt,
			ApproachUsed:     r.ApproachUsed,
			AttemptedAt:      r.AttemptedAt,
			Metadata:         r.Metadata,
			TargetTitle:      r.TargetTitle,
			TargetExternalID: r.TargetExternalID,
		}
	}
	return result, nil
}

// AttachObservations populates Attempt.Observations for each attempt in
// the slice, preserving the attempt order the caller passed in. Batches
// the fetch via ObservationsByAttemptIDs (one round-trip regardless of
// attempt count) so callers paying for the observation layer get bounded
// cost — attempt_history uses this for the refined-b shape where every
// mode surfaces observations and the concept-mode matched_observation_id
// is a pointer into this list.
//
// Observations within each attempt come in Position ASC, matching the
// coach-insertion order recorded at record_attempt time.
//
// Attempts with zero observations receive an empty (non-nil) slice so
// downstream JSON consumers iterating Observations never hit a nil
// dereference. No-op when attempts is empty.
func (s *Store) AttachObservations(ctx context.Context, attempts []Attempt) error {
	if len(attempts) == 0 {
		return nil
	}

	ids := make([]uuid.UUID, len(attempts))
	for i := range attempts {
		ids[i] = attempts[i].ID
	}

	rows, err := s.q.ObservationsByAttemptIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("fetching observations for %d attempts: %w", len(attempts), err)
	}

	byAttempt := make(map[uuid.UUID][]Observation, len(attempts))
	for i := range rows {
		r := &rows[i]
		byAttempt[r.AttemptID] = append(byAttempt[r.AttemptID], Observation{
			ID:          r.ID,
			AttemptID:   r.AttemptID,
			ConceptID:   r.ConceptID,
			SignalType:  r.SignalType,
			Category:    r.Category,
			Severity:    r.Severity,
			Detail:      r.Detail,
			Confidence:  r.Confidence,
			Position:    r.Position,
			ConceptSlug: r.ConceptSlug,
			ConceptName: r.ConceptName,
		})
	}

	for i := range attempts {
		if obs, ok := byAttempt[attempts[i].ID]; ok {
			attempts[i].Observations = obs
		} else {
			attempts[i].Observations = []Observation{}
		}
	}
	return nil
}
