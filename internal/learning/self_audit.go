// Copyright 2026 Koopa. All rights reserved.

package learning

import (
	"context"
	"fmt"
	"time"

	"github.com/Koopa0/koopa/internal/db"
)

// OutcomeRate carries the solved_after_solution numerator and the
// problem_solving denominator for a weekly window. The split surfaces
// both raw counts so the caller can render the rate AND the magnitude
// (rate 0.5 means very different things at 2 attempts vs 200).
type OutcomeRate struct {
	SolvedAfterSolutionCount   int64 `json:"solved_after_solution_count"`
	ProblemSolvingAttemptCount int64 `json:"problem_solving_attempt_count"`
}

// RepeatedConcept is one row of the same-concept-repeated-within-week
// metric: a concept that appeared in attempt_count >= threshold
// distinct attempts during the window. Counting unit is distinct
// attempts (NOT observations) — see query.sql for rationale.
type RepeatedConcept struct {
	Concept string `json:"concept"`
	Count   int64  `json:"count"`
}

// SelfAuditOutcomeRate returns solved_after_solution count + total
// problem_solving attempt count for [start, end). Used by
// weekly_summary.self_audit to surface the CF-06 fix's behavioral
// signal — if the rate stays flat across weeks the playbook adoption
// is sticking; if it spikes, learning-studio's outcome discipline is
// drifting.
func (s *Store) SelfAuditOutcomeRate(ctx context.Context, start, end time.Time) (OutcomeRate, error) {
	row, err := s.q.SelfAuditAttemptOutcomeRate(ctx, db.SelfAuditAttemptOutcomeRateParams{
		StartAt: start,
		EndAt:   end,
	})
	if err != nil {
		return OutcomeRate{}, fmt.Errorf("querying self_audit attempt outcome rate: %w", err)
	}
	return OutcomeRate{
		SolvedAfterSolutionCount:   row.SolvedAfterSolutionCount,
		ProblemSolvingAttemptCount: row.ProblemSolvingAttemptCount,
	}, nil
}

// SelfAuditRepeatedConcepts returns concepts touched by >= minCount
// distinct attempts in [start, end). minCount is caller-supplied so
// the threshold can be tuned without a query change — the canonical
// default is captured in weekly_summary's
// selfAuditConceptRepetitionThreshold constant. Empty slice (NOT nil)
// when no rows match.
func (s *Store) SelfAuditRepeatedConcepts(ctx context.Context, start, end time.Time, minCount int) ([]RepeatedConcept, error) {
	rows, err := s.q.SelfAuditRepeatedConcepts(ctx, db.SelfAuditRepeatedConceptsParams{
		StartAt:  start,
		EndAt:    end,
		MinCount: int64(minCount),
	})
	if err != nil {
		return nil, fmt.Errorf("querying self_audit repeated concepts: %w", err)
	}
	out := make([]RepeatedConcept, len(rows))
	for i := range rows {
		out[i] = RepeatedConcept{
			Concept: rows[i].ConceptSlug,
			Count:   rows[i].AttemptCount,
		}
	}
	return out, nil
}
