package activity

import (
	"context"
	"fmt"
	"time"

	"github.com/Koopa0/koopa/internal/db"
)

// SkipReasonPrefix is one bucket of the weekly skip-reason histogram —
// the soft prefix of activity_events.payload->>'reason' for
// learning_plan_entry rows that transitioned to status='skipped' in the
// window. The prefix is the substring before the first ':' in the
// reason text; entries with empty / NULL / colon-less reasons resolve
// to "unclassified" inside the SQL (so the histogram is always a
// closed set the caller doesn't need to special-case).
type SkipReasonPrefix struct {
	Prefix string `json:"prefix"`
	Count  int64  `json:"count"`
}

// LearningPlanForceCount returns the number of force-mode plan-entry
// completions in [start, end). A force completion is structurally
// distinguishable in activity_events by the 'manual override:' prefix
// the validateCompleteEntryReason helper requires (internal/mcp/plan.go);
// the audit_learning_plan_entries trigger writes that reason into
// payload.reason, so a single LIKE filter is sufficient. Used by
// weekly_summary.self_audit.
func (s *Store) LearningPlanForceCount(ctx context.Context, start, end time.Time) (int64, error) {
	count, err := s.q.SelfAuditLearningPlanForceCount(ctx, db.SelfAuditLearningPlanForceCountParams{
		StartAt: start,
		EndAt:   end,
	})
	if err != nil {
		return 0, fmt.Errorf("querying learning plan force count: %w", err)
	}
	return count, nil
}

// LearningPlanSkippedHistogram returns the skip-reason prefix
// histogram for learning_plan_entry status='skipped' transitions in
// [start, end), sorted descending by count then ascending by prefix
// for deterministic ties. Empty slice (NOT nil) when no rows match,
// per the json-api rule. The sum of all counts is the
// skipped_count metric.
func (s *Store) LearningPlanSkippedHistogram(ctx context.Context, start, end time.Time) ([]SkipReasonPrefix, error) {
	rows, err := s.q.SelfAuditLearningPlanSkippedHistogram(ctx, db.SelfAuditLearningPlanSkippedHistogramParams{
		StartAt: start,
		EndAt:   end,
	})
	if err != nil {
		return nil, fmt.Errorf("querying learning plan skipped histogram: %w", err)
	}
	out := make([]SkipReasonPrefix, len(rows))
	for i := range rows {
		out[i] = SkipReasonPrefix{
			Prefix: rows[i].Prefix,
			Count:  rows[i].Count,
		}
	}
	return out, nil
}
