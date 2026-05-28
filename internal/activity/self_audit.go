package activity

import (
	"context"
	"fmt"
	"time"

	"github.com/Koopa0/koopa/internal/db"
)

// SkipReasonPrefix is one bucket of the weekly skip-reason histogram.
// Sources from activity_events.payload->>'reason' for learning_plan_entry
// rows that transitioned to status='skipped' in the window.
//
// Bucketing convention (locked by the SQL — see
// SelfAuditLearningPlanSkippedHistogram in query.sql):
//
//   - Reason starting with the literal 'skipped:' → Prefix is the
//     trimmed text AFTER 'skipped:'. Example:
//     'skipped: solved offline' → 'solved offline'.
//   - Reason that does not start with 'skipped:' → 'unclassified'.
//   - Reason that is empty / NULL / whitespace-only after 'skipped:' →
//     'unclassified'.
//
// The 'skipped:' soft convention is documented in the learning-studio
// audit decisions memo §F.1.d as a coaching hint, not a server-enforced
// rule — CF-04 only mandates non-blank reason text, not a specific
// prefix. The histogram therefore reports BOTH the in-convention
// categories AND the share of non-conforming reasons (as the
// 'unclassified' bucket).
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
