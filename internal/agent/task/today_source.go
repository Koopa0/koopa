package task

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/today"
)

// TodayAwaitingSource adapts Store.AwaitingApprovalPaged into a
// today.TaskAwaitingApprovalLister so the admin Today aggregate can fold
// completed-but-unacknowledged tasks into its awaiting-judgment section.
//
// The ack-aware filter lives in the underlying query (backed by
// idx_tasks_awaiting_approval): acknowledged completed tasks are excluded
// server-side, never client-side. Acknowledged completed tasks are the
// completed-history view (CompletedPaged) — they do not belong in the
// "awaiting your judgment" inbox.
//
// This mirrors the content.NewSearchSource → search.Source pattern: the
// producer package adapts its Store onto a consumer-defined interface so
// the today package never imports another feature's *Store.
type TodayAwaitingSource struct {
	store *Store
}

// NewTodayAwaitingSource returns a today.TaskAwaitingApprovalLister backed
// by the given task Store.
func NewTodayAwaitingSource(store *Store) *TodayAwaitingSource {
	return &TodayAwaitingSource{store: store}
}

var _ today.TaskAwaitingApprovalLister = (*TodayAwaitingSource)(nil)

// AwaitingApproval returns up to limit completed + unacknowledged tasks,
// newest completion first, projected onto today.JudgmentTask. Returns an
// empty slice on zero hits so the aggregate's load step has no nil case
// to guard. The page is fixed at 1 — Today shows the top slice only;
// callers wanting the full paged inbox hit the tasks awaiting-approval
// endpoint directly.
func (s *TodayAwaitingSource) AwaitingApproval(ctx context.Context, limit int) ([]today.JudgmentTask, error) {
	if limit <= 0 {
		return []today.JudgmentTask{}, nil
	}
	rows, _, err := s.store.AwaitingApprovalPaged(ctx, 1, limit)
	if err != nil {
		return nil, fmt.Errorf("listing tasks awaiting approval: %w", err)
	}
	out := make([]today.JudgmentTask, len(rows))
	for i := range rows {
		out[i] = today.JudgmentTask{
			ID:          rows[i].ID,
			Title:       rows[i].Title,
			Source:      rows[i].Source,
			Assignee:    rows[i].Target,
			CompletedAt: rows[i].CompletedAt,
		}
	}
	return out, nil
}
