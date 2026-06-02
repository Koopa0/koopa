// Copyright 2026 Koopa. All rights reserved.

package today

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/daily"
)

// fakePlanItems satisfies PlanItemReader, the one required reader. It
// returns no items so the test isolates the awaiting-judgment section.
type fakePlanItems struct{}

func (fakePlanItems) ItemsByDate(context.Context, time.Time) ([]daily.Item, error) {
	return nil, nil
}

// fakeAwaiting satisfies TaskAwaitingApprovalLister with a canned slice so
// the test controls exactly what the aggregate folds in.
type fakeAwaiting struct {
	tasks []JudgmentTask
}

func (f fakeAwaiting) AwaitingApproval(context.Context, int) ([]JudgmentTask, error) {
	return f.tasks, nil
}

// TestToday_AwaitingTasksWiredOthersNil proves the backend Today aggregate
// populates awaiting_judgment.completed_tasks_awaiting_approval from the
// wired task source, while the other two awaiting-judgment sections stay
// empty because their readers are nil — exactly the wiring shape main.go
// installs (only the awaiting-task source is wired in this slice).
func TestToday_AwaitingTasksWiredOthersNil(t *testing.T) {
	t.Parallel()

	completedAt := time.Date(2026, 5, 28, 9, 0, 0, 0, time.UTC)
	want := []JudgmentTask{
		{
			ID:          uuid.New(),
			Title:       "research pgvector indexing",
			Source:      "hq",
			Assignee:    "research-lab",
			CompletedAt: &completedAt,
		},
	}

	h := NewHandler(fakePlanItems{}, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithSources(
			nil, // contentQueue — parked, must stay empty
			nil, // hypotheses — parked, must stay empty
			fakeAwaiting{tasks: want},
			nil, // plannings
			nil, // dueReviews
			nil, // feeds
			nil, // staleGoals
		)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/today", http.NoBody)
	rec := httptest.NewRecorder()
	h.Today(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data Response `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	got := body.Data.AwaitingJudgment.CompletedTasksAwaitingApproval
	// EquateApproxTime(0) compares CompletedAt by instant, tolerating the
	// monotonic-clock strip and UTC re-parse that the JSON round-trip
	// applies to time.Time.
	if diff := cmp.Diff(want, got, cmpopts.EquateApproxTime(0)); diff != "" {
		t.Errorf("completed_tasks_awaiting_approval mismatch (-want +got):\n%s", diff)
	}

	// The unwired sections must remain empty — proving nil readers do not
	// fabricate rows and that only the task source contributed.
	if n := len(body.Data.AwaitingJudgment.ContentReview); n != 0 {
		t.Errorf("content_review len = %d, want 0 (reader is nil)", n)
	}
	if n := len(body.Data.AwaitingJudgment.UnverifiedHypotheses); n != 0 {
		t.Errorf("unverified_hypotheses len = %d, want 0 (reader is nil)", n)
	}
}
