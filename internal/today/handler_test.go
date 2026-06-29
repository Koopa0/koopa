// Copyright 2026 Koopa. All rights reserved.

package today

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/todo"
)

// --- fakes ---

// fakePlanItems satisfies PlanItemReader, the one required reader.
type fakePlanItems struct {
	items []daily.Item
}

func (f fakePlanItems) ItemsByDate(context.Context, time.Time) ([]daily.Item, error) {
	return f.items, nil
}

// fakeTodos satisfies TodoReader with canned slices per view.
type fakeTodos struct {
	overdue    []todo.PendingDetail
	dueOn      []todo.PendingDetail
	inRange    []todo.PendingDetail
	inProgress []todo.PendingDetail
	recurring  []todo.Item
}

func (f *fakeTodos) OverdueItems(context.Context, time.Time) ([]todo.PendingDetail, error) {
	return f.overdue, nil
}

func (f *fakeTodos) ItemsDueOn(context.Context, time.Time) ([]todo.PendingDetail, error) {
	return f.dueOn, nil
}

func (f *fakeTodos) ItemsDueInRange(context.Context, time.Time, time.Time) ([]todo.PendingDetail, error) {
	return f.inRange, nil
}

func (f *fakeTodos) InProgressItems(context.Context) ([]todo.PendingDetail, error) {
	return f.inProgress, nil
}

func (f *fakeTodos) RecurringItemsDueToday(context.Context, time.Time) ([]todo.Item, error) {
	return f.recurring, nil
}

// fakeGoals satisfies ActiveGoalReader.
type fakeGoals struct {
	goals []goal.ActiveGoalSummary
}

func (f fakeGoals) ActiveGoals(context.Context) ([]goal.ActiveGoalSummary, error) {
	return f.goals, nil
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	return NewHandler(fakePlanItems{}, time.UTC, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func decodeResponse(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body struct {
		Data Response `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body.Data
}

func doToday(t *testing.T, h *Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/today", http.NoBody)
	rec := httptest.NewRecorder()
	h.Today(rec, req)
	return rec
}

// TestToday_EmptyStateReturnsEmptyArrays proves every list section marshals
// as [] (never null) when no reader is wired — the json-api.md "lists return
// [], never null" contract.
func TestToday_EmptyStateReturnsEmptyArrays(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t).WithSources(nil, nil, nil)
	rec := doToday(t, h)
	got := decodeResponse(t, rec)

	wantEmpty := Response{
		Date:           got.Date, // date is request-relative; copy it through
		OverdueTodos:   []todo.PendingDetail{},
		TodayTodos:     []todo.PendingDetail{},
		ActiveTodos:    []todo.PendingDetail{},
		RecurringTodos: []todo.Item{},
		CommittedTodos: []daily.Item{},
		UpcomingTodos:  []todo.PendingDetail{},
		ActiveGoals:    []goal.ActiveGoalSummary{},
		RSSHighlights:  []RSSHighlight{},
	}
	if diff := cmp.Diff(wantEmpty, got); diff != "" {
		t.Errorf("empty-state Today() mismatch (-want +got):\n%s", diff)
	}

	// Raw JSON must contain "[]" for each list, never "null".
	raw := rec.Body.String()
	for _, field := range []string{
		"overdue_todos", "today_todos", "active_todos", "recurring_todos",
		"committed_todos", "upcoming_todos",
		"active_goals", "rss_highlights",
	} {
		if strings.Contains(raw, `"`+field+`":null`) {
			t.Errorf("field %q serialized as null, want []", field)
		}
	}
}

// TestToday_WiredSectionsPopulate proves each wired reader contributes its
// section and plan completion counts derive from the committed items.
func TestToday_WiredSectionsPopulate(t *testing.T) {
	t.Parallel()

	overdue := []todo.PendingDetail{{ID: uuid.New(), Title: "ship audit memo"}}
	dueOn := []todo.PendingDetail{{ID: uuid.New(), Title: "review draft"}}
	inRange := []todo.PendingDetail{{ID: uuid.New(), Title: "next week task"}}
	goals := []goal.ActiveGoalSummary{{Goal: goal.Goal{ID: uuid.New(), Title: "GDE application"}}}

	// Completion derives from the backing todo's state (+ recurring-occurrence
	// completion), not daily_plan_items.status (which has no write path). Each
	// item carries Status=planned (the only value the dead column ever holds) to
	// prove it is IGNORED; the TodoState / recurrence fields drive the counts.
	now := time.Now().UTC()
	todayUTC := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	recurInterval := int32(1)
	planItems := []daily.Item{
		{ID: uuid.New(), Status: daily.StatusPlanned, TodoState: "todo"},    // → Planned
		{ID: uuid.New(), Status: daily.StatusPlanned, TodoState: "done"},    // → Completed (terminal)
		{ID: uuid.New(), Status: daily.StatusPlanned, TodoState: "someday"}, // → Deferred
		{ID: uuid.New(), Status: daily.StatusPlanned, TodoState: "in_progress", // recurring occurrence completed today → Completed
			TodoRecurInterval: &recurInterval, TodoLastCompletedOn: &todayUTC},
	}

	h := NewHandler(fakePlanItems{items: planItems}, time.UTC, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithSources(
			&fakeTodos{overdue: overdue, dueOn: dueOn, inRange: inRange},
			fakeGoals{goals: goals},
			nil, // rss left nil — its section must stay []
		)

	got := decodeResponse(t, doToday(t, h))

	opt := cmpopts.IgnoreFields(todo.PendingDetail{}, "CreatedAt", "UpdatedAt")
	if diff := cmp.Diff(overdue, got.OverdueTodos, opt); diff != "" {
		t.Errorf("overdue_todos mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(dueOn, got.TodayTodos, opt); diff != "" {
		t.Errorf("today_todos mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(inRange, got.UpcomingTodos, opt); diff != "" {
		t.Errorf("upcoming_todos mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(goals, got.ActiveGoals); diff != "" {
		t.Errorf("active_goals mismatch (-want +got):\n%s", diff)
	}

	wantCompletion := PlanCompletion{Planned: 1, Completed: 2, Deferred: 1}
	if diff := cmp.Diff(wantCompletion, got.PlanCompletion); diff != "" {
		t.Errorf("plan_completion mismatch (-want +got):\n%s", diff)
	}
	if n := len(got.CommittedTodos); n != 4 {
		t.Errorf("committed_todos len = %d, want 4", n)
	}
	if n := len(got.RSSHighlights); n != 0 {
		t.Errorf("rss_highlights len = %d, want 0 (reader is nil)", n)
	}
}

// TestToday_ActiveDedupsAgainstOtherSections proves the Active section surfaces
// started work that no date section or the plan already shows (the previously-
// invisible due-less in_progress case) while never double-listing an in_progress
// todo that is also overdue/due-today/upcoming/committed/recurring.
func TestToday_ActiveDedupsAgainstOtherSections(t *testing.T) {
	t.Parallel()

	// loneStarted: in_progress, due-less, in no other section → must appear.
	loneStarted := todo.PendingDetail{ID: uuid.New(), Title: "終審 Go 課文", State: todo.StateInProgress}
	// alsoOverdue: in_progress AND surfaced as overdue → must not double-list.
	alsoOverdue := todo.PendingDetail{ID: uuid.New(), Title: "overdue+started", State: todo.StateInProgress}
	// committedID: in_progress AND committed to today's plan → must not double-list.
	committedID := uuid.New()
	alsoCommitted := todo.PendingDetail{ID: committedID, Title: "planned+started", State: todo.StateInProgress}

	h := NewHandler(
		fakePlanItems{items: []daily.Item{{ID: uuid.New(), TodoID: committedID, Status: daily.StatusPlanned}}},
		time.UTC,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithSources(
		&fakeTodos{
			overdue:    []todo.PendingDetail{alsoOverdue},
			inProgress: []todo.PendingDetail{loneStarted, alsoOverdue, alsoCommitted},
		},
		nil, nil,
	)

	got := decodeResponse(t, doToday(t, h))

	opt := cmpopts.IgnoreFields(todo.PendingDetail{}, "CreatedAt", "UpdatedAt")
	want := []todo.PendingDetail{loneStarted}
	if diff := cmp.Diff(want, got.ActiveTodos, opt); diff != "" {
		t.Errorf("active_todos mismatch (-want +got):\n%s", diff)
	}
}

// TestToday_InvalidDateRejected proves a malformed date query returns 400.
func TestToday_InvalidDateRejected(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t).WithSources(nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/today?date=not-a-date", http.NoBody)
	rec := httptest.NewRecorder()
	h.Today(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
