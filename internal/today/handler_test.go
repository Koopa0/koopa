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
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
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
	overdue []todo.PendingDetail
	dueOn   []todo.PendingDetail
	inRange []todo.PendingDetail
}

func (f fakeTodos) OverdueItems(context.Context, time.Time) ([]todo.PendingDetail, error) {
	return f.overdue, nil
}

func (f fakeTodos) ItemsDueOn(context.Context, time.Time) ([]todo.PendingDetail, error) {
	return f.dueOn, nil
}

func (f fakeTodos) ItemsDueInRange(context.Context, time.Time, time.Time) ([]todo.PendingDetail, error) {
	return f.inRange, nil
}

// fakeGoals satisfies ActiveGoalReader.
type fakeGoals struct {
	goals []goal.ActiveGoalSummary
}

func (f fakeGoals) ActiveGoals(context.Context) ([]goal.ActiveGoalSummary, error) {
	return f.goals, nil
}

// fakeHypotheses satisfies UnverifiedHypothesisReader.
type fakeHypotheses struct {
	recs []hypothesis.Record
}

func (f fakeHypotheses) Unverified(context.Context, int32) ([]hypothesis.Record, error) {
	return f.recs, nil
}

// fakeSession satisfies ActiveSessionReader. When session is nil it returns
// learning.ErrNoActive, mirroring the store's no-open-session behavior.
type fakeSession struct {
	session *learning.Session
}

func (f fakeSession) ActiveSession(context.Context) (*learning.Session, error) {
	if f.session == nil {
		return nil, learning.ErrNoActive
	}
	return f.session, nil
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	return NewHandler(fakePlanItems{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
// as [] (never null) and that the active session is omitted when no reader
// is wired — the json-api.md "lists return [], never null" contract.
func TestToday_EmptyStateReturnsEmptyArrays(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t).WithSources(nil, nil, nil, nil, nil)
	rec := doToday(t, h)
	got := decodeResponse(t, rec)

	wantEmpty := Response{
		Date:                 got.Date, // date is request-relative; copy it through
		OverdueTodos:         []todo.PendingDetail{},
		TodayTodos:           []todo.PendingDetail{},
		CommittedTodos:       []daily.Item{},
		UpcomingTodos:        []todo.PendingDetail{},
		ActiveGoals:          []goal.ActiveGoalSummary{},
		UnverifiedHypotheses: []hypothesis.Record{},
		RSSHighlights:        []RSSHighlight{},
	}
	if diff := cmp.Diff(wantEmpty, got); diff != "" {
		t.Errorf("empty-state Today() mismatch (-want +got):\n%s", diff)
	}

	// Raw JSON must contain "[]" for each list, never "null".
	raw := rec.Body.String()
	for _, field := range []string{
		"overdue_todos", "today_todos", "committed_todos", "upcoming_todos",
		"active_goals", "unverified_hypotheses", "rss_highlights",
	} {
		if strings.Contains(raw, `"`+field+`":null`) {
			t.Errorf("field %q serialized as null, want []", field)
		}
	}
	// active_session is omitempty — must be absent, not null.
	if strings.Contains(raw, "active_session") {
		t.Errorf("active_session present in empty-state body, want omitted: %s", raw)
	}
}

// TestToday_WiredSectionsPopulate proves each wired reader contributes its
// section, plan completion counts derive from the committed items, and the
// active session is surfaced when one is open.
func TestToday_WiredSectionsPopulate(t *testing.T) {
	t.Parallel()

	overdue := []todo.PendingDetail{{ID: uuid.New(), Title: "ship audit memo"}}
	dueOn := []todo.PendingDetail{{ID: uuid.New(), Title: "review draft"}}
	inRange := []todo.PendingDetail{{ID: uuid.New(), Title: "next week task"}}
	goals := []goal.ActiveGoalSummary{{Goal: goal.Goal{ID: uuid.New(), Title: "GDE application"}}}
	hyps := []hypothesis.Record{{ID: uuid.New(), Claim: "DFS termination is the gap"}}
	sessionID := uuid.New()
	session := &learning.Session{ID: sessionID, Domain: "leetcode"}

	planItems := []daily.Item{
		{ID: uuid.New(), Status: daily.StatusPlanned},
		{ID: uuid.New(), Status: daily.StatusDone},
		{ID: uuid.New(), Status: daily.StatusDeferred},
		{ID: uuid.New(), Status: daily.StatusDropped},
	}

	h := NewHandler(fakePlanItems{items: planItems}, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithSources(
			fakeTodos{overdue: overdue, dueOn: dueOn, inRange: inRange},
			fakeGoals{goals: goals},
			fakeHypotheses{recs: hyps},
			fakeSession{session: session},
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
	if diff := cmp.Diff(hyps, got.UnverifiedHypotheses, cmpopts.EquateApproxTime(0)); diff != "" {
		t.Errorf("unverified_hypotheses mismatch (-want +got):\n%s", diff)
	}
	if got.ActiveSession == nil || got.ActiveSession.ID != sessionID {
		t.Errorf("active_session = %+v, want session id %s", got.ActiveSession, sessionID)
	}

	wantCompletion := PlanCompletion{Planned: 1, Completed: 1, Deferred: 1}
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

// TestToday_InvalidDateRejected proves a malformed date query returns 400.
func TestToday_InvalidDateRejected(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t).WithSources(nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/commitment/today?date=not-a-date", http.NoBody)
	rec := httptest.NewRecorder()
	h.Today(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
