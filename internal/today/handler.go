// Copyright 2026 Koopa. All rights reserved.

package today

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/feed/entry"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/todo"
)

// --- Source interfaces ---
//
// Each interface is consumer-defined and matched to a real store method so
// the production wiring injects the concrete store directly — no adapter.

// TodoReader returns the date-relative todo views: overdue, due-today, and
// the upcoming-week window. Backed by *todo.Store.
type TodoReader interface {
	OverdueItems(ctx context.Context, today time.Time) ([]todo.PendingDetail, error)
	ItemsDueOn(ctx context.Context, date time.Time) ([]todo.PendingDetail, error)
	ItemsDueInRange(ctx context.Context, start, end time.Time) ([]todo.PendingDetail, error)
}

// PlanItemReader returns the day's committed daily plan items. Backed by
// *daily.Store.
type PlanItemReader interface {
	ItemsByDate(ctx context.Context, date time.Time) ([]daily.Item, error)
}

// ActiveGoalReader returns the in_progress goals with milestone counts.
// Backed by *goal.Store.
type ActiveGoalReader interface {
	ActiveGoals(ctx context.Context) ([]goal.ActiveGoalSummary, error)
}

// RSSHighlightReader returns recent high-priority feed entries. Backed by
// *entry.Store.
type RSSHighlightReader interface {
	HighPriorityRecent(ctx context.Context, since time.Time, maxResults int32) ([]entry.Item, error)
}

// Handler handles the Today aggregate HTTP request.
type Handler struct {
	planItems PlanItemReader
	todos     TodoReader
	goals     ActiveGoalReader
	rss       RSSHighlightReader
	logger    *slog.Logger
}

// NewHandler returns a today Handler. planItems is required; every other
// reader is injected via WithSources. A nil reader leaves its section of
// the response at the initialized empty-slice / zero state.
func NewHandler(planItems PlanItemReader, logger *slog.Logger) *Handler {
	return &Handler{planItems: planItems, logger: logger}
}

// WithSources injects the cross-domain readers and returns the handler for
// chaining.
func (h *Handler) WithSources(
	todos TodoReader,
	goals ActiveGoalReader,
	rss RSSHighlightReader,
) *Handler {
	h.todos = todos
	h.goals = goals
	h.rss = rss
	return h
}

const (
	rssHighlightLimit  = 10 // mirrors brief(morning) fillRSSHighlights
	rssLookbackDays    = 2  // mirrors brief(morning): since = date - 2d
	upcomingWindowDays = 7  // mirrors brief(morning): upcoming = date .. date+7d
)

// Today handles GET /api/admin/commitment/today.
func (h *Handler) Today(w http.ResponseWriter, r *http.Request) {
	date := time.Now().UTC()
	if d := r.URL.Query().Get("date"); d != "" {
		parsed, err := time.Parse(time.DateOnly, d)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid date format, use YYYY-MM-DD")
			return
		}
		date = parsed
	}

	ctx := r.Context()
	resp := Response{
		Date:           date.Format(time.DateOnly),
		OverdueTodos:   []todo.PendingDetail{},
		TodayTodos:     []todo.PendingDetail{},
		CommittedTodos: []daily.Item{},
		UpcomingTodos:  []todo.PendingDetail{},
		ActiveGoals:    []goal.ActiveGoalSummary{},
		RSSHighlights:  []RSSHighlight{},
	}

	h.loadTodos(ctx, date, &resp)
	h.loadPlan(ctx, date, &resp)
	h.loadGoals(ctx, &resp)
	h.loadRSS(ctx, date, &resp)

	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

func (h *Handler) loadTodos(ctx context.Context, date time.Time, resp *Response) {
	if h.todos == nil {
		return
	}
	if rows, err := h.todos.OverdueItems(ctx, date); err != nil {
		h.logger.Warn("today: overdue todos failed", "error", err)
	} else if rows != nil {
		resp.OverdueTodos = rows
	}
	if rows, err := h.todos.ItemsDueOn(ctx, date); err != nil {
		h.logger.Warn("today: today todos failed", "error", err)
	} else if rows != nil {
		resp.TodayTodos = rows
	}
	end := date.AddDate(0, 0, upcomingWindowDays)
	if rows, err := h.todos.ItemsDueInRange(ctx, date, end); err != nil {
		h.logger.Warn("today: upcoming todos failed", "error", err)
	} else if rows != nil {
		resp.UpcomingTodos = rows
	}
}

func (h *Handler) loadPlan(ctx context.Context, date time.Time, resp *Response) {
	items, err := h.planItems.ItemsByDate(ctx, date)
	if err != nil {
		h.logger.Error("today: plan items failed", "error", err)
		return
	}
	if items != nil {
		resp.CommittedTodos = items
	}
	for i := range items {
		switch items[i].Status {
		case daily.StatusPlanned:
			resp.PlanCompletion.Planned++
		case daily.StatusDone:
			resp.PlanCompletion.Completed++
		case daily.StatusDeferred:
			resp.PlanCompletion.Deferred++
		case daily.StatusDropped:
			// dropped items are not counted in any category
		}
	}
}

func (h *Handler) loadGoals(ctx context.Context, resp *Response) {
	if h.goals == nil {
		return
	}
	if rows, err := h.goals.ActiveGoals(ctx); err != nil {
		h.logger.Warn("today: active goals failed", "error", err)
	} else if rows != nil {
		resp.ActiveGoals = rows
	}
}

func (h *Handler) loadRSS(ctx context.Context, date time.Time, resp *Response) {
	if h.rss == nil {
		return
	}
	since := date.AddDate(0, 0, -rssLookbackDays)
	items, err := h.rss.HighPriorityRecent(ctx, since, rssHighlightLimit)
	if err != nil {
		h.logger.Warn("today: rss highlights failed", "error", err)
		return
	}
	highlights := make([]RSSHighlight, 0, len(items))
	for i := range items {
		highlights = append(highlights, RSSHighlight{
			Title:     items[i].Title,
			URL:       items[i].SourceURL,
			FeedName:  items[i].FeedName,
			CreatedAt: items[i].CollectedAt.Format(time.RFC3339),
		})
	}
	resp.RSSHighlights = highlights
}
