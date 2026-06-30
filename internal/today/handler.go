// Copyright 2026 Koopa. All rights reserved.

package today

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

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

// todoDateReader returns the date-relative todo views: overdue, due-today, and
// the upcoming-week window. Backed by *todo.Store.
type todoDateReader interface {
	OverdueItems(ctx context.Context, today time.Time) ([]todo.PendingDetail, error)
	ItemsDueOn(ctx context.Context, date time.Time) ([]todo.PendingDetail, error)
	ItemsDueInRange(ctx context.Context, start, end time.Time) ([]todo.PendingDetail, error)
}

// todoActiveReader returns the started-work view (in_progress) and today's
// recurring occurrences that back the Today Active + Recurring sections.
// Backed by *todo.Store.
type todoActiveReader interface {
	InProgressItems(ctx context.Context) ([]todo.PendingDetail, error)
	RecurringItemsDueToday(ctx context.Context, today time.Time) ([]todo.Item, error)
}

// todoCompletedReader returns the todos completed today — one-time todos done
// within the day window plus recurring occurrences stamped today — backing the
// Today Completed count and review list. Backed by *todo.Store.
type todoCompletedReader interface {
	CompletedItemsOn(ctx context.Context, today, dayStart, dayEnd time.Time) ([]todo.Item, error)
}

// TodoReader is the todo-views surface the Today aggregate composes — the
// consumer-boundary subset of *todo.Store it depends on, split by role so each
// part stays small (interfaces.md).
type TodoReader interface {
	todoDateReader
	todoActiveReader
	todoCompletedReader
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
	loc       *time.Location
	logger    *slog.Logger
}

// NewHandler returns a today Handler. planItems is required; every other
// reader is injected via WithSources. A nil reader leaves its section of
// the response at the initialized empty-slice / zero state. loc is the owner's
// timezone for the day boundary (matches the MCP server); nil falls back to UTC.
func NewHandler(planItems PlanItemReader, loc *time.Location, logger *slog.Logger) *Handler {
	if loc == nil {
		loc = time.UTC
	}
	return &Handler{planItems: planItems, loc: loc, logger: logger}
}

// today returns the current date in the owner's timezone, at midnight. Mirrors
// mcp.Server.today so the dashboard and brief(morning) agree on the day.
func (h *Handler) today() time.Time {
	now := time.Now().In(h.loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, h.loc)
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
	date := h.today()
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
		ActiveTodos:    []todo.PendingDetail{},
		RecurringTodos: []todo.Item{},
		CompletedTodos: []todo.Item{},
		CommittedTodos: []daily.Item{},
		UpcomingTodos:  []todo.PendingDetail{},
		ActiveGoals:    []goal.ActiveGoalSummary{},
		RSSHighlights:  []RSSHighlight{},
	}

	h.loadTodos(ctx, date, &resp)
	h.loadCompleted(ctx, date, &resp)
	h.loadPlan(ctx, date, &resp)
	// Active dedups against the date sections, the plan, and recurring, so it
	// must run after loadTodos + loadPlan have populated them.
	h.loadActive(ctx, &resp)
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
	if rows, err := h.todos.RecurringItemsDueToday(ctx, date); err != nil {
		h.logger.Warn("today: recurring todos failed", "error", err)
	} else if rows != nil {
		resp.RecurringTodos = rows
	}
}

// loadActive fills ActiveTodos with in_progress work not already surfaced by a
// date section (overdue / due-today / upcoming), the committed plan, or
// recurring-due-today — so a started task is never double-listed yet never
// invisible. Typically these are the due-less in_progress items. Runs after
// loadTodos + loadPlan so the dedup set is complete.
func (h *Handler) loadActive(ctx context.Context, resp *Response) {
	if h.todos == nil {
		return
	}
	rows, err := h.todos.InProgressItems(ctx)
	if err != nil {
		h.logger.Warn("today: active todos failed", "error", err)
		return
	}
	shown := make(map[uuid.UUID]struct{},
		len(resp.OverdueTodos)+len(resp.TodayTodos)+len(resp.UpcomingTodos)+
			len(resp.RecurringTodos)+len(resp.CommittedTodos))
	for i := range resp.OverdueTodos {
		shown[resp.OverdueTodos[i].ID] = struct{}{}
	}
	for i := range resp.TodayTodos {
		shown[resp.TodayTodos[i].ID] = struct{}{}
	}
	for i := range resp.UpcomingTodos {
		shown[resp.UpcomingTodos[i].ID] = struct{}{}
	}
	for i := range resp.RecurringTodos {
		shown[resp.RecurringTodos[i].ID] = struct{}{}
	}
	for i := range resp.CommittedTodos {
		shown[resp.CommittedTodos[i].TodoID] = struct{}{}
	}
	active := make([]todo.PendingDetail, 0, len(rows))
	for i := range rows {
		if _, dup := shown[rows[i].ID]; dup {
			continue
		}
		active = append(active, rows[i])
	}
	resp.ActiveTodos = active
}

// loadCompleted fills CompletedTodos with what was finished today — one-time
// todos done within [date, date+1d) plus recurring occurrences stamped today —
// feeding the front end's Completed count (derived from len(CompletedTodos))
// and the "completed today" list.
func (h *Handler) loadCompleted(ctx context.Context, date time.Time, resp *Response) {
	if h.todos == nil {
		return
	}
	dayEnd := date.AddDate(0, 0, 1)
	if rows, err := h.todos.CompletedItemsOn(ctx, date, date, dayEnd); err != nil {
		h.logger.Warn("today: completed todos failed", "error", err)
	} else if rows != nil {
		resp.CompletedTodos = rows
	}
}

// loadPlan fills CommittedTodos with the day's committed plan. The plan is now
// an optional pin: it no longer drives the progress counts (the front end
// derives those from the due/recurring/completed section lengths), so a missing
// plan does not zero the dashboard — hence a failure logs at Warn like the other
// optional sections, not Error.
func (h *Handler) loadPlan(ctx context.Context, date time.Time, resp *Response) {
	items, err := h.planItems.ItemsByDate(ctx, date)
	if err != nil {
		h.logger.Warn("today: plan items failed", "error", err)
		return
	}
	if items != nil {
		resp.CommittedTodos = items
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
