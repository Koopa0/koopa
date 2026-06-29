// Copyright 2026 Koopa. All rights reserved.

// Package today composes the admin Today dashboard — a cross-domain
// aggregate over todos, the day's committed plan, active goals, and RSS
// highlights. It is the HTTP mirror of the agent-facing brief(mode=morning)
// tool: both pull the same morning sections from the same domain stores.
//
// Every cross-domain source is expressed through a consumer-defined
// interface; this package does not import another feature's *Store
// directly.
package today

import (
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/todo"
)

// RSSHighlight is a recent high-priority feed entry surfaced as a
// situational-awareness signal. It mirrors the brief(morning)
// rss_highlights shape: recency-ordered, filtered by the feed's
// pre-tagged priority — not relevance-scored or curated.
type RSSHighlight struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	FeedName  string `json:"feed_name"`
	CreatedAt string `json:"created_at"`
}

// PlanCompletion is the small counts panel derived from the day's
// committed plan items: how many are still planned, done, or deferred.
type PlanCompletion struct {
	Planned   int `json:"planned"`
	Completed int `json:"completed"`
	Deferred  int `json:"deferred"`
}

// Response is the wire shape for GET /api/admin/commitment/today. It
// carries the same morning sections as brief(mode=morning), exposed via
// the admin API. List fields always marshal as [] (never null).
//
// ActiveTodos and RecurringTodos close the gap where started-but-undated work
// and due-today routines were invisible on the day's surfaces: ActiveTodos is
// in_progress work not already shown by a date section or the plan; RecurringTodos
// is the compute-on-read due-today routines (mirrors brief(morning)).
type Response struct {
	Date           string                   `json:"date"`
	OverdueTodos   []todo.PendingDetail     `json:"overdue_todos"`
	TodayTodos     []todo.PendingDetail     `json:"today_todos"`
	ActiveTodos    []todo.PendingDetail     `json:"active_todos"`
	RecurringTodos []todo.Item              `json:"recurring_todos"`
	CommittedTodos []daily.Item             `json:"committed_todos"`
	UpcomingTodos  []todo.PendingDetail     `json:"upcoming_todos"`
	PlanCompletion PlanCompletion           `json:"plan_completion"`
	ActiveGoals    []goal.ActiveGoalSummary `json:"active_goals"`
	RSSHighlights  []RSSHighlight           `json:"rss_highlights"`
}
