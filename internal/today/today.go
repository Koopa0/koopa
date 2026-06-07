// Copyright 2026 Koopa. All rights reserved.

// Package today composes the admin Today dashboard — a cross-domain
// aggregate over todos, the day's committed plan, active goals,
// unverified hypotheses, the active learning session, and RSS highlights.
// It is the HTTP mirror of the agent-facing brief(mode=morning) tool:
// both pull the same morning sections from the same domain stores.
//
// Every cross-domain source is expressed through a consumer-defined
// interface; this package does not import another feature's *Store
// directly.
package today

import (
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
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
// the admin API. List fields always marshal as [] (never null); the
// active learning session is omitted when none is open.
type Response struct {
	Date                 string                   `json:"date"`
	OverdueTodos         []todo.PendingDetail     `json:"overdue_todos"`
	TodayTodos           []todo.PendingDetail     `json:"today_todos"`
	CommittedTodos       []daily.Item             `json:"committed_todos"`
	UpcomingTodos        []todo.PendingDetail     `json:"upcoming_todos"`
	PlanCompletion       PlanCompletion           `json:"plan_completion"`
	ActiveGoals          []goal.ActiveGoalSummary `json:"active_goals"`
	UnverifiedHypotheses []hypothesis.Record      `json:"unverified_hypotheses"`
	ActiveSession        *learning.Session        `json:"active_session,omitempty"`
	RSSHighlights        []RSSHighlight           `json:"rss_highlights"`
}
