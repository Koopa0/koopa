// Copyright 2026 Koopa. All rights reserved.

// review.go holds the read model for review_period — the windowed owner
// retrospective computed LIVE from activity_events over a [since, until]
// window. Like progress.go nothing here is stored: every count and list is a
// read-time query against the canonical audit log. HUMAN-ACTIVITY-ONLY is the
// load-bearing semantic for the owner-progress rows: only activity_events with
// actor = 'human' count (identical to ProjectMomentum); the backlog-inflow
// count (todos opened) deliberately counts all actors.

package project

import (
	"context"
	"fmt"
	"time"

	"github.com/Koopa0/koopa/internal/db"
)

// CompletedTodo is one todo the owner completed within the review window. Title
// is the activity_events write-time snapshot, so a since-deleted todo still
// reports. Project / Area are nil when the event had no project association.
type CompletedTodo struct {
	Title       string    `json:"title"`
	CompletedAt time.Time `json:"completed_at"`
	Project     *string   `json:"project"`
	Area        *string   `json:"area"`
}

// CompletedMilestone is one milestone the owner completed within the window.
// Goal / Area are nil when the milestone (or its goal) was hard-deleted after
// the event; Title still reports from the activity_events snapshot.
type CompletedMilestone struct {
	Title       string    `json:"title"`
	Goal        *string   `json:"goal"`
	Area        *string   `json:"area"`
	CompletedAt time.Time `json:"completed_at"`
}

// GoalAdvance is one active goal's milestone progress plus whether it advanced
// (had a milestone completed) within the window.
type GoalAdvance struct {
	Title          string  `json:"title"`
	Area           *string `json:"area"`
	MilestoneDone  int64   `json:"milestone_done"`
	MilestoneTotal int64   `json:"milestone_total"`
	Status         string  `json:"status"`
	Advanced       bool    `json:"advanced"`
}

// AreaWindowActivity is one active area's owner-activity count over the window.
// Neglected is derived (ActivityCount == 0) by the handler, not stored here.
type AreaWindowActivity struct {
	Name          string `json:"name"`
	ActivityCount int64  `json:"activity_count"`
}

// CompletedTodosInWindow returns the todos the owner completed within
// [since, until], for review_period.completed_todos. Read-only.
func (s *Store) CompletedTodosInWindow(ctx context.Context, since, until time.Time) ([]CompletedTodo, error) {
	rows, err := s.q.CompletedTodosInWindow(ctx, db.CompletedTodosInWindowParams{Since: since, Until: until})
	if err != nil {
		return nil, fmt.Errorf("querying completed todos in window: %w", err)
	}
	out := make([]CompletedTodo, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = CompletedTodo{
			Title:       deref(r.Title),
			CompletedAt: r.CompletedAt,
			Project:     r.ProjectTitle,
			Area:        r.AreaName,
		}
	}
	return out, nil
}

// CompletedMilestonesInWindow returns the milestones the owner completed within
// [since, until], for review_period.completed_milestones. Read-only.
func (s *Store) CompletedMilestonesInWindow(ctx context.Context, since, until time.Time) ([]CompletedMilestone, error) {
	rows, err := s.q.CompletedMilestonesInWindow(ctx, db.CompletedMilestonesInWindowParams{Since: since, Until: until})
	if err != nil {
		return nil, fmt.Errorf("querying completed milestones in window: %w", err)
	}
	out := make([]CompletedMilestone, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = CompletedMilestone{
			Title:       deref(r.Title),
			Goal:        r.GoalTitle,
			Area:        r.AreaName,
			CompletedAt: r.CompletedAt,
		}
	}
	return out, nil
}

// GoalsAdvancedInWindow returns every active goal with its milestone progress
// and an "advanced" flag (a milestone completed within [since, until]), for
// review_period.goals. Status is always in_progress (the query's filter), echoed
// so the wire row is self-describing. Read-only.
func (s *Store) GoalsAdvancedInWindow(ctx context.Context, since, until time.Time) ([]GoalAdvance, error) {
	rows, err := s.q.ActiveGoalsAdvancedInWindow(ctx, db.ActiveGoalsAdvancedInWindowParams{Since: &since, Until: &until})
	if err != nil {
		return nil, fmt.Errorf("querying active goals advanced in window: %w", err)
	}
	out := make([]GoalAdvance, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = GoalAdvance{
			Title:          r.Title,
			Area:           r.AreaName,
			MilestoneDone:  r.MilestoneDone,
			MilestoneTotal: r.MilestoneTotal,
			Status:         "in_progress",
			Advanced:       r.Advanced,
		}
	}
	return out, nil
}

// AreaActivityInWindow returns the per-active-area owner-activity count over
// [since, until], for review_period.areas. Read-only.
func (s *Store) AreaActivityInWindow(ctx context.Context, since, until time.Time) ([]AreaWindowActivity, error) {
	rows, err := s.q.AreaActivityInWindow(ctx, db.AreaActivityInWindowParams{Since: since, Until: until})
	if err != nil {
		return nil, fmt.Errorf("querying area activity in window: %w", err)
	}
	out := make([]AreaWindowActivity, len(rows))
	for i := range rows {
		out[i] = AreaWindowActivity{
			Name:          rows[i].Name,
			ActivityCount: rows[i].ActivityCount,
		}
	}
	return out, nil
}

// TodosOpenedInWindow returns the count of todos created within [since, until]
// across ALL actors (backlog inflow), for review_period.counts.todos_opened.
// Deliberately not human-only: inflow is inflow whoever captured it. Read-only.
func (s *Store) TodosOpenedInWindow(ctx context.Context, since, until time.Time) (int64, error) {
	n, err := s.q.TodosOpenedCountInWindow(ctx, db.TodosOpenedCountInWindowParams{Since: since, Until: until})
	if err != nil {
		return 0, fmt.Errorf("counting todos opened in window: %w", err)
	}
	return n, nil
}

// ActiveDaysInWindow returns the count of distinct calendar days on which the
// owner had any activity within [since, until], for
// review_period.counts.active_days. Human-actor only. Read-only.
func (s *Store) ActiveDaysInWindow(ctx context.Context, since, until time.Time) (int64, error) {
	n, err := s.q.ActiveDaysInWindow(ctx, db.ActiveDaysInWindowParams{Since: since, Until: until})
	if err != nil {
		return 0, fmt.Errorf("counting active days in window: %w", err)
	}
	return n, nil
}
