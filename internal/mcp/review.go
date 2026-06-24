// Copyright 2026 Koopa. All rights reserved.

// review.go holds review_period, the read-only windowed owner retrospective.
// It returns what the OWNER got done across a [since, until] date window —
// completed todos and milestones, goal advancement, area activity / neglect,
// and published content — computed LIVE from activity_events at read time.
// Nothing is stored.
//
// Authorization: none at the tool layer — access is gated by the MCP transport
// (the connection is the trust boundary). It is deliberately NOT caller-scoped
// (no created_by=caller filter): the retrospective is the single owner's data,
// so a caller-scope would return empty. Any caller reads the whole owner
// retrospective.
//
// HUMAN-ACTIVITY-ONLY: the owner-progress rows count solely activity_events with
// actor='human' — IDENTICAL to project_progress. The one exception is the
// backlog-inflow count (todos opened), which counts all actors by design.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ReviewPeriodInput selects the retrospective window. Since is required
// (YYYY-MM-DD); Until is optional and defaults to today. The window is
// whole-day-inclusive: until covers the entire day.
type ReviewPeriodInput struct {
	As    string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call."`
	Since string `json:"since" jsonschema:"required" jsonschema_description:"Window start date YYYY-MM-DD (inclusive, from 00:00 in the owner's timezone)."`
	Until string `json:"until,omitempty" jsonschema_description:"Window end date YYYY-MM-DD (inclusive, through 23:59:59 in the owner's timezone). Defaults to today."`
}

// ReviewWindow echoes the resolved date window back to the caller.
type ReviewWindow struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// ReviewCompletedTodo is one todo the owner completed in the window.
type ReviewCompletedTodo struct {
	Title       string  `json:"title"`
	CompletedAt string  `json:"completed_at"`
	Project     *string `json:"project"`
	Area        *string `json:"area"`
}

// ReviewCompletedMilestone is one milestone the owner completed in the window.
type ReviewCompletedMilestone struct {
	Title       string  `json:"title"`
	Goal        *string `json:"goal"`
	Area        *string `json:"area"`
	CompletedAt string  `json:"completed_at"`
}

// ReviewGoal is one active goal's milestone progress plus whether it advanced
// (had a milestone completed) within the window.
type ReviewGoal struct {
	Title          string  `json:"title"`
	Area           *string `json:"area"`
	MilestoneDone  int64   `json:"milestone_done"`
	MilestoneTotal int64   `json:"milestone_total"`
	Status         string  `json:"status"`
	Advanced       bool    `json:"advanced"`
}

// ReviewArea is one active area's window activity count and neglect flag.
type ReviewArea struct {
	Name          string `json:"name"`
	ActivityCount int64  `json:"activity_count"`
	Neglected     bool   `json:"neglected"`
}

// ReviewPublishedContent is one content piece published within the window.
type ReviewPublishedContent struct {
	Title       string `json:"title"`
	Type        string `json:"type"`
	PublishedAt string `json:"published_at"`
}

// ReviewCounts is the headline tally for the window.
type ReviewCounts struct {
	TodosCompleted      int `json:"todos_completed"`
	TodosOpened         int `json:"todos_opened"`
	MilestonesCompleted int `json:"milestones_completed"`
	ContentPublished    int `json:"content_published"`
	AreasActive         int `json:"areas_active"`
	AreasNeglected      int `json:"areas_neglected"`
	ActiveDays          int `json:"active_days"`
}

// ReviewPeriodOutput is the structured review_period response.
type ReviewPeriodOutput struct {
	Window              ReviewWindow               `json:"window"`
	CompletedTodos      []ReviewCompletedTodo      `json:"completed_todos"`
	CompletedMilestones []ReviewCompletedMilestone `json:"completed_milestones"`
	Goals               []ReviewGoal               `json:"goals"`
	Areas               []ReviewArea               `json:"areas"`
	PublishedContent    []ReviewPublishedContent   `json:"published_content"`
	Counts              ReviewCounts               `json:"counts"`
}

// store reads with a single date-parse branch — splitting it would scatter the
// window assembly that is clearest read top to bottom.
func (s *Server) reviewPeriod(ctx context.Context, _ *mcp.CallToolRequest, input ReviewPeriodInput) (*mcp.CallToolResult, ReviewPeriodOutput, error) {
	since, until, err := s.parseReviewWindow(input.Since, input.Until)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}

	out := ReviewPeriodOutput{
		Window:              ReviewWindow{Since: since.Format(time.DateOnly), Until: until.Format(time.DateOnly)},
		CompletedTodos:      []ReviewCompletedTodo{},
		CompletedMilestones: []ReviewCompletedMilestone{},
		Goals:               []ReviewGoal{},
		Areas:               []ReviewArea{},
		PublishedContent:    []ReviewPublishedContent{},
	}

	// Whole-day-inclusive window bounds in the owner's timezone: [since 00:00,
	// until 23:59:59.999999999]. Resolved here so every store call shares the
	// same instants.
	from := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, s.loc)
	to := time.Date(until.Year(), until.Month(), until.Day(), 23, 59, 59, int(time.Second-time.Nanosecond), s.loc)

	// Sequential store reads — matches project_progress's style. Each read is a
	// single round-trip; the handler stays a flat composition.
	todos, err := s.projects.CompletedTodosInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}
	for i := range todos {
		out.CompletedTodos = append(out.CompletedTodos, ReviewCompletedTodo{
			Title:       todos[i].Title,
			CompletedAt: todos[i].CompletedAt.Format(time.RFC3339),
			Project:     todos[i].Project,
			Area:        todos[i].Area,
		})
	}

	milestones, err := s.projects.CompletedMilestonesInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}
	for i := range milestones {
		out.CompletedMilestones = append(out.CompletedMilestones, ReviewCompletedMilestone{
			Title:       milestones[i].Title,
			Goal:        milestones[i].Goal,
			Area:        milestones[i].Area,
			CompletedAt: milestones[i].CompletedAt.Format(time.RFC3339),
		})
	}

	goals, err := s.projects.GoalsAdvancedInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}
	for i := range goals {
		out.Goals = append(out.Goals, ReviewGoal{
			Title:          goals[i].Title,
			Area:           goals[i].Area,
			MilestoneDone:  goals[i].MilestoneDone,
			MilestoneTotal: goals[i].MilestoneTotal,
			Status:         goals[i].Status,
			Advanced:       goals[i].Advanced,
		})
	}

	areas, err := s.projects.AreaActivityInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}
	var areasActive, areasNeglected int
	for i := range areas {
		neglected := areas[i].ActivityCount == 0
		if neglected {
			areasNeglected++
		} else {
			areasActive++
		}
		out.Areas = append(out.Areas, ReviewArea{
			Name:          areas[i].Name,
			ActivityCount: areas[i].ActivityCount,
			Neglected:     neglected,
		})
	}

	published, err := s.contents.PublishedInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}
	for i := range published {
		out.PublishedContent = append(out.PublishedContent, ReviewPublishedContent{
			Title:       published[i].Title,
			Type:        string(published[i].Type),
			PublishedAt: rfc3339OrEmpty(published[i].PublishedAt),
		})
	}

	todosOpened, err := s.projects.TodosOpenedInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}
	activeDays, err := s.projects.ActiveDaysInWindow(ctx, from, to)
	if err != nil {
		return nil, ReviewPeriodOutput{}, err
	}

	out.Counts = ReviewCounts{
		TodosCompleted:      len(out.CompletedTodos),
		TodosOpened:         int(todosOpened),
		MilestonesCompleted: len(out.CompletedMilestones),
		ContentPublished:    len(out.PublishedContent),
		AreasActive:         areasActive,
		AreasNeglected:      areasNeglected,
		ActiveDays:          int(activeDays),
	}

	return nil, out, nil
}

// parseReviewWindow parses the since (required) and until (optional, default
// today) date inputs as whole dates in the owner's timezone. since must not be
// after until.
func (s *Server) parseReviewWindow(sinceStr, untilStr string) (since, until time.Time, err error) {
	if sinceStr == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("since is required (format YYYY-MM-DD)")
	}
	since, err = time.ParseInLocation(time.DateOnly, sinceStr, s.loc)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid since %q: %w", sinceStr, err)
	}

	until = s.today()
	if untilStr != "" {
		until, err = time.ParseInLocation(time.DateOnly, untilStr, s.loc)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid until %q: %w", untilStr, err)
		}
	}

	if since.After(until) {
		return time.Time{}, time.Time{}, fmt.Errorf("since %q must not be after until %q", sinceStr, until.Format(time.DateOnly))
	}
	return since, until, nil
}

// rfc3339OrEmpty renders a nullable instant as RFC3339, or "" when nil. Used for
// published_at, which is non-null for published rows but typed *time.Time.
func rfc3339OrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
