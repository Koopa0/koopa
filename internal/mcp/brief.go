// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/todo"
)

// --- brief ---
//
// brief is the read-only planning-state multiplexer. mode=morning is the
// single-call daily-planning briefing (todos, goals, hypotheses, RSS,
// content pipeline); mode=reflection is the end-of-day plan-vs-actual
// retrospective (daily plan items + completion counts). brief is a pure
// planning-state pull and carries no agent memory of its own.

// sectionTimeout is the per-section timeout for brief morning queries.
const sectionTimeout = 15 * time.Second

const (
	briefModeMorning    = "morning"
	briefModeReflection = "reflection"
)

// defaultSectionsByAgent maps a caller agent name to the brief morning
// sections it gets when the caller doesn't supply `sections` explicitly.
// Callers not listed here keep the historical "all sections" default.
// Explicit `sections` always wins over this map.
//
// This exists because callers like learning-studio routinely paid the
// token cost of unrelated sections (e.g. 10 Google Developers Blog RSS
// items) before learning to pass an explicit sections list. The map is
// the single auditable point where per-agent defaults live — DO NOT
// scatter the per-agent override logic across the section fillers.
// Section names must match the runSection labels in fillBriefMorning.
var defaultSectionsByAgent = map[string][]string{
	"learning-studio": {"tasks", "hypotheses"},
}

// resolveDefaultSections returns the section set to use when the caller
// omitted `sections`. nil means "fall through to the historical all-
// sections default" — callers must distinguish nil (use all) from an
// empty-but-non-nil slice (which would be wrong; the map intentionally
// never returns an empty slice). Pass the resolved caller identity, not
// the raw context — keeps this function unit-testable.
func resolveDefaultSections(caller string) []string {
	defaults, ok := defaultSectionsByAgent[caller]
	if !ok {
		return nil
	}
	return defaults
}

// BriefInput is the input for the brief tool.
//
// Mode selects the briefing flavour and is required. Sections is a STRICT
// filter that applies only in morning mode: when non-empty, only the listed
// groups are populated and every other morning field stays at its empty-slice
// default. Omit Sections (or pass an empty list) to populate every morning
// group. Sections is ignored in reflection mode.
//
// Morning group → response field mapping:
//
//	"tasks"            → overdue_todos, today_todos, committed_todos, upcoming_todos
//	"goals"            → active_goals
//	"hypotheses"       → unverified_hypotheses
//	"rss"              → rss_highlights
//	"content_pipeline" → content_pipeline
//
// Unknown group names are ignored silently (no error, no warning).
type BriefInput struct {
	As       string          `json:"as,omitempty" jsonschema_description:"Caller agent identity (e.g. planner, learning-studio)."`
	Mode     string          `json:"mode" jsonschema_description:"Briefing mode (required): 'morning' = daily-planning pull (todos/goals/hypotheses/rss/content_pipeline); 'reflection' = end-of-day plan-vs-actual retrospective (daily plan items + completion counts). brief is a pure planning-state pull and carries no agent memory."`
	Sections FlexStringSlice `json:"sections,omitempty" jsonschema_description:"MORNING-ONLY strict filter on which groups to populate (default: all). Ignored in reflection mode. Omit or pass [] to get the full morning briefing. Group key → response fields: 'tasks' → overdue_todos/today_todos/committed_todos/upcoming_todos; 'goals' → active_goals; 'hypotheses' → unverified_hypotheses; 'rss' → rss_highlights; 'content_pipeline' → content_pipeline. Unknown keys silently ignored."`
	Date     *string         `json:"date,omitempty" jsonschema_description:"Target date YYYY-MM-DD (default: today)"`
}

// BriefOutput is the output of the brief tool. The active mode determines
// which group of fields carries data; MarshalJSON emits {mode, date} plus
// only the active mode's fields so the wire shape mirrors the former
// morning_context / reflection_context tools (minus their agent_notes
// sections). The unused mode's fields are dropped, not emitted as empty.
type BriefOutput struct {
	Mode string `json:"mode"`
	Date string `json:"date"`

	// Morning fields.
	OverdueTodos         []todo.PendingDetail     `json:"-"`
	TodayTodos           []todo.PendingDetail     `json:"-"`
	CommittedTodos       []daily.Item             `json:"-"`
	UpcomingTodos        []todo.PendingDetail     `json:"-"`
	ActiveGoals          []goal.ActiveGoalSummary `json:"-"`
	UnverifiedHypotheses []hypothesis.Record      `json:"-"`
	RSSHighlights        []RSSHighlight           `json:"-"`
	ContentPipeline      []ContentSummary         `json:"-"`

	// Reflection fields.
	PlannedItems   []daily.Item `json:"-"`
	CompletedCount int          `json:"-"`
	DeferredCount  int          `json:"-"`
	PlannedCount   int          `json:"-"`
	CompletionRate float64      `json:"-"`
}

// briefMorningWire is the wire shape for mode=morning. Field tags mirror the
// former morning briefing exactly, minus the dropped daily-plan-note section.
type briefMorningWire struct {
	Mode                 string                   `json:"mode"`
	Date                 string                   `json:"date"`
	OverdueTodos         []todo.PendingDetail     `json:"overdue_todos"`
	TodayTodos           []todo.PendingDetail     `json:"today_todos"`
	CommittedTodos       []daily.Item             `json:"committed_todos"`
	UpcomingTodos        []todo.PendingDetail     `json:"upcoming_todos"`
	ActiveGoals          []goal.ActiveGoalSummary `json:"active_goals"`
	UnverifiedHypotheses []hypothesis.Record      `json:"unverified_hypotheses"`
	RSSHighlights        []RSSHighlight           `json:"rss_highlights"`
	ContentPipeline      []ContentSummary         `json:"content_pipeline"`
}

// briefReflectionWire is the wire shape for mode=reflection. Field tags mirror
// the former reflection retrospective exactly, minus the dropped note sections.
type briefReflectionWire struct {
	Mode           string       `json:"mode"`
	Date           string       `json:"date"`
	PlannedItems   []daily.Item `json:"planned_items"`
	CompletedCount int          `json:"completed_count"`
	DeferredCount  int          `json:"deferred_count"`
	PlannedCount   int          `json:"planned_count"`
	CompletionRate float64      `json:"completion_rate"`
}

// MarshalJSON emits {mode, date, ...only the active mode's fields}. Selecting
// by Mode keeps each mode's wire shape identical to its former standalone tool
// (morning_context / reflection_context) plus the `mode` tag, and prevents the
// inactive mode's zero-value fields from leaking into the response.
//
//nolint:gocritic // hugeParam: stdlib json.Marshaler interface takes value receiver
func (o BriefOutput) MarshalJSON() ([]byte, error) {
	switch o.Mode {
	case briefModeMorning:
		return json.Marshal(briefMorningWire{
			Mode:                 o.Mode,
			Date:                 o.Date,
			OverdueTodos:         o.OverdueTodos,
			TodayTodos:           o.TodayTodos,
			CommittedTodos:       o.CommittedTodos,
			UpcomingTodos:        o.UpcomingTodos,
			ActiveGoals:          o.ActiveGoals,
			UnverifiedHypotheses: o.UnverifiedHypotheses,
			RSSHighlights:        o.RSSHighlights,
			ContentPipeline:      o.ContentPipeline,
		})
	case briefModeReflection:
		return json.Marshal(briefReflectionWire{
			Mode:           o.Mode,
			Date:           o.Date,
			PlannedItems:   o.PlannedItems,
			CompletedCount: o.CompletedCount,
			DeferredCount:  o.DeferredCount,
			PlannedCount:   o.PlannedCount,
			CompletionRate: o.CompletionRate,
		})
	default:
		// Mode is validated by the handler before marshalling, so this is a
		// programming error rather than a runtime condition.
		return nil, fmt.Errorf("brief: unknown mode %q", o.Mode)
	}
}

// RSSHighlight is a recent feed_entries row from a feed whose
// priority='high'. The "highlight" name is historical: nothing about
// the row is relevance-scored or curated — it is recency-ordered and
// filtered by the feed's pre-tagged priority. A prolific high-priority
// feed will fill all 10 slots. For ranked retrieval, callers use
// search_knowledge; the morning briefing surfaces these as a
// situational-awareness signal, not a recommendation.
type RSSHighlight struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	FeedName  string `json:"feed_name"`
	CreatedAt string `json:"created_at"`
}

// ContentSummary is a lightweight content record for the content-pipeline
// section of the morning brief.
type ContentSummary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

func (s *Server) brief(ctx context.Context, _ *mcp.CallToolRequest, input BriefInput) (*mcp.CallToolResult, BriefOutput, error) {
	if input.Mode != briefModeMorning && input.Mode != briefModeReflection {
		return nil, BriefOutput{}, fmt.Errorf("brief: invalid mode %q (valid: morning, reflection)", input.Mode)
	}

	date := s.today()
	if input.Date != nil && *input.Date != "" {
		t, err := time.Parse(time.DateOnly, *input.Date)
		if err != nil {
			return nil, BriefOutput{}, err
		}
		date = t
	}

	out := BriefOutput{
		Mode: input.Mode,
		Date: date.Format(time.DateOnly),
	}

	switch input.Mode {
	case briefModeMorning:
		s.fillBriefMorning(ctx, date, input.Sections, &out)
	case briefModeReflection:
		s.fillBriefReflection(ctx, date, &out)
	}

	return nil, out, nil
}

// fillBriefMorning populates the morning fields concurrently, honouring the
// optional sections filter. Every list field is initialised to an empty slice
// first so JSON marshalling always emits [] (never null) for sections that are
// not requested or that fail to load.
func (s *Server) fillBriefMorning(ctx context.Context, date time.Time, requested FlexStringSlice, out *BriefOutput) {
	out.OverdueTodos = []todo.PendingDetail{}
	out.TodayTodos = []todo.PendingDetail{}
	out.CommittedTodos = []daily.Item{}
	out.UpcomingTodos = []todo.PendingDetail{}
	out.ActiveGoals = []goal.ActiveGoalSummary{}
	out.UnverifiedHypotheses = []hypothesis.Record{}
	out.RSSHighlights = []RSSHighlight{}
	out.ContentPipeline = []ContentSummary{}

	// If the caller omitted sections, consult the per-agent allowlist before
	// falling through to "all sections". Explicit sections always wins.
	// Resolved here so the dispatcher sees a uniform shape — caller-aware
	// behavior is contained to this one site.
	sections := requested
	if len(sections) == 0 {
		if defaults := resolveDefaultSections(s.callerIdentity(ctx)); defaults != nil {
			sections = FlexStringSlice(defaults)
		}
	}

	all := len(sections) == 0
	has := map[string]bool{}
	for _, sec := range sections {
		has[sec] = true
	}

	var wg sync.WaitGroup
	runSection := func(name string, fn func(context.Context)) {
		if all || has[name] {
			wg.Go(func() {
				secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
				defer cancel()
				fn(secCtx)
			})
		}
	}

	runSection("tasks", func(c context.Context) { s.fillMorningTasks(c, date, out) })
	runSection("goals", func(c context.Context) { s.fillGoals(c, out) })
	runSection("hypotheses", func(c context.Context) { s.fillHypotheses(c, out) })
	runSection("rss", func(c context.Context) { s.fillRSSHighlights(c, date, out) })
	runSection("content_pipeline", func(c context.Context) { s.fillContentPipeline(c, out) })
	wg.Wait()
}

func (s *Server) fillMorningTasks(ctx context.Context, date time.Time, out *BriefOutput) {
	if rows, err := s.todos.OverdueItems(ctx, date); err == nil {
		out.OverdueTodos = rows
	} else {
		s.logger.Warn("brief: overdue todo items", "error", err)
	}

	if rows, err := s.todos.ItemsDueOn(ctx, date); err == nil {
		out.TodayTodos = rows
	} else {
		s.logger.Warn("brief: today todo items", "error", err)
	}

	if items, err := s.dayplan.ItemsByDate(ctx, date); err == nil {
		out.CommittedTodos = items
	} else {
		s.logger.Warn("brief: committed todo items", "error", err)
	}

	weekEnd := date.AddDate(0, 0, 7)
	if rows, err := s.todos.ItemsDueInRange(ctx, date, weekEnd); err == nil {
		out.UpcomingTodos = rows
	} else {
		s.logger.Warn("brief: upcoming todo items", "error", err)
	}

	// Yesterday's unfinished plan items surface as overdue.
	yesterday := date.AddDate(0, 0, -1)
	if items, err := s.dayplan.ItemsByDate(ctx, yesterday); err == nil {
		for i := range items {
			if items[i].Status == daily.StatusPlanned {
				out.OverdueTodos = append(out.OverdueTodos, planItemToPendingDetail(&items[i]))
			}
		}
	}
}

func (s *Server) fillGoals(ctx context.Context, out *BriefOutput) {
	if goals, err := s.goals.ActiveGoals(ctx); err == nil {
		out.ActiveGoals = goals
	} else {
		s.logger.Warn("brief: active goals", "error", err)
	}
}

func (s *Server) fillHypotheses(ctx context.Context, out *BriefOutput) {
	if recs, err := s.hypotheses.Unverified(ctx, 10); err == nil {
		out.UnverifiedHypotheses = recs
	} else {
		s.logger.Warn("brief: unverified hypotheses", "error", err)
	}
}

func (s *Server) fillRSSHighlights(ctx context.Context, date time.Time, out *BriefOutput) {
	if s.feedEntries == nil {
		return
	}
	since := date.AddDate(0, 0, -2)
	items, err := s.feedEntries.HighPriorityRecent(ctx, since, 10)
	if err != nil {
		s.logger.Warn("brief: rss highlights", "error", err)
		return
	}
	for i := range items {
		out.RSSHighlights = append(out.RSSHighlights, RSSHighlight{
			Title:     items[i].Title,
			URL:       items[i].SourceURL,
			FeedName:  items[i].FeedName,
			CreatedAt: items[i].CollectedAt.Format(time.RFC3339),
		})
	}
}

func (s *Server) fillContentPipeline(ctx context.Context, out *BriefOutput) {
	var all []content.Content
	if drafts, err := s.contents.ByStatus(ctx, string(content.StatusDraft), 20); err == nil {
		all = append(all, drafts...)
	} else {
		s.logger.Warn("brief: content pipeline drafts", "error", err)
	}
	if reviews, err := s.contents.ByStatus(ctx, string(content.StatusReview), 20); err == nil {
		all = append(all, reviews...)
	} else {
		s.logger.Warn("brief: content pipeline reviews", "error", err)
	}
	out.ContentPipeline = toContentSummaries(all)
}

// fillBriefReflection populates the reflection fields: the day's plan items
// plus plan-vs-actual counts. Completion is derived from each planned todo's
// CURRENT state (done -> completed, someday -> deferred, anything else ->
// still planned), not the daily_plan_item.status column, which has no write
// path. It references ZERO agent_notes — the former reflection_context
// today_notes / today_plan sections are dropped.
func (s *Server) fillBriefReflection(ctx context.Context, date time.Time, out *BriefOutput) {
	out.PlannedItems = []daily.Item{}

	items, err := s.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		s.logger.Warn("brief: reflection plan items", "error", err)
		return
	}
	out.PlannedItems = items
	for i := range items {
		switch items[i].TodoState {
		case string(todo.StateDone):
			out.CompletedCount++
		case string(todo.StateSomeday):
			out.DeferredCount++
		default:
			out.PlannedCount++
		}
	}
	if total := len(items); total > 0 {
		out.CompletionRate = float64(out.CompletedCount) / float64(total)
	}
}

func planItemToPendingDetail(item *daily.Item) todo.PendingDetail {
	return todo.PendingDetail{
		ID:           item.TodoID,
		Title:        item.TodoTitle,
		State:        todo.State(item.TodoState),
		Due:          item.TodoDue,
		Energy:       item.TodoEnergy,
		Priority:     item.TodoPriority,
		ProjectTitle: item.ProjectTitle,
		ProjectSlug:  item.ProjectSlug,
		CreatedAt:    item.CreatedAt,
		UpdatedAt:    item.UpdatedAt,
	}
}

func toContentSummaries(contents []content.Content) []ContentSummary {
	summaries := make([]ContentSummary, len(contents))
	for i := range contents {
		c := &contents[i]
		summaries[i] = ContentSummary{
			ID:        c.ID.String(),
			Title:     c.Title,
			Type:      string(c.Type),
			Status:    string(c.Status),
			UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
		}
	}
	return summaries
}
