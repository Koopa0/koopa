// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/todo"
)

// sectionTimeout is the per-section timeout for morning_context queries.
const sectionTimeout = 15 * time.Second

// defaultSectionsByAgent maps a caller agent name to the morning_context
// sections it gets when the caller doesn't supply `sections` explicitly.
// Callers not listed here keep the historical "all sections" default.
// Explicit `sections` always wins over this map.
//
// This exists because callers like learning-studio routinely paid the
// token cost of unrelated sections (e.g. 10 Google Developers Blog RSS
// items) before learning to pass an explicit sections list. The map is
// the single auditable point where per-agent defaults live — DO NOT
// scatter the per-agent override logic across the section fillers.
// Section names must match the runSection labels in fillMorningSections.
var defaultSectionsByAgent = map[string][]string{
	"learning-studio": {"tasks", "pending_tasks", "hypotheses", "plan_history"},
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

// --- morning_context ---

// MorningContextInput is the input for the morning_context tool.
//
// Sections is a STRICT filter: when non-empty, only the listed groups
// are populated and every other response field stays at its empty-slice
// default. Omit Sections (or pass an empty list) to populate every
// group — that is the typical morning-briefing call.
//
// Group → response field mapping:
//
//	"tasks"            → overdue_todos, today_todos, committed_todos, upcoming_todos
//	"goals"            → active_goals
//	"pending_tasks"    → pending_tasks_received, pending_tasks_issued
//	"hypotheses"       → unverified_hypotheses
//	"rss"              → rss_highlights
//	"plan_history"     → plan_history
//	"content_pipeline" → content_pipeline
//
// Unknown group names are ignored silently (no error, no warning).
type MorningContextInput struct {
	Sections FlexStringSlice `json:"sections,omitempty" jsonschema_description:"Strict filter on which groups to populate (default: all). Omit or pass [] to get the full briefing. Group key → response fields populated: 'tasks' → overdue_todos/today_todos/committed_todos/upcoming_todos; 'goals' → active_goals; 'pending_tasks' → pending_tasks_received/pending_tasks_issued; 'hypotheses' → unverified_hypotheses; 'rss' → rss_highlights; 'plan_history' → plan_history; 'content_pipeline' → content_pipeline. Unknown keys silently ignored. Non-listed groups stay [] so JSON shape is stable across calls."`
	Date     *string         `json:"date,omitempty" jsonschema_description:"Target date YYYY-MM-DD (default: today)"`
}

// MorningContextOutput is the output of the morning_context tool.
type MorningContextOutput struct {
	Date                 string                   `json:"date"`
	OverdueTodos         []todo.PendingDetail     `json:"overdue_todos"`
	TodayTodos           []todo.PendingDetail     `json:"today_todos"`
	CommittedTodos       []daily.Item             `json:"committed_todos"`
	UpcomingTodos        []todo.PendingDetail     `json:"upcoming_todos"`
	ActiveGoals          []goal.ActiveGoalSummary `json:"active_goals"`
	PendingTasksReceived []task.Task              `json:"pending_tasks_received"`
	PendingTasksIssued   []task.Task              `json:"pending_tasks_issued"`
	UnverifiedHypotheses []hypothesis.Record      `json:"unverified_hypotheses"`
	RSSHighlights        []RSSHighlight           `json:"rss_highlights"`
	PlanHistory          []agentnote.Note         `json:"plan_history"`
	ContentPipeline      []ContentSummary         `json:"content_pipeline"`
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

func (s *Server) morningContext(ctx context.Context, _ *mcp.CallToolRequest, input MorningContextInput) (*mcp.CallToolResult, MorningContextOutput, error) {
	date := s.today()
	if input.Date != nil && *input.Date != "" {
		t, err := time.Parse(time.DateOnly, *input.Date)
		if err != nil {
			return nil, MorningContextOutput{}, err
		}
		date = t
	}

	// If the caller omitted sections, consult the per-agent allowlist
	// before falling through to "all sections". Explicit input.Sections
	// always wins. Resolved here (not inside fillMorningSections) so the
	// dispatcher sees a uniform shape — caller-aware behavior is
	// contained to this one site.
	sections := input.Sections
	if len(sections) == 0 {
		if defaults := resolveDefaultSections(s.callerIdentity(ctx)); defaults != nil {
			sections = FlexStringSlice(defaults)
		}
	}

	// Initialize every list field to empty slice so that JSON marshalling
	// always emits []. Sections that are not requested (or that fail to
	// load) leave their field as the zero-length slice rather than null —
	// the json-api rule requires lists to be [] not null.
	out := MorningContextOutput{
		Date:                 date.Format(time.DateOnly),
		OverdueTodos:         []todo.PendingDetail{},
		TodayTodos:           []todo.PendingDetail{},
		CommittedTodos:       []daily.Item{},
		UpcomingTodos:        []todo.PendingDetail{},
		ActiveGoals:          []goal.ActiveGoalSummary{},
		PendingTasksReceived: []task.Task{},
		PendingTasksIssued:   []task.Task{},
		UnverifiedHypotheses: []hypothesis.Record{},
		RSSHighlights:        []RSSHighlight{},
		PlanHistory:          []agentnote.Note{},
		ContentPipeline:      []ContentSummary{},
	}
	s.fillMorningSections(ctx, date, sections, &out)
	return nil, out, nil
}

func (s *Server) fillMorningSections(ctx context.Context, date time.Time, requested FlexStringSlice, out *MorningContextOutput) {
	all := len(requested) == 0
	has := map[string]bool{}
	for _, sec := range requested {
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
	runSection("pending_tasks", func(c context.Context) { s.fillPendingTasks(c, out) })
	runSection("hypotheses", func(c context.Context) { s.fillHypotheses(c, out) })
	runSection("rss", func(c context.Context) { s.fillRSSHighlights(c, date, out) })
	runSection("plan_history", func(c context.Context) { s.fillPlanHistory(c, date, out) })
	runSection("content_pipeline", func(c context.Context) { s.fillContentPipeline(c, out) })
	wg.Wait()
}

func (s *Server) fillMorningTasks(ctx context.Context, date time.Time, out *MorningContextOutput) {
	if rows, err := s.todos.OverdueItems(ctx, date); err == nil {
		out.OverdueTodos = rows
	} else {
		s.logger.Warn("morning_context: overdue todo items", "error", err)
	}

	if rows, err := s.todos.ItemsDueOn(ctx, date); err == nil {
		out.TodayTodos = rows
	} else {
		s.logger.Warn("morning_context: today todo items", "error", err)
	}

	if items, err := s.dayplan.ItemsByDate(ctx, date); err == nil {
		out.CommittedTodos = items
	} else {
		s.logger.Warn("morning_context: committed todo items", "error", err)
	}

	weekEnd := date.AddDate(0, 0, 7)
	if rows, err := s.todos.ItemsDueInRange(ctx, date, weekEnd); err == nil {
		out.UpcomingTodos = rows
	} else {
		s.logger.Warn("morning_context: upcoming todo items", "error", err)
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

func (s *Server) fillGoals(ctx context.Context, out *MorningContextOutput) {
	if goals, err := s.goals.ActiveGoals(ctx); err == nil {
		out.ActiveGoals = goals
	} else {
		s.logger.Warn("morning_context: active goals", "error", err)
	}
}

func (s *Server) fillPendingTasks(ctx context.Context, out *MorningContextOutput) {
	caller := s.callerIdentity(ctx)
	const limit = 20

	if received, err := s.tasks.OpenForAssignee(ctx, caller, limit); err == nil {
		out.PendingTasksReceived = received
	} else {
		s.logger.Warn("morning_context: pending tasks received", "error", err)
	}

	if issued, err := s.tasks.OpenForCreator(ctx, caller, limit); err == nil {
		out.PendingTasksIssued = issued
	} else {
		s.logger.Warn("morning_context: pending tasks issued", "error", err)
	}
}

func (s *Server) fillHypotheses(ctx context.Context, out *MorningContextOutput) {
	if recs, err := s.hypotheses.Unverified(ctx, 10); err == nil {
		out.UnverifiedHypotheses = recs
	} else {
		s.logger.Warn("morning_context: unverified hypotheses", "error", err)
	}
}

func (s *Server) fillPlanHistory(ctx context.Context, date time.Time, out *MorningContextOutput) {
	threeDaysAgo := date.AddDate(0, 0, -3)
	planKind := agentnote.KindPlan
	if entries, err := s.agentNotes.NotesInRange(ctx, threeDaysAgo, date, &planKind, nil); err == nil {
		out.PlanHistory = entries
	} else {
		s.logger.Warn("morning_context: plan history", "error", err)
	}
}

func (s *Server) fillRSSHighlights(ctx context.Context, date time.Time, out *MorningContextOutput) {
	if s.feedEntries == nil {
		return
	}
	since := date.AddDate(0, 0, -2)
	items, err := s.feedEntries.HighPriorityRecent(ctx, since, 10)
	if err != nil {
		s.logger.Warn("morning_context: rss highlights", "error", err)
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

func (s *Server) fillContentPipeline(ctx context.Context, out *MorningContextOutput) {
	var all []content.Content
	if drafts, err := s.contents.ByStatus(ctx, string(content.StatusDraft), 20); err == nil {
		all = append(all, drafts...)
	} else {
		s.logger.Warn("morning_context: content pipeline drafts", "error", err)
	}
	if reviews, err := s.contents.ByStatus(ctx, string(content.StatusReview), 20); err == nil {
		all = append(all, reviews...)
	} else {
		s.logger.Warn("morning_context: content pipeline reviews", "error", err)
	}
	out.ContentPipeline = toContentSummaries(all)
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
