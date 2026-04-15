package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa0.dev/internal/agent/note"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/hypothesis"
	"github.com/Koopa0/koopa0.dev/internal/todo"
)

// sectionTimeout is the per-section timeout for morning_context queries.
const sectionTimeout = 15 * time.Second

// --- morning_context ---
//
// TODO(coordination-rebuild): the directives section currently returns
// empty arrays because the old directive.Store is gone and internal/task
// (coordination) doesn't exist yet. The follow-up PR restores this by
// calling task.Store.Summarize with filters for target == caller (received)
// and source == caller (issued) over open states.

// MorningContextInput is the input for the morning_context tool.
type MorningContextInput struct {
	Sections FlexStringSlice `json:"sections,omitempty" jsonschema_description:"Sections to include (default all). Valid: tasks, goals, directives, insights, rss, plan_history, content_pipeline"`
	Date     *string         `json:"date,omitempty" jsonschema_description:"Target date YYYY-MM-DD (default: today)"`
}

// DirectiveStub is the placeholder shape returned by the directives section
// during the coordination rebuild. Empty struct — clients should treat the
// directives arrays as "no data yet", not "endpoint removed".
type DirectiveStub struct{}

// MorningContextOutput is the output of the morning_context tool.
type MorningContextOutput struct {
	Date               string                   `json:"date"`
	OverdueTasks       []todo.PendingDetail     `json:"overdue_tasks"`
	TodayTasks         []todo.PendingDetail     `json:"today_tasks"`
	CommittedTasks     []daily.Item             `json:"committed_tasks"`
	UpcomingTasks      []todo.PendingDetail     `json:"upcoming_tasks"`
	ActiveGoals        []goal.ActiveGoalSummary `json:"active_goals"`
	DirectivesReceived []DirectiveStub          `json:"directives_received"`
	DirectivesIssued   []DirectiveStub          `json:"directives_issued"`
	UnverifiedInsights []hypothesis.Record      `json:"unverified_insights"`
	RSSHighlights      []RSSHighlight           `json:"rss_highlights"`
	PlanHistory        []agentnote.Note        `json:"plan_history"`
	ContentPipeline    []ContentSummary         `json:"content_pipeline"`
}

// RSSHighlight is a recent high-priority RSS item.
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

	out := MorningContextOutput{
		Date:               date.Format(time.DateOnly),
		DirectivesReceived: []DirectiveStub{},
		DirectivesIssued:   []DirectiveStub{},
	}
	s.fillMorningSections(ctx, date, input.Sections, &out)
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
	// directives intentionally omitted — stubs are empty arrays (see MorningContextOutput).
	runSection("insights", func(c context.Context) { s.fillInsights(c, out) })
	runSection("rss", func(c context.Context) { s.fillRSSHighlights(c, date, out) })
	runSection("plan_history", func(c context.Context) { s.fillPlanHistory(c, date, out) })
	runSection("content_pipeline", func(c context.Context) { s.fillContentPipeline(c, out) })
	wg.Wait()
}

func (s *Server) fillMorningTasks(ctx context.Context, date time.Time, out *MorningContextOutput) {
	if rows, err := s.todos.OverdueItems(ctx, date); err == nil {
		out.OverdueTasks = rows
	} else {
		s.logger.Warn("morning_context: overdue todo items", "error", err)
	}

	if rows, err := s.todos.ItemsDueOn(ctx, date); err == nil {
		out.TodayTasks = rows
	} else {
		s.logger.Warn("morning_context: today todo items", "error", err)
	}

	if items, err := s.dayplan.ItemsByDate(ctx, date); err == nil {
		out.CommittedTasks = items
	} else {
		s.logger.Warn("morning_context: committed todo items", "error", err)
	}

	weekEnd := date.AddDate(0, 0, 7)
	if rows, err := s.todos.ItemsDueInRange(ctx, date, weekEnd); err == nil {
		out.UpcomingTasks = rows
	} else {
		s.logger.Warn("morning_context: upcoming todo items", "error", err)
	}

	// Yesterday's unfinished plan items surface as overdue.
	yesterday := date.AddDate(0, 0, -1)
	if items, err := s.dayplan.ItemsByDate(ctx, yesterday); err == nil {
		for i := range items {
			if items[i].Status == daily.StatusPlanned {
				out.OverdueTasks = append(out.OverdueTasks, planItemToPendingDetail(&items[i]))
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

func (s *Server) fillInsights(ctx context.Context, out *MorningContextOutput) {
	if recs, err := s.hypotheses.Unverified(ctx, 10); err == nil {
		out.UnverifiedInsights = recs
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
		Assignee:     item.TodoAssignee,
		ProjectTitle: item.ProjectTitle,
		ProjectSlug:  item.ProjectSlug,
		CreatedAt:    item.CreatedAt,
		UpdatedAt:    item.UpdatedAt,
	}
}
