package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/directive"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/insight"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// sectionTimeout is the per-section timeout for morning_context queries.
// Individual sections that exceed this timeout are skipped with a warning,
// rather than causing the entire morning_context call to fail.
const sectionTimeout = 15 * time.Second

// --- morning_context ---

// MorningContextInput is the input for the morning_context tool.
type MorningContextInput struct {
	Sections FlexStringSlice `json:"sections,omitempty" jsonschema_description:"Sections to include (default all). Valid: tasks, goals, directives, insights, rss, plan_history"`
	Date     *string         `json:"date,omitempty" jsonschema_description:"Target date YYYY-MM-DD (default: today)"`
}

// MorningContextOutput is the output of the morning_context tool.
type MorningContextOutput struct {
	Date               string                   `json:"date"`
	OverdueTasks       []task.PendingTaskDetail `json:"overdue_tasks"`
	TodayTasks         []task.PendingTaskDetail `json:"today_tasks"`
	CommittedTasks     []daily.Item             `json:"committed_tasks"`
	UpcomingTasks      []task.PendingTaskDetail `json:"upcoming_tasks"`
	ActiveGoals        []goal.ActiveGoalSummary `json:"active_goals"`
	DirectivesReceived []directive.Directive    `json:"directives_received"`
	DirectivesIssued   []directive.Directive    `json:"directives_issued"`
	UnverifiedInsights []insight.Insight        `json:"unverified_insights"`
	RSSHighlights      []RSSHighlight           `json:"rss_highlights"`
	PlanHistory        []journal.Entry          `json:"plan_history"`
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

	out := MorningContextOutput{Date: date.Format(time.DateOnly)}
	s.fillMorningSections(ctx, date, input.Sections, &out)
	return nil, out, nil
}

func (s *Server) fillMorningSections(ctx context.Context, date time.Time, requested FlexStringSlice, out *MorningContextOutput) {
	all := len(requested) == 0
	has := map[string]bool{}
	for _, sec := range requested {
		has[sec] = true
	}

	// Each section writes to disjoint fields in out, so no mutex needed.
	// Per-section timeout prevents one slow query from blocking the rest.
	var wg sync.WaitGroup
	if all || has["tasks"] {
		wg.Go(func() {
			secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
			defer cancel()
			s.fillMorningTasks(secCtx, date, out)
		})
	}
	if all || has["goals"] {
		wg.Go(func() {
			secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
			defer cancel()
			s.fillGoals(secCtx, out)
		})
	}
	if all || has["directives"] {
		wg.Go(func() {
			secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
			defer cancel()
			s.fillDirectives(secCtx, out)
		})
	}
	if all || has["insights"] {
		wg.Go(func() {
			secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
			defer cancel()
			s.fillInsights(secCtx, out)
		})
	}
	if all || has["rss"] {
		wg.Go(func() {
			secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
			defer cancel()
			s.fillRSSHighlights(secCtx, date, out)
		})
	}
	if all || has["plan_history"] {
		wg.Go(func() {
			secCtx, cancel := context.WithTimeout(ctx, sectionTimeout)
			defer cancel()
			s.fillPlanHistory(secCtx, date, out)
		})
	}
	wg.Wait()
}

func (s *Server) fillMorningTasks(ctx context.Context, date time.Time, out *MorningContextOutput) {
	if rows, err := s.tasks.OverdueTasks(ctx, date); err == nil {
		out.OverdueTasks = rows
	} else {
		s.logger.Warn("morning_context: overdue tasks", "error", err)
	}

	if rows, err := s.tasks.TasksDueOn(ctx, date); err == nil {
		out.TodayTasks = rows
	} else {
		s.logger.Warn("morning_context: today tasks", "error", err)
	}

	if items, err := s.dayplan.ItemsByDate(ctx, date); err == nil {
		out.CommittedTasks = items
	} else {
		s.logger.Warn("morning_context: committed tasks", "error", err)
	}

	weekEnd := date.AddDate(0, 0, 7)
	if rows, err := s.tasks.TasksDueInRange(ctx, date, weekEnd); err == nil {
		out.UpcomingTasks = rows
	} else {
		s.logger.Warn("morning_context: upcoming tasks", "error", err)
	}

	// Yesterday's unfinished plan items surface as overdue.
	yesterday := date.AddDate(0, 0, -1)
	if items, err := s.dayplan.ItemsByDate(ctx, yesterday); err == nil {
		for i := range items {
			if items[i].Status == daily.StatusPlanned {
				out.OverdueTasks = append(out.OverdueTasks, planItemToTaskDetail(&items[i]))
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

func (s *Server) fillDirectives(ctx context.Context, out *MorningContextOutput) {
	caller := s.callerIdentity(ctx)

	// Received: directives targeting the caller (unacked + unresolved).
	if dirs, err := s.directives.UnackedForTarget(ctx, caller); err == nil {
		out.DirectivesReceived = append(out.DirectivesReceived, dirs...)
	} else {
		s.logger.Warn("morning_context: unacked directives received", "error", err)
	}
	if dirs, err := s.directives.UnresolvedForTarget(ctx, caller); err == nil {
		out.DirectivesReceived = append(out.DirectivesReceived, dirs...)
	} else {
		s.logger.Warn("morning_context: unresolved directives received", "error", err)
	}

	// Issued: directives the caller sent that are still open.
	if dirs, err := s.directives.UnackedIssuedBySource(ctx, caller); err == nil {
		out.DirectivesIssued = append(out.DirectivesIssued, dirs...)
	} else {
		s.logger.Warn("morning_context: unacked directives issued", "error", err)
	}
	if dirs, err := s.directives.UnresolvedIssuedBySource(ctx, caller); err == nil {
		out.DirectivesIssued = append(out.DirectivesIssued, dirs...)
	} else {
		s.logger.Warn("morning_context: unresolved directives issued", "error", err)
	}
}

func (s *Server) fillInsights(ctx context.Context, out *MorningContextOutput) {
	if ins, err := s.insights.Unverified(ctx, 10); err == nil {
		out.UnverifiedInsights = ins
	} else {
		s.logger.Warn("morning_context: unverified insights", "error", err)
	}
}

func (s *Server) fillPlanHistory(ctx context.Context, date time.Time, out *MorningContextOutput) {
	threeDaysAgo := date.AddDate(0, 0, -3)
	kind := string(journal.KindPlan)
	if entries, err := s.journal.EntriesByDateRange(ctx, threeDaysAgo, date, &kind, nil); err == nil {
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

func planItemToTaskDetail(item *daily.Item) task.PendingTaskDetail {
	return task.PendingTaskDetail{
		ID:           item.TaskID,
		Title:        item.TaskTitle,
		Status:       task.Status(item.TaskStatus),
		Due:          item.TaskDue,
		Energy:       item.TaskEnergy,
		Priority:     item.TaskPriority,
		Assignee:     item.TaskAssignee,
		ProjectTitle: item.ProjectTitle,
		ProjectSlug:  item.ProjectSlug,
		CreatedAt:    item.CreatedAt,
		UpdatedAt:    item.UpdatedAt,
	}
}
