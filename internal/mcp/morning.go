package mcp

import (
	"context"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/directive"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/insight"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// --- morning_context ---

// MorningContextInput is the input for the morning_context tool.
type MorningContextInput struct {
	Sections FlexStringSlice `json:"sections,omitempty" jsonschema_description:"Sections to include (default all). Valid: tasks, goals, directives, insights, plan_history"`
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
	UnackedDirectives  []directive.Directive    `json:"unacked_directives"`
	UnverifiedInsights []insight.Insight        `json:"unverified_insights"`
	PlanHistory        []journal.Entry          `json:"plan_history"`
}

func (s *Server) morningContext(ctx context.Context, _ *sdkmcp.CallToolRequest, input MorningContextInput) (*sdkmcp.CallToolResult, MorningContextOutput, error) {
	date := s.today()
	if input.Date != nil && *input.Date != "" {
		t, err := time.Parse(time.DateOnly, *input.Date)
		if err != nil {
			return nil, MorningContextOutput{}, err
		}
		date = t
	}

	all := len(input.Sections) == 0
	sections := map[string]bool{}
	for _, sec := range input.Sections {
		sections[sec] = true
	}

	out := MorningContextOutput{Date: date.Format(time.DateOnly)}

	if all || sections["tasks"] {
		s.fillMorningTasks(ctx, date, &out)
	}
	if all || sections["goals"] {
		s.fillGoals(ctx, &out)
	}
	if all || sections["directives"] {
		s.fillDirectives(ctx, &out)
	}
	if all || sections["insights"] {
		s.fillInsights(ctx, &out)
	}
	if all || sections["plan_history"] {
		s.fillPlanHistory(ctx, date, &out)
	}

	return nil, out, nil
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
	if dirs, err := s.directives.UnackedForTarget(ctx, s.participant); err == nil {
		out.UnackedDirectives = dirs
	} else {
		s.logger.Warn("morning_context: unacked directives", "error", err)
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
	}
}
