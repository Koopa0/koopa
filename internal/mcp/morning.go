package mcp

import (
	"context"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// --- morning_context ---

// MorningContextInput is the input for the morning_context tool.
type MorningContextInput struct {
	Sections FlexStringSlice `json:"sections,omitempty" jsonschema_description:"Sections to include (default all). Valid: tasks, plan_history"`
	Date     *string         `json:"date,omitempty" jsonschema_description:"Target date YYYY-MM-DD (default: today)"`
}

// MorningContextOutput is the output of the morning_context tool.
type MorningContextOutput struct {
	Date           string                   `json:"date"`
	OverdueTasks   []task.PendingTaskDetail `json:"overdue_tasks"`
	TodayTasks     []task.PendingTaskDetail `json:"today_tasks"`
	CommittedTasks []daily.Item             `json:"committed_tasks"`
	UpcomingTasks  []task.PendingTaskDetail `json:"upcoming_tasks"`
	PlanHistory    []journal.Entry          `json:"plan_history"`
	// Phase 2 will add: active_goals, unacked_directives, pending_reports, unverified_insights
	// Phase 4 will add: rss_highlights
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

	sections := map[string]bool{}
	if len(input.Sections) == 0 {
		sections["tasks"] = true
		sections["plan_history"] = true
	} else {
		for _, s := range input.Sections {
			sections[s] = true
		}
	}

	out := MorningContextOutput{Date: date.Format(time.DateOnly)}

	if sections["tasks"] {
		s.fillMorningTasks(ctx, date, &out)
	}
	if sections["plan_history"] {
		s.fillPlanHistory(ctx, date, &out)
	}

	return nil, out, nil
}

func (s *Server) fillMorningTasks(ctx context.Context, date time.Time, out *MorningContextOutput) {
	// Overdue tasks
	if rows, err := s.tasks.OverdueTasks(ctx, date); err == nil {
		out.OverdueTasks = rows
	} else {
		s.logger.Warn("morning_context: overdue tasks", "error", err)
	}

	// Today's tasks (due today, not yet in plan)
	if rows, err := s.tasks.TasksDueOn(ctx, date); err == nil {
		out.TodayTasks = rows
	} else {
		s.logger.Warn("morning_context: today tasks", "error", err)
	}

	// Committed daily plan items
	if items, err := s.dayplan.ItemsByDate(ctx, date); err == nil {
		out.CommittedTasks = items
	} else {
		s.logger.Warn("morning_context: committed tasks", "error", err)
	}

	// Upcoming tasks (next 7 days)
	weekEnd := date.AddDate(0, 0, 7)
	if rows, err := s.tasks.TasksDueInRange(ctx, date, weekEnd); err == nil {
		out.UpcomingTasks = rows
	} else {
		s.logger.Warn("morning_context: upcoming tasks", "error", err)
	}

	// Yesterday's unfinished plan items
	yesterday := date.AddDate(0, 0, -1)
	if items, err := s.dayplan.ItemsByDate(ctx, yesterday); err == nil {
		var unfinished []daily.Item
		for i := range items {
			if items[i].Status == daily.StatusPlanned {
				unfinished = append(unfinished, items[i])
			}
		}
		if len(unfinished) > 0 {
			out.OverdueTasks = append(out.OverdueTasks, convertPlanItemsToTaskDetails(unfinished)...)
		}
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

func convertPlanItemsToTaskDetails(items []daily.Item) []task.PendingTaskDetail {
	result := make([]task.PendingTaskDetail, len(items))
	for i := range items {
		result[i] = task.PendingTaskDetail{
			ID:           items[i].TaskID,
			Title:        items[i].TaskTitle,
			Status:       task.Status(items[i].TaskStatus),
			Due:          items[i].TaskDue,
			Energy:       items[i].TaskEnergy,
			Priority:     items[i].TaskPriority,
			Assignee:     items[i].TaskAssignee,
			ProjectTitle: items[i].ProjectTitle,
			ProjectSlug:  items[i].ProjectSlug,
		}
	}
	return result
}
