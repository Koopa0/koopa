package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// --- advance_work ---

// AdvanceWorkInput is the input for the advance_work tool.
type AdvanceWorkInput struct {
	TaskID   string  `json:"task_id" jsonschema:"required" jsonschema_description:"Task UUID"`
	Action   string  `json:"action" jsonschema:"required" jsonschema_description:"Action: clarify (inbox→todo), start (todo→in-progress), complete (→done), defer (→someday)"`
	Project  string  `json:"project,omitempty" jsonschema_description:"Project UUID (for clarify action)"`
	Due      *string `json:"due,omitempty" jsonschema_description:"Due date YYYY-MM-DD (for clarify action)"`
	Priority *string `json:"priority,omitempty" jsonschema_description:"Priority: high, medium, low (for clarify action)"`
	Energy   *string `json:"energy,omitempty" jsonschema_description:"Energy: high, medium, low (for clarify action)"`
}

// AdvanceWorkOutput is the output of the advance_work tool.
type AdvanceWorkOutput struct {
	Task              task.Task `json:"task"`
	PlanItemUpdated   bool      `json:"plan_item_updated,omitempty"`
	RecurringAdvanced bool      `json:"recurring_advanced,omitempty"`
	NextDue           *string   `json:"next_due,omitempty"`
}

func (s *Server) advanceWork(ctx context.Context, _ *sdkmcp.CallToolRequest, input AdvanceWorkInput) (*sdkmcp.CallToolResult, AdvanceWorkOutput, error) {
	taskID, err := uuid.Parse(input.TaskID)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("invalid task_id: %w", err)
	}

	// Fetch current task to validate state transition.
	current, err := s.tasks.TaskByID(ctx, taskID)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("task not found: %w", err)
	}

	if err := validateTransition(current.Status, input.Action); err != nil {
		return nil, AdvanceWorkOutput{}, err
	}

	switch input.Action {
	case "clarify":
		return s.advanceClarify(ctx, taskID, input)
	case "start":
		return s.advanceTransition(ctx, taskID, task.StatusInProgress)
	case "complete":
		return s.advanceComplete(ctx, taskID)
	case "defer":
		return s.advanceTransition(ctx, taskID, task.StatusSomeday)
	default:
		return nil, AdvanceWorkOutput{}, fmt.Errorf("invalid action %q (valid: clarify, start, complete, defer)", input.Action)
	}
}

// validateTransition checks if the action is valid for the current task status.
func validateTransition(current task.Status, action string) error {
	valid := map[task.Status][]string{
		task.StatusInbox:      {"clarify", "defer"},
		task.StatusTodo:       {"start", "complete", "defer"},
		task.StatusInProgress: {"complete", "defer"},
		task.StatusSomeday:    {"clarify", "start"},
		// done tasks cannot be transitioned
	}
	allowed, ok := valid[current]
	if !ok {
		return fmt.Errorf("task status %q does not support transitions", current)
	}
	for _, a := range allowed {
		if a == action {
			return nil
		}
	}
	return fmt.Errorf("cannot %q a task in %q status (allowed: %v)", action, current, allowed)
}

func (s *Server) advanceClarify(ctx context.Context, taskID uuid.UUID, input AdvanceWorkInput) (*sdkmcp.CallToolResult, AdvanceWorkOutput, error) {
	params := &task.UpdateParams{ID: taskID}

	newStatus := task.StatusTodo
	params.Status = &newStatus

	if input.Due != nil && *input.Due != "" {
		t, err := time.Parse(time.DateOnly, *input.Due)
		if err != nil {
			return nil, AdvanceWorkOutput{}, fmt.Errorf("invalid due date: %w", err)
		}
		params.Due = &t
	}
	params.Priority = input.Priority
	params.Energy = input.Energy

	if input.Project != "" {
		id, err := uuid.Parse(input.Project)
		if err == nil {
			params.ProjectID = &id
		}
	}

	updated, err := s.tasks.Update(ctx, params)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("clarifying task: %w", err)
	}

	s.logger.Info("advance_work", "action", "clarify", "task_id", taskID)
	return nil, AdvanceWorkOutput{Task: *updated}, nil
}

func (s *Server) advanceTransition(ctx context.Context, taskID uuid.UUID, status task.Status) (*sdkmcp.CallToolResult, AdvanceWorkOutput, error) {
	updated, err := s.tasks.UpdateStatus(ctx, taskID, status)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("transitioning task to %s: %w", status, err)
	}

	s.logger.Info("advance_work", "action", string(status), "task_id", taskID)
	return nil, AdvanceWorkOutput{Task: *updated}, nil
}

func (s *Server) advanceComplete(ctx context.Context, taskID uuid.UUID) (*sdkmcp.CallToolResult, AdvanceWorkOutput, error) {
	updated, err := s.tasks.UpdateStatus(ctx, taskID, task.StatusDone)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("completing task: %w", err)
	}

	out := AdvanceWorkOutput{Task: *updated}

	// Side effect: update today's daily_plan_item if exists.
	today := s.today()
	if completeErr := s.dayplan.CompleteByTask(ctx, taskID, today); completeErr == nil {
		out.PlanItemUpdated = true
	}

	// Side effect: handle recurring task.
	if updated.IsRecurring() {
		tomorrow := today.AddDate(0, 0, 1)
		nextDue := updated.NextCycleDateOnOrAfter(tomorrow)
		if nextDue != nil {
			resetted, resetErr := s.tasks.ResetRecurring(ctx, taskID, *nextDue)
			if resetErr == nil {
				out.Task = *resetted
				out.RecurringAdvanced = true
				d := nextDue.Format(time.DateOnly)
				out.NextDue = &d
			}
		}
	}

	s.logger.Info("advance_work", "action", "complete", "task_id", taskID,
		"recurring", out.RecurringAdvanced, "plan_item_updated", out.PlanItemUpdated)
	return nil, out, nil
}

// --- plan_day ---

// PlanDayInput is the input for the plan_day tool.
type PlanDayInput struct {
	Date      *string       `json:"date,omitempty" jsonschema_description:"Plan date YYYY-MM-DD (default: today)"`
	Items     []PlanDayItem `json:"items" jsonschema:"required" jsonschema_description:"Tasks to plan for the day"`
	JournalID *FlexInt      `json:"journal_id,omitempty" jsonschema_description:"Optional journal entry ID that drove this planning session"`
}

// PlanDayItem is a single item in the plan_day input.
type PlanDayItem struct {
	TaskID   string `json:"task_id" jsonschema:"required" jsonschema_description:"Task UUID"`
	Position int    `json:"position,omitempty" jsonschema_description:"Position in plan (0-based, lower = higher priority)"`
}

// PlanDayOutput is the output of the plan_day tool.
type PlanDayOutput struct {
	Date         string       `json:"date"`
	ItemsCreated int          `json:"items_created"`
	Items        []daily.Item `json:"items"`
}

func (s *Server) planDay(ctx context.Context, _ *sdkmcp.CallToolRequest, input PlanDayInput) (*sdkmcp.CallToolResult, PlanDayOutput, error) {
	if len(input.Items) == 0 {
		return nil, PlanDayOutput{}, fmt.Errorf("items is required (at least one task)")
	}

	date := s.today()
	if input.Date != nil && *input.Date != "" {
		t, err := time.Parse(time.DateOnly, *input.Date)
		if err != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("invalid date: %w", err)
		}
		date = t
	}

	// Delete existing planned items for this date (idempotent re-plan).
	if err := s.dayplan.DeletePlannedByDate(ctx, date); err != nil {
		return nil, PlanDayOutput{}, fmt.Errorf("clearing existing plan: %w", err)
	}

	var journalID *int64
	if input.JournalID != nil {
		v := int64(*input.JournalID)
		journalID = &v
	}

	var created []daily.Item
	for i, item := range input.Items {
		taskID, err := uuid.Parse(item.TaskID)
		if err != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("invalid task_id at position %d: %w", i, err)
		}

		pos := item.Position
		if pos == 0 {
			pos = i
		}

		dpi, err := s.dayplan.Create(ctx, &daily.CreateItemParams{
			PlanDate:   date,
			TaskID:     taskID,
			SelectedBy: s.participant,
			Position:   int32(pos),
			JournalID:  journalID,
		})
		if err != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("creating plan item for task %s: %w", item.TaskID, err)
		}
		_ = dpi // raw item without task join
	}

	// Re-fetch with task details.
	items, err := s.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		return nil, PlanDayOutput{}, fmt.Errorf("fetching created plan items: %w", err)
	}
	created = items

	s.logger.Info("plan_day", "date", date.Format(time.DateOnly), "items", len(created))
	return nil, PlanDayOutput{
		Date:         date.Format(time.DateOnly),
		ItemsCreated: len(created),
		Items:        created,
	}, nil
}
