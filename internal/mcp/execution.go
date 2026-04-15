package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/todo"
)

// normalizePriority maps shorthand priority values to the DB enum.
// Accepts: high/medium/low (direct), p0/p1/p2/p3 (shorthand), h/m/l (abbreviation),
// and common synonyms (critical, urgent).
func normalizePriority(s string) string {
	switch s {
	case "high", "p0", "p1", "h", "critical", "urgent":
		return "high"
	case "medium", "p2", "m":
		return "medium"
	case "low", "p3", "l":
		return "low"
	default:
		return s
	}
}

// --- advance_work ---
//
// Operates on todo items (personal GTD), NOT on coordination tasks. The tool
// name stays advance_work so Cowork project instructions keep working, but
// internally it routes through internal/todo.

// AdvanceWorkInput is the input for the advance_work tool.
type AdvanceWorkInput struct {
	TaskID   string  `json:"task_id" jsonschema:"required" jsonschema_description:"Todo item UUID"`
	Action   string  `json:"action" jsonschema:"required" jsonschema_description:"Action: clarify (inbox→todo), start (todo→in_progress), complete (→done), defer (→someday)"`
	Project  string  `json:"project,omitempty" jsonschema_description:"Project UUID (for clarify action)"`
	Due      *string `json:"due,omitempty" jsonschema_description:"Due date YYYY-MM-DD (for clarify action)"`
	Priority *string `json:"priority,omitempty" jsonschema_description:"Priority: high, medium, low (for clarify action)"`
	Energy   *string `json:"energy,omitempty" jsonschema_description:"Energy: high, medium, low (for clarify action)"`
}

// AdvanceWorkOutput is the output of the advance_work tool.
type AdvanceWorkOutput struct {
	Task              todo.Item `json:"task"`
	PlanItemUpdated   bool      `json:"plan_item_updated,omitempty"`
	RecurringAdvanced bool      `json:"recurring_advanced,omitempty"`
	NextDue           *string   `json:"next_due,omitempty"`
}

func (s *Server) advanceWork(ctx context.Context, _ *mcp.CallToolRequest, input AdvanceWorkInput) (*mcp.CallToolResult, AdvanceWorkOutput, error) {
	itemID, err := uuid.Parse(input.TaskID)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("invalid task_id: %w", err)
	}

	current, err := s.todos.ItemByID(ctx, itemID)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("todo item not found: %w", err)
	}

	if err := validateTransition(current.State, input.Action); err != nil {
		return nil, AdvanceWorkOutput{}, err
	}

	switch input.Action {
	case "clarify":
		return s.advanceClarify(ctx, itemID, input)
	case "start":
		return s.advanceTransition(ctx, itemID, todo.StateInProgress)
	case "complete":
		return s.advanceComplete(ctx, itemID)
	case "defer":
		return s.advanceTransition(ctx, itemID, todo.StateSomeday)
	default:
		return nil, AdvanceWorkOutput{}, fmt.Errorf("invalid action %q (valid: clarify, start, complete, defer)", input.Action)
	}
}

// validateTransition checks if the action is valid for the current todo state.
func validateTransition(current todo.State, action string) error {
	valid := map[todo.State][]string{
		todo.StateInbox:      {"clarify", "defer"},
		todo.StateTodo:       {"start", "complete", "defer"},
		todo.StateInProgress: {"complete", "defer"},
		todo.StateSomeday:    {"clarify", "start"},
	}
	allowed, ok := valid[current]
	if !ok {
		return fmt.Errorf("todo state %q does not support transitions", current)
	}
	for _, a := range allowed {
		if a == action {
			return nil
		}
	}
	return fmt.Errorf("cannot %q a todo in %q state (allowed: %v)", action, current, allowed)
}

func (s *Server) advanceClarify(ctx context.Context, itemID uuid.UUID, input AdvanceWorkInput) (*mcp.CallToolResult, AdvanceWorkOutput, error) {
	params := &todo.UpdateParams{ID: itemID}

	newState := todo.StateTodo
	params.State = &newState

	if input.Due != nil && *input.Due != "" {
		t, err := time.Parse(time.DateOnly, *input.Due)
		if err != nil {
			return nil, AdvanceWorkOutput{}, fmt.Errorf("invalid due date: %w", err)
		}
		params.Due = &t
	}
	if input.Priority != nil {
		p := normalizePriority(*input.Priority)
		params.Priority = &p
	}
	params.Energy = input.Energy

	if input.Project != "" {
		params.ProjectID = s.resolveProjectID(ctx, input.Project)
	}

	updated, err := s.todos.Update(ctx, params)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("clarifying todo item: %w", err)
	}

	s.logger.Info("advance_work", "action", "clarify", "todo_id", itemID)
	return nil, AdvanceWorkOutput{Task: *updated}, nil
}

func (s *Server) advanceTransition(ctx context.Context, itemID uuid.UUID, state todo.State) (*mcp.CallToolResult, AdvanceWorkOutput, error) {
	updated, err := s.todos.UpdateState(ctx, itemID, state)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("transitioning todo item to %s: %w", state, err)
	}

	s.logger.Info("advance_work", "action", string(state), "todo_id", itemID)
	return nil, AdvanceWorkOutput{Task: *updated}, nil
}

func (s *Server) advanceComplete(ctx context.Context, itemID uuid.UUID) (*mcp.CallToolResult, AdvanceWorkOutput, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	txTodos := todo.NewStore(tx)
	txDayplan := daily.NewStore(tx)

	updated, err := txTodos.UpdateState(ctx, itemID, todo.StateDone)
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("completing todo item: %w", err)
	}

	out := AdvanceWorkOutput{Task: *updated}

	today := s.today()
	if wasUpdated, completeErr := txDayplan.CompleteByTodo(ctx, itemID, today); completeErr == nil {
		out.PlanItemUpdated = wasUpdated
	}

	if updated.IsRecurring() {
		tomorrow := today.AddDate(0, 0, 1)
		nextDue := updated.NextCycleDateOnOrAfter(tomorrow)
		if nextDue != nil {
			resetted, resetErr := txTodos.ResetRecurring(ctx, itemID, *nextDue)
			if resetErr == nil {
				out.Task = *resetted
				out.RecurringAdvanced = true
				d := nextDue.Format(time.DateOnly)
				out.NextDue = &d
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("committing todo completion: %w", err)
	}

	s.logger.Info("advance_work", "action", "complete", "todo_id", itemID,
		"recurring", out.RecurringAdvanced, "plan_item_updated", out.PlanItemUpdated)
	return nil, out, nil
}

// --- plan_day ---

// PlanDayInput is the input for the plan_day tool.
type PlanDayInput struct {
	Date      *string       `json:"date,omitempty" jsonschema_description:"Plan date YYYY-MM-DD (default: today)"`
	Items     []PlanDayItem `json:"items" jsonschema:"required" jsonschema_description:"Todo items to plan for the day"`
	JournalID *FlexInt      `json:"journal_id,omitempty" jsonschema_description:"Optional agent_note ID that drove this planning session"`
}

// PlanDayItem is a single item in the plan_day input.
type PlanDayItem struct {
	TaskID   string `json:"task_id" jsonschema:"required" jsonschema_description:"Todo item UUID"`
	Position int    `json:"position,omitempty" jsonschema_description:"Position in plan (0-based, lower = higher priority)"`
}

// PlanDayOutput is the output of the plan_day tool.
type PlanDayOutput struct {
	Date         string       `json:"date"`
	ItemsCreated int          `json:"items_created"`
	Items        []daily.Item `json:"items"`
}

func (s *Server) planDay(ctx context.Context, _ *mcp.CallToolRequest, input PlanDayInput) (*mcp.CallToolResult, PlanDayOutput, error) {
	if len(input.Items) == 0 {
		return nil, PlanDayOutput{}, fmt.Errorf("items is required (at least one todo item)")
	}

	date := s.today()
	if input.Date != nil && *input.Date != "" {
		t, err := time.Parse(time.DateOnly, *input.Date)
		if err != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("invalid date: %w", err)
		}
		date = t
	}

	if err := s.dayplan.DeletePlannedByDate(ctx, date); err != nil {
		return nil, PlanDayOutput{}, fmt.Errorf("clearing existing plan: %w", err)
	}

	var noteID *int64
	if input.JournalID != nil {
		v := int64(*input.JournalID)
		noteID = &v
	}

	for i, item := range input.Items {
		itemID, err := uuid.Parse(item.TaskID)
		if err != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("invalid task_id at position %d: %w", i, err)
		}

		t, tErr := s.todos.ItemByID(ctx, itemID)
		if tErr != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("todo item %s not found: %w", item.TaskID, tErr)
		}
		if t.State == todo.StateInbox {
			return nil, PlanDayOutput{}, fmt.Errorf("todo item %s is in inbox state — clarify before planning", item.TaskID)
		}

		pos := item.Position
		if pos == 0 {
			pos = i
		}

		if _, err := s.dayplan.Create(ctx, &daily.CreateItemParams{
			PlanDate:    date,
			TodoID:  itemID,
			SelectedBy:  s.callerIdentity(ctx),
			Position:    int32(pos),
			AgentNoteID: noteID,
		}); err != nil {
			return nil, PlanDayOutput{}, fmt.Errorf("creating plan item for todo %s: %w", item.TaskID, err)
		}
	}

	items, err := s.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		return nil, PlanDayOutput{}, fmt.Errorf("fetching created plan items: %w", err)
	}

	s.logger.Info("plan_day", "date", date.Format(time.DateOnly), "items", len(items))
	return nil, PlanDayOutput{
		Date:         date.Format(time.DateOnly),
		ItemsCreated: len(items),
		Items:        items,
	}, nil
}
