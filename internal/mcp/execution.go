// execution.go holds the handler + inputs for advance_work (todo
// state machine), plan_day (daily plan assembly), and the shared
// priority normalizer.
//
// advance_work operates on todos (personal GTD), NOT on coordination
// tasks — the tool kept its original name so Cowork project
// instructions keep working, but every code path routes to
// internal/todo. Do not migrate it to internal/agent/task without
// updating every caller first.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/todo"
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
	if input.Energy != nil && *input.Energy != "" && !isValidEnergy(*input.Energy) {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("energy must be one of: high, medium, low (got %q)", *input.Energy)
	}

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
	if input.Priority != nil && *input.Priority != "" {
		p := normalizePriority(*input.Priority)
		if !isValidTaskPriority(p) {
			return nil, AdvanceWorkOutput{}, fmt.Errorf("priority must be one of: high, medium, low (got %q)", *input.Priority)
		}
		params.Priority = &p
	}
	params.Energy = input.Energy

	if input.Project != "" {
		params.ProjectID = s.resolveProjectID(ctx, input.Project)
	}

	var updated *todo.Item
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		updated, err = todo.NewStore(tx).Update(ctx, params)
		return err
	})
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("clarifying todo item: %w", err)
	}

	s.logger.Info("advance_work", "action", "clarify", "todo_id", itemID)
	return nil, AdvanceWorkOutput{Task: *updated}, nil
}

func (s *Server) advanceTransition(ctx context.Context, itemID uuid.UUID, state todo.State) (*mcp.CallToolResult, AdvanceWorkOutput, error) {
	var updated *todo.Item
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		updated, err = todo.NewStore(tx).UpdateState(ctx, itemID, state)
		return err
	})
	if err != nil {
		return nil, AdvanceWorkOutput{}, fmt.Errorf("transitioning todo item to %s: %w", state, err)
	}

	s.logger.Info("advance_work", "action", string(state), "todo_id", itemID)
	return nil, AdvanceWorkOutput{Task: *updated}, nil
}

func (s *Server) advanceComplete(ctx context.Context, itemID uuid.UUID) (*mcp.CallToolResult, AdvanceWorkOutput, error) {
	var out AdvanceWorkOutput
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		txTodos := todo.NewStore(tx)
		txDayplan := daily.NewStore(tx)

		updated, err := txTodos.UpdateState(ctx, itemID, todo.StateDone)
		if err != nil {
			return fmt.Errorf("completing todo item: %w", err)
		}
		out.Task = *updated

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
		return nil
	})
	if err != nil {
		return nil, AdvanceWorkOutput{}, err
	}

	s.logger.Info("advance_work", "action", "complete", "todo_id", itemID,
		"recurring", out.RecurringAdvanced, "plan_item_updated", out.PlanItemUpdated)
	return nil, out, nil
}

// --- plan_day ---

// PlanDayInput is the input for the plan_day tool.
type PlanDayInput struct {
	Date        *string       `json:"date,omitempty" jsonschema_description:"Plan date YYYY-MM-DD (default: today)"`
	Items       []PlanDayItem `json:"items" jsonschema:"required" jsonschema_description:"Todo items to plan for the day. Each todo MUST already be in state=todo (not inbox/done/someday). Inbox-state items are rejected — promote them first via advance_work(action=clarify). plan_day is idempotent for the given date: re-calling with a different items list replaces existing 'planned' rows for that date and reports the displaced items in items_removed."`
	AgentNoteID *string       `json:"agent_note_id,omitempty" jsonschema_description:"Optional agent_note UUID that drove this planning session"`
}

// PlanDayItem is a single item in the plan_day input.
type PlanDayItem struct {
	TaskID   string `json:"task_id" jsonschema:"required" jsonschema_description:"Todo item UUID. The todo must be in state=todo; inbox/done/someday are rejected."`
	Position int    `json:"position,omitempty" jsonschema_description:"Position in plan (0-based, lower = higher priority)"`
}

// PlanDayOutput is the output of the plan_day tool.
type PlanDayOutput struct {
	Date         string       `json:"date"`
	ItemsCreated int          `json:"items_created"`
	Items        []daily.Item `json:"items"`
	// ItemsRemoved lists the 'planned' items that were displaced when this
	// call replaced an existing plan for the date. Empty when no plan
	// existed yet or the existing plan was already empty. Always [], never
	// null — callers can rely on len() without a nil check.
	ItemsRemoved []daily.RemovedItem `json:"items_removed"`
}

// resolvePlanDate parses the optional caller-supplied date, falling back to
// today. Split out from planDay to keep it under the cognitive-complexity
// budget.
func (s *Server) resolvePlanDate(date *string) (time.Time, error) {
	if date == nil || *date == "" {
		return s.today(), nil
	}
	t, err := time.Parse(time.DateOnly, *date)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date: %w", err)
	}
	return t, nil
}

// resolvePlanAgentNote parses the optional agent_note UUID and verifies the
// referenced note has kind='plan' — the invariant D5 enforces at the MCP
// boundary since schema has no cross-row CHECK.
func (s *Server) resolvePlanAgentNote(ctx context.Context, raw *string) (*uuid.UUID, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(*raw)
	if err != nil {
		return nil, fmt.Errorf("invalid agent_note_id: %w", err)
	}
	ref, err := s.agentNotes.NoteByID(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("loading agent_note %s: %w", parsed, err)
	}
	if ref.Kind != agentnote.KindPlan {
		return nil, fmt.Errorf("agent_note %s has kind=%q; daily_plan_items.agent_note_id requires kind='plan'", parsed, ref.Kind)
	}
	return &parsed, nil
}

// createPlanItem resolves a single PlanDayItem to a todo and persists the
// daily_plan_items row. Index `i` is the caller-loop position used when the
// item did not specify one.
func (s *Server) createPlanItem(ctx context.Context, item PlanDayItem, i int, date time.Time, noteID *uuid.UUID) error {
	itemID, err := uuid.Parse(item.TaskID)
	if err != nil {
		return fmt.Errorf("invalid task_id at position %d: %w", i, err)
	}
	t, err := s.todos.ItemByID(ctx, itemID)
	if err != nil {
		return fmt.Errorf("todo item %s not found: %w", item.TaskID, err)
	}
	if t.State == todo.StateInbox {
		return fmt.Errorf("todo item %s is in inbox state — call advance_work(action=\"clarify\", task_id=%q) first to promote it to state=todo before planning", item.TaskID, item.TaskID)
	}
	pos := item.Position
	if pos == 0 {
		pos = i
	}
	if _, err := s.dayplan.Create(ctx, &daily.CreateItemParams{
		PlanDate:    date,
		TodoID:      itemID,
		SelectedBy:  s.callerIdentity(ctx),
		Position:    int32(pos), // #nosec G115 -- position is bounded by caller Items slice length
		AgentNoteID: noteID,
	}); err != nil {
		return fmt.Errorf("creating plan item for todo %s: %w", item.TaskID, err)
	}
	return nil
}

// planDay assembles a day's daily_plan_items. Only HQ (the morning
// briefing role) and the human owner author daily plans. The other
// cowork agents have their own work queues — content-studio's
// content_pipeline, research-lab's directive backlog, learning-studio's
// FSRS schedule — and do not participate in daily_plan_items.
func (s *Server) planDay(ctx context.Context, _ *mcp.CallToolRequest, input PlanDayInput) (*mcp.CallToolResult, PlanDayOutput, error) {
	if err := s.requireAuthor(ctx, "plan_day", "hq"); err != nil {
		return nil, PlanDayOutput{}, err
	}
	if len(input.Items) == 0 {
		return nil, PlanDayOutput{}, fmt.Errorf("items must contain at least one todo. plan_day is idempotent — to replace today's plan, supply the full new list (any displaced items are reported in items_removed). To leave today unplanned, do not call plan_day at all")
	}

	date, err := s.resolvePlanDate(input.Date)
	if err != nil {
		return nil, PlanDayOutput{}, err
	}

	removed, err := s.dayplan.DeletePlannedByDate(ctx, date)
	if err != nil {
		return nil, PlanDayOutput{}, fmt.Errorf("clearing existing plan: %w", err)
	}

	noteID, err := s.resolvePlanAgentNote(ctx, input.AgentNoteID)
	if err != nil {
		return nil, PlanDayOutput{}, err
	}

	for i, item := range input.Items {
		if err := s.createPlanItem(ctx, item, i, date, noteID); err != nil {
			return nil, PlanDayOutput{}, err
		}
	}

	items, err := s.dayplan.ItemsByDate(ctx, date)
	if err != nil {
		return nil, PlanDayOutput{}, fmt.Errorf("fetching created plan items: %w", err)
	}

	s.logger.Info("plan_day", "date", date.Format(time.DateOnly), "items", len(items), "items_removed", len(removed))
	return nil, PlanDayOutput{
		Date:         date.Format(time.DateOnly),
		ItemsCreated: len(items),
		Items:        items,
		ItemsRemoved: removed,
	}, nil
}
