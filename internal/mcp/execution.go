// Copyright 2026 Koopa. All rights reserved.

// execution.go holds the handler + inputs for plan_day (daily plan
// assembly). It operates on todos (personal GTD), NOT on coordination
// tasks — every code path routes to internal/todo. Inbox→todo
// promotion (clarify) is an admin-UI action, not an agent tool.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/todo"
)

// --- plan_day ---

// PlanDayInput is the input for the plan_day tool.
type PlanDayInput struct {
	Date  *string       `json:"date,omitempty" jsonschema_description:"Plan date YYYY-MM-DD (default: today)"`
	Items []PlanDayItem `json:"items" jsonschema:"required" jsonschema_description:"Todo items to plan for the day. Each todo MUST already be in state=todo (not inbox/done/someday). Inbox-state items are rejected — clarify them to state=todo via the admin UI first. plan_day is idempotent for the given date: re-calling with a different items list replaces existing 'planned' rows for that date and reports the displaced items in items_removed."`
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
	// ItemsRemoved lists todos that were planned for this date in the
	// previous successful plan but are NOT in the new items list — i.e.
	// the todos genuinely displaced by this call. A todo carried over
	// (same task_id appears in both the old plan and the new items
	// list) does NOT appear here even though its underlying plan_item
	// row gets a new id; the row identity churn is an implementation
	// detail of the delete-then-insert path, not a semantic eviction.
	// Empty when no previous plan existed or every previous todo was
	// retained. Always [], never null — callers can rely on len()
	// without a nil check.
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

// maxPlanPosition bounds the user-supplied plan position so the int32 cast
// in createPlanItemTx cannot overflow. Daily plans are small; this is a
// generous safety ceiling, not a product limit.
const maxPlanPosition = 100_000

// createPlanItemTx resolves a single PlanDayItem against tx-bound stores
// and inserts the daily_plan_items row. The caller wraps all calls in a
// single transaction so a mid-loop failure rolls back both the new
// inserts AND the upstream DeletePlannedByDate that opens the
// idempotent-replace window — without that the previous plan would be
// silently destroyed when the second item's todo is in inbox-state.
//
// Index i is the caller-loop position used when the item did not
// specify one.
func createPlanItemTx(ctx context.Context, txTodos *todo.Store, txDayplan *daily.Store, item PlanDayItem, i int, date time.Time, caller string) error {
	itemID, err := uuid.Parse(item.TaskID)
	if err != nil {
		return fmt.Errorf("invalid task_id at position %d: %w", i, err)
	}
	t, err := txTodos.ItemByID(ctx, itemID)
	if err != nil {
		return fmt.Errorf("todo item %s not found: %w", item.TaskID, err)
	}
	if t.State == todo.StateInbox {
		return fmt.Errorf("todo item %s is in inbox state — it must be clarified to state=todo (via the admin UI) before planning", item.TaskID)
	}
	if item.Position < 0 || item.Position > maxPlanPosition {
		return fmt.Errorf("todo item %s position %d out of range [0, %d]", item.TaskID, item.Position, maxPlanPosition)
	}
	pos := item.Position
	if pos == 0 {
		pos = i
	}
	if _, err := txDayplan.Create(ctx, &daily.CreateItemParams{
		PlanDate:   date,
		TodoID:     itemID,
		SelectedBy: caller,
		Position:   int32(pos), // #nosec G115 -- pos validated to [0, maxPlanPosition] or the loop index; fits int32
	}); err != nil {
		return fmt.Errorf("creating plan item for todo %s: %w", item.TaskID, err)
	}
	return nil
}

// displacedFrom filters a slice of removed plan_items down to those
// whose todo_id is NOT in the new plan. The DELETE-then-INSERT pattern
// inside planDay produces a fresh plan_item ID for every todo that
// stays in the plan, so the raw "removed" list contains rows for
// todos the caller is keeping. Reporting those as displaced confuses
// "Koopa override" call sites that read items_removed to confirm a
// todo got pushed out — see Koopa-Planner.md §plan_day.
//
// The new-plan input is the source of truth for "what's still in the
// plan" because, by the time we return, the new rows have just been
// inserted from exactly those todo_ids.
func displacedFrom(removed []daily.RemovedItem, kept []PlanDayItem) []daily.RemovedItem {
	if len(removed) == 0 {
		return removed
	}
	keptIDs := make(map[uuid.UUID]struct{}, len(kept))
	for _, item := range kept {
		if id, err := uuid.Parse(item.TaskID); err == nil {
			keptIDs[id] = struct{}{}
		}
	}
	out := make([]daily.RemovedItem, 0, len(removed))
	for _, r := range removed {
		if _, stillThere := keptIDs[r.TodoID]; !stillThere {
			out = append(out, r)
		}
	}
	return out
}

// planDay assembles a day's daily_plan_items. Only the planner (the morning
// briefing role) and the human owner author daily plans; other agents do
// not participate in daily_plan_items.
//
// All writes (delete-existing + insert-new) run inside a single
// transaction. Without that wrapper a mid-loop validation failure
// (typically a todo in inbox state) leaves the plan empty: the delete
// commits, the insert never runs, and the next plan_day call sees an
// empty starting state and reports an empty items_removed even though
// a previous plan existed. The atomic wrapper preserves the previous
// plan on any failure path.
func (s *Server) planDay(ctx context.Context, _ *mcp.CallToolRequest, input PlanDayInput) (*mcp.CallToolResult, PlanDayOutput, error) {
	if err := s.requireAuthor(ctx, "plan_day", "planner"); err != nil {
		return nil, PlanDayOutput{}, err
	}
	if len(input.Items) == 0 {
		return nil, PlanDayOutput{}, fmt.Errorf("items must contain at least one todo. plan_day is idempotent — to replace today's plan, supply the full new list (any displaced items are reported in items_removed). To leave today unplanned, do not call plan_day at all")
	}

	date, err := s.resolvePlanDate(input.Date)
	if err != nil {
		return nil, PlanDayOutput{}, err
	}

	caller := s.callerIdentity(ctx)
	var (
		removed []daily.RemovedItem
		items   []daily.Item
	)
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		txTodos := todo.NewStore(tx)
		txDayplan := daily.NewStore(tx)

		var dErr error
		removed, dErr = txDayplan.DeletePlannedByDate(ctx, date)
		if dErr != nil {
			return fmt.Errorf("clearing existing plan: %w", dErr)
		}

		for i, item := range input.Items {
			if err := createPlanItemTx(ctx, txTodos, txDayplan, item, i, date, caller); err != nil {
				return err
			}
		}

		var fErr error
		items, fErr = txDayplan.ItemsByDate(ctx, date)
		if fErr != nil {
			return fmt.Errorf("fetching created plan items: %w", fErr)
		}
		return nil
	})
	if err != nil {
		return nil, PlanDayOutput{}, err
	}

	displaced := displacedFrom(removed, input.Items)

	s.logger.Info("plan_day", "date", date.Format(time.DateOnly), "items", len(items), "items_removed", len(displaced))
	return nil, PlanDayOutput{
		Date:         date.Format(time.DateOnly),
		ItemsCreated: len(items),
		Items:        items,
		ItemsRemoved: displaced,
	}, nil
}
