// Copyright 2026 Koopa. All rights reserved.

// execution.go holds the handler + inputs for plan_day (daily plan
// assembly). It operates on todos (personal GTD), NOT on coordination
// tasks — every code path routes to internal/todo. Inbox→todo
// promotion (clarify) is an admin-UI action, not an agent tool.

package mcp

import (
	"context"
	"errors"
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
	Items []PlanDayItem `json:"items" jsonschema:"required" jsonschema_description:"Todo items to plan for the day. Each todo MUST be in state=todo or in_progress (inbox/done/someday/archived/dismissed rejected — clarify inbox todos via the admin UI first). plan_day is idempotent for the given date: re-calling with a different items list replaces existing 'planned' rows for that date and reports the displaced items in items_removed."`
}

// PlanDayItem is a single item in the plan_day input.
type PlanDayItem struct {
	TodoID   string `json:"todo_id" jsonschema:"required" jsonschema_description:"Todo item UUID. The todo must be in state=todo or in_progress; inbox/done/someday/archived are rejected."`
	Position *int   `json:"position,omitempty" jsonschema_description:"Position in plan (0-based, lower = higher priority). Omit to fall back to the item's order in the list."`
}

// PlanDayOutput is the output of the plan_day tool.
type PlanDayOutput struct {
	Date         string       `json:"date"`
	ItemsCreated int          `json:"items_created"`
	Items        []daily.Item `json:"items"`
	// ItemsRemoved lists todos that were planned for this date in the
	// previous successful plan but are NOT in the new items list — i.e.
	// the todos genuinely displaced by this call. A todo carried over
	// (same todo_id appears in both the old plan and the new items
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
// in validatePlanItem cannot overflow. Daily plans are small; this is a
// generous safety ceiling, not a product limit.
const maxPlanPosition = 100_000

// batchFetchTodos resolves every parseable todo_id in items in one round
// trip, keyed by id. Items with a malformed todo_id are simply skipped here
// — validatePlanItem re-parses each item's id itself and surfaces that error
// at its original per-item position, so validation-error ordering is
// unaffected by batching the DB lookups ahead of the loop.
func batchFetchTodos(ctx context.Context, txTodos *todo.Store, items []PlanDayItem) (map[uuid.UUID]todo.Item, error) {
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		if id, err := uuid.Parse(item.TodoID); err == nil {
			ids = append(ids, id)
		}
	}
	fetched, err := txTodos.ItemsByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("fetching todos by id: %w", err)
	}
	byID := make(map[uuid.UUID]todo.Item, len(fetched))
	for i := range fetched {
		byID[fetched[i].ID] = fetched[i]
	}
	return byID, nil
}

// validatePlanItem checks a single PlanDayItem against todosByID (the
// batch-fetched lookup built once by batchFetchTodos) and builds its
// daily.CreateItemParams. Pure in-memory — no DB call — so on any failure
// the caller returns without having written anything; the tx rolls back
// cleanly (also undoing the upstream DeletePlannedByDate that opened the
// idempotent-replace window, so a mid-validation failure never destroys the
// previous plan).
//
// Index i is the caller-loop position used when the item did not
// specify one.
func validatePlanItem(todosByID map[uuid.UUID]todo.Item, item PlanDayItem, i int, date time.Time, caller string) (daily.CreateItemParams, error) {
	itemID, err := uuid.Parse(item.TodoID)
	if err != nil {
		return daily.CreateItemParams{}, fmt.Errorf("invalid todo_id at position %d: %w", i, err)
	}
	t, ok := todosByID[itemID]
	if !ok {
		return daily.CreateItemParams{}, fmt.Errorf("todo item %s not found: %w", item.TodoID, todo.ErrNotFound)
	}
	// Only actionable items belong on a day's plan: todo (ready to start) and
	// in_progress (continuing). inbox is unclarified; done/someday/archived/
	// dismissed are not things you start today.
	if t.State != todo.StateTodo && t.State != todo.StateInProgress {
		return daily.CreateItemParams{}, fmt.Errorf("todo item %s is in state %q — only todo or in_progress items can be planned (inbox must be clarified first; done/someday are not today's work)", item.TodoID, t.State)
	}
	// Default to the caller-loop index; an explicit position (including 0) is
	// honored. A bare int could not tell "omitted" from "explicit 0", so the
	// field is *int.
	pos := i
	if item.Position != nil {
		pos = *item.Position
	}
	if pos < 0 || pos > maxPlanPosition {
		return daily.CreateItemParams{}, fmt.Errorf("todo item %s position %d out of range [0, %d]", item.TodoID, pos, maxPlanPosition)
	}
	return daily.CreateItemParams{
		PlanDate:   date,
		TodoID:     itemID,
		SelectedBy: caller,
		Position:   int32(pos), // #nosec G115 -- pos validated to [0, maxPlanPosition] or the loop index; fits int32
	}, nil
}

// writePlanItems validates every item against todosByID, then batch-inserts
// them via CreateAll in one round trip. Returns the first validation error
// or the first per-item batch-write failure (in list order) — matching the
// old per-item loop's stop-at-first-failure semantics even though the
// batch write itself is pipelined, not sequential. Split out of planDay's
// tx closure to keep cognitive complexity down.
func writePlanItems(ctx context.Context, todosByID map[uuid.UUID]todo.Item, txDayplan *daily.Store, items []PlanDayItem, date time.Time, caller string) error {
	params := make([]daily.CreateItemParams, len(items))
	for i, item := range items {
		p, vErr := validatePlanItem(todosByID, item, i, date, caller)
		if vErr != nil {
			return vErr
		}
		params[i] = p
	}
	for i, result := range txDayplan.CreateAll(ctx, params) {
		if result.Err == nil {
			continue
		}
		if errors.Is(result.Err, daily.ErrItemResolved) {
			return fmt.Errorf("todo item %s is already resolved (done/deferred/dropped) for %s and cannot be re-planned", items[i].TodoID, date.Format(time.DateOnly))
		}
		return fmt.Errorf("creating plan item for todo %s: %w", items[i].TodoID, result.Err)
	}
	return nil
}

// displacedFrom filters a slice of removed plan_items down to those
// whose todo_id is NOT in the new plan. The DELETE-then-INSERT pattern
// inside planDay produces a fresh plan_item ID for every todo that
// stays in the plan, so the raw "removed" list contains rows for
// todos the caller is keeping. Reporting those as displaced confuses
// "Koopa override" call sites that read items_removed to confirm a
// todo got pushed out.
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
		if id, err := uuid.Parse(item.TodoID); err == nil {
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

// planDay assembles a day's daily_plan_items. Daily plans are authored by the
// human owner and by an agent acting as the daily driver; other agents do not
// participate in daily_plan_items.
//
// All writes (delete-existing + insert-new) run inside a single
// transaction. Without that wrapper a mid-loop validation failure
// (typically a todo in inbox state) leaves the plan empty: the delete
// commits, the insert never runs, and the next plan_day call sees an
// empty starting state and reports an empty items_removed even though
// a previous plan existed. The atomic wrapper preserves the previous
// plan on any failure path.
func (s *Server) planDay(ctx context.Context, _ *mcp.CallToolRequest, input PlanDayInput) (*mcp.CallToolResult, PlanDayOutput, error) {
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

		todosByID, bErr := batchFetchTodos(ctx, txTodos, input.Items)
		if bErr != nil {
			return bErr
		}
		if wErr := writePlanItems(ctx, todosByID, txDayplan, input.Items, date, caller); wErr != nil {
			return wErr
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
