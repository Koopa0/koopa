package mcp

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/plan"
)

// --- manage_plan ---

// ManagePlanInput holds the input for the manage_plan multiplexer tool.
type ManagePlanInput struct {
	Action string `json:"action" jsonschema:"required" jsonschema_description:"Action: add_items, remove_items, update_item, reorder, update_plan, progress"`
	PlanID string `json:"plan_id" jsonschema:"required" jsonschema_description:"Plan UUID"`

	// add_items
	Items []ManagePlanItemInput `json:"items,omitempty" jsonschema_description:"Items to add [{learning_item_id, position, phase?}]"`

	// remove_items (draft only)
	ItemIDs []string `json:"item_ids,omitempty" jsonschema_description:"Plan item UUIDs to remove (draft plans only)"`

	// update_item
	ItemID                   *string `json:"item_id,omitempty" jsonschema_description:"Plan item UUID (for update_item)"`
	Status                   *string `json:"status,omitempty" jsonschema_description:"New status: completed, skipped, substituted (for update_item) or active, paused, completed, abandoned (for update_plan)"`
	Reason                   *string `json:"reason,omitempty" jsonschema_description:"Why skipped/substituted"`
	SubstituteLearningItemID *string `json:"substitute_learning_item_id,omitempty" jsonschema_description:"learning_items.id of the replacement (for status=substituted)"`
	CompletedByAttemptID     *string `json:"completed_by_attempt_id,omitempty" jsonschema_description:"Attempt UUID that informed the completion decision (policy-mandatory for AI-initiated completions)"`

	// reorder
	Positions []ManagePlanPositionInput `json:"positions,omitempty" jsonschema_description:"[{item_id, position}] for reordering"`
}

// ManagePlanItemInput represents a single item to add to a plan.
type ManagePlanItemInput struct {
	LearningItemID string  `json:"learning_item_id" jsonschema:"required"`
	Position       int32   `json:"position" jsonschema:"required"`
	Phase          *string `json:"phase,omitempty"`
}

// ManagePlanPositionInput represents a position update for reordering.
type ManagePlanPositionInput struct {
	ItemID   string `json:"item_id" jsonschema:"required"`
	Position int32  `json:"position" jsonschema:"required"`
}

// ManagePlanOutput holds the result of a manage_plan action.
type ManagePlanOutput struct {
	Action   string                `json:"action"`
	PlanID   string                `json:"plan_id"`
	Message  string                `json:"message"`
	Progress *plan.Progress        `json:"progress,omitempty"`
	Items    []plan.PlanItemDetail `json:"items,omitempty"` // populated by action=progress so update_item callers have plan_item_id + title
}

//nolint:gocritic // hugeParam: addTool generic requires value type I, cannot pass by pointer.
func (s *Server) managePlan(ctx context.Context, _ *mcp.CallToolRequest, input ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	planID, err := uuid.Parse(input.PlanID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid plan_id: %w", err)
	}

	switch input.Action {
	case "add_items":
		return s.mpAddItems(ctx, planID, &input)
	case "remove_items":
		return s.mpRemoveItems(ctx, planID, &input)
	case "update_item":
		return s.mpUpdateItem(ctx, planID, &input)
	case "reorder":
		return s.mpReorder(ctx, planID, &input)
	case "update_plan":
		return s.mpUpdatePlan(ctx, planID, &input)
	case "progress":
		return s.mpProgress(ctx, planID)
	default:
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid action %q (valid: add_items, remove_items, update_item, reorder, update_plan, progress)", input.Action)
	}
}

func (s *Server) mpAddItems(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if len(input.Items) == 0 {
		return nil, ManagePlanOutput{}, fmt.Errorf("items is required for add_items")
	}

	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}
	if p.Status != plan.StatusDraft && p.Status != plan.StatusActive {
		return nil, ManagePlanOutput{}, fmt.Errorf("add_items is only allowed on draft or active plans (current: %s)", p.Status)
	}

	// Parse all IDs upfront before starting transaction.
	type parsedItem struct {
		id    uuid.UUID
		pos   int32
		phase *string
	}
	parsed := make([]parsedItem, len(input.Items))
	for i, item := range input.Items {
		liID, pErr := uuid.Parse(item.LearningItemID)
		if pErr != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("invalid learning_item_id %q: %w", item.LearningItemID, pErr)
		}
		parsed[i] = parsedItem{id: liID, pos: item.Position, phase: item.Phase}
	}

	// Batch insert in a transaction — all or nothing.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	txPlans := s.plans.WithTx(tx)
	for _, it := range parsed {
		_, addErr := txPlans.AddItem(ctx, plan.AddItemParams{
			PlanID:         planID,
			LearningItemID: it.id,
			Position:       it.pos,
			Phase:          it.phase,
		})
		if addErr != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("adding item %s: %w", it.id, addErr)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("committing add_items: %w", err)
	}

	s.logger.Info("manage_plan", "action", "add_items", "plan_id", planID, "count", len(input.Items))
	return nil, ManagePlanOutput{
		Action:  "add_items",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("added %d items", len(input.Items)),
	}, nil
}

func (s *Server) mpRemoveItems(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if len(input.ItemIDs) == 0 {
		return nil, ManagePlanOutput{}, fmt.Errorf("item_ids is required for remove_items")
	}

	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}
	if p.Status != plan.StatusDraft {
		return nil, ManagePlanOutput{}, fmt.Errorf("remove_items is only allowed on draft plans (use skip or substitute for active plans)")
	}

	itemIDs := make([]uuid.UUID, len(input.ItemIDs))
	for i, raw := range input.ItemIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("invalid item_id %q: %w", raw, err)
		}
		itemIDs[i] = id
	}

	if err := s.plans.RemoveItems(ctx, planID, itemIDs); err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("removing items: %w", err)
	}

	s.logger.Info("manage_plan", "action", "remove_items", "plan_id", planID, "count", len(itemIDs))
	return nil, ManagePlanOutput{
		Action:  "remove_items",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("removed %d items", len(itemIDs)),
	}, nil
}

func (s *Server) mpUpdateItem(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if input.ItemID == nil || *input.ItemID == "" {
		return nil, ManagePlanOutput{}, fmt.Errorf("item_id is required for update_item")
	}
	if input.Status == nil || *input.Status == "" {
		return nil, ManagePlanOutput{}, fmt.Errorf("status is required for update_item")
	}

	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}
	if p.Status != plan.StatusActive {
		return nil, ManagePlanOutput{}, fmt.Errorf("update_item is only allowed on active plans (current: %s)", p.Status)
	}

	itemID, err := uuid.Parse(*input.ItemID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid item_id: %w", err)
	}

	status := plan.ItemStatus(*input.Status)
	switch status {
	case plan.ItemCompleted, plan.ItemSkipped:
		params := plan.UpdateItemStatusParams{
			ID:     itemID,
			Status: status,
			Reason: input.Reason,
		}
		if status == plan.ItemCompleted {
			now := time.Now()
			params.CompletedAt = &now
			aid, parseErr := parseOptionalUUID(input.CompletedByAttemptID)
			if parseErr != nil {
				return nil, ManagePlanOutput{}, fmt.Errorf("invalid completed_by_attempt_id: %w", parseErr)
			}
			params.CompletedByAttemptID = aid
			if aid == nil {
				s.logger.Warn("manage_plan: completed without attempt id",
					"plan_id", planID, "item_id", itemID)
			}
		}
		if _, err = s.plans.UpdateItemStatus(ctx, params); err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("updating item to %s: %w", status, err)
		}

	case plan.ItemSubstituted:
		if err := s.mpSubstitute(ctx, planID, itemID, input); err != nil {
			return nil, ManagePlanOutput{}, err
		}

	default:
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid item status %q (valid: completed, skipped, substituted)", *input.Status)
	}

	s.logger.Info("manage_plan", "action", "update_item", "plan_id", planID, "item_id", itemID, "status", *input.Status)
	return nil, ManagePlanOutput{
		Action:  "update_item",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("item %s → %s", itemID, *input.Status),
	}, nil
}

func (s *Server) mpSubstitute(ctx context.Context, planID, itemID uuid.UUID, input *ManagePlanInput) error {
	if input.SubstituteLearningItemID == nil || *input.SubstituteLearningItemID == "" {
		return fmt.Errorf("substitute_learning_item_id is required for status=substituted")
	}
	subLIID, err := uuid.Parse(*input.SubstituteLearningItemID)
	if err != nil {
		return fmt.Errorf("invalid substitute_learning_item_id: %w", err)
	}

	// Wrap in transaction — AddItem + UpdateItemStatus must be atomic.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	txPlans := s.plans.WithTx(tx)

	items, err := txPlans.Items(ctx, planID)
	if err != nil {
		return fmt.Errorf("fetching plan items: %w", err)
	}
	var nextPos int32
	if len(items) > 0 {
		maxItem := slices.MaxFunc(items, func(a, b plan.PlanItem) int {
			return cmp.Compare(a.Position, b.Position)
		})
		nextPos = maxItem.Position + 1
	}

	newItem, err := txPlans.AddItem(ctx, plan.AddItemParams{
		PlanID:         planID,
		LearningItemID: subLIID,
		Position:       nextPos,
	})
	if err != nil {
		return fmt.Errorf("adding substitute item: %w", err)
	}

	_, err = txPlans.UpdateItemStatus(ctx, plan.UpdateItemStatusParams{
		ID:            itemID,
		Status:        plan.ItemSubstituted,
		SubstitutedBy: &newItem.ID,
		Reason:        input.Reason,
	})
	if err != nil {
		return fmt.Errorf("marking item as substituted: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing substitution: %w", err)
	}
	return nil
}

func (s *Server) mpReorder(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if len(input.Positions) == 0 {
		return nil, ManagePlanOutput{}, fmt.Errorf("positions is required for reorder")
	}

	for _, pos := range input.Positions {
		itemID, err := uuid.Parse(pos.ItemID)
		if err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("invalid item_id %q: %w", pos.ItemID, err)
		}
		if err := s.plans.UpdateItemPosition(ctx, itemID, pos.Position); err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("updating position for item %s: %w", pos.ItemID, err)
		}
	}

	s.logger.Info("manage_plan", "action", "reorder", "plan_id", planID, "count", len(input.Positions))
	return nil, ManagePlanOutput{
		Action:  "reorder",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("reordered %d items", len(input.Positions)),
	}, nil
}

func (s *Server) mpUpdatePlan(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if input.Status == nil || *input.Status == "" {
		return nil, ManagePlanOutput{}, fmt.Errorf("status is required for update_plan")
	}

	// Fetch current plan to validate transition.
	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}

	newStatus := plan.Status(*input.Status)
	if tErr := validatePlanTransition(p.Status, newStatus); tErr != nil {
		return nil, ManagePlanOutput{}, tErr
	}

	_, err = s.plans.UpdatePlanStatus(ctx, planID, newStatus)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("updating plan status: %w", err)
	}

	s.logger.Info("manage_plan", "action", "update_plan", "plan_id", planID, "status", newStatus)
	return nil, ManagePlanOutput{
		Action:  "update_plan",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("plan status → %s", newStatus),
	}, nil
}

func (s *Server) mpProgress(ctx context.Context, planID uuid.UUID) (*mcp.CallToolResult, ManagePlanOutput, error) {
	// Verify plan exists before computing progress — without this, a bogus
	// plan_id returns {total:0, items:[]} which looks like an empty plan.
	// Every other mp* action already does this lookup; progress was the only
	// read path where a wrong plan_id silently succeeded.
	if _, err := s.plans.Plan(ctx, planID); err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}

	progress, err := s.plans.Progress(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan progress: %w", err)
	}
	items, err := s.plans.ItemsDetailed(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan items: %w", err)
	}

	s.logger.Info("manage_plan", "action", "progress", "plan_id", planID, "item_count", len(items))
	return nil, ManagePlanOutput{
		Action:   "progress",
		PlanID:   planID.String(),
		Message:  fmt.Sprintf("%d/%d completed", progress.Completed, progress.Total),
		Progress: progress,
		Items:    items,
	}, nil
}

var allowedPlanTransitions = map[plan.Status][]plan.Status{
	plan.StatusDraft:  {plan.StatusActive, plan.StatusAbandoned},
	plan.StatusActive: {plan.StatusPaused, plan.StatusCompleted, plan.StatusAbandoned},
	plan.StatusPaused: {plan.StatusActive, plan.StatusAbandoned},
}

// validatePlanTransition checks that the status transition is allowed.
func validatePlanTransition(from, to plan.Status) error {
	targets, ok := allowedPlanTransitions[from]
	if !ok {
		return fmt.Errorf("plan status %q cannot be transitioned", from)
	}
	for _, t := range targets {
		if t == to {
			return nil
		}
	}
	return fmt.Errorf("invalid plan transition %s → %s", from, to)
}

// parseOptionalUUID parses a nullable string pointer as a UUID.
// Returns (nil, nil) when the input is nil or empty.
func parseOptionalUUID(s *string) (*uuid.UUID, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}
