// plan.go holds the manage_plan multiplexer tool for learning plans.
//
// manage_plan is at the approved 6-action ceiling (add_entries,
// remove_entries, update_entry, reorder, update_plan, progress —
// see .claude/rules/mcp-decision-policy.md §10). Adding a seventh
// action requires either splitting one out into a dedicated tool or
// consolidating two existing actions — do NOT just append.
//
// `update_entry` enforces the audit-trail policy from §13: marking an
// entry completed REQUIRES both `completed_by_attempt_id` (the
// learning_attempts row that justified the decision) and `reason`
// (Claude's short justification). The schema CHECK is nullable-friendly
// to allow future manual paths; the MCP layer is where the policy is
// enforced.

package mcp

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/plan"
)

// --- manage_plan ---

// ManagePlanInput holds the input for the manage_plan multiplexer tool.
type ManagePlanInput struct {
	Action string `json:"action" jsonschema:"required" jsonschema_description:"Action: add_entries, remove_entries, update_entry, reorder, update_plan, progress"`
	PlanID string `json:"plan_id" jsonschema:"required" jsonschema_description:"Plan UUID"`

	// add_entries
	Entries []ManagePlanEntryInput `json:"entries,omitempty" jsonschema_description:"Entries to add [{learning_target_id OR title, position, phase?}]. Use title for targets not yet attempted."`

	// remove_entries (draft only)
	EntryIDs []string `json:"entry_ids,omitempty" jsonschema_description:"Plan entry UUIDs to remove (draft plans only)"`

	// update_entry
	EntryID                    *string `json:"entry_id,omitempty" jsonschema_description:"Plan entry UUID (for update_entry)"`
	Status                     *string `json:"status,omitempty" jsonschema_description:"New status: completed, skipped, substituted (for update_entry) or active, paused, completed, abandoned (for update_plan)"`
	Reason                     *string `json:"reason,omitempty" jsonschema_description:"Why skipped/substituted"`
	SubstituteLearningTargetID *string `json:"substitute_learning_target_id,omitempty" jsonschema_description:"learning_targets.id of the replacement (for status=substituted)"`
	CompletedByAttemptID       *string `json:"completed_by_attempt_id,omitempty" jsonschema_description:"Attempt UUID that informed the completion decision (policy-mandatory for AI-initiated completions)"`

	// reorder
	Positions []ManagePlanPositionInput `json:"positions,omitempty" jsonschema_description:"[{entry_id, position}] for reordering"`
}

// ManagePlanEntryInput represents a single entry to add to a plan.
// Either learning_target_id OR title must be provided. When only title is
// given, the target is resolved via FindOrCreateItem using the plan's domain.
//
// ExternalID is optional even when Title is used — supplying it makes the
// find-or-create match the same canonical learning_target that record_attempt
// resolved under the same external_id (e.g. "leetcode-198"), so a plan entry
// and the attempt history stay on the same row. Without it, the target is
// matched by title only.
type ManagePlanEntryInput struct {
	LearningTargetID string  `json:"learning_target_id,omitempty" jsonschema_description:"Existing learning target UUID. Either this or title is required."`
	Title            string  `json:"title,omitempty" jsonschema_description:"Target title for find-or-create (uses plan domain). Either this or learning_target_id is required."`
	ExternalID       *string `json:"external_id,omitempty" jsonschema_description:"Optional provider ID (e.g. LeetCode number). When set, the entry binds to the canonical learning target for this (domain, external_id) so plan progress and attempt history stay aligned."`
	Difficulty       *string `json:"difficulty,omitempty" jsonschema_description:"Target difficulty (used with title-based find-or-create)"`
	Position         int32   `json:"position" jsonschema:"required"`
	Phase            *string `json:"phase,omitempty"`
}

// ManagePlanPositionInput represents a position update for reordering.
type ManagePlanPositionInput struct {
	EntryID  string `json:"entry_id" jsonschema:"required"`
	Position int32  `json:"position" jsonschema:"required"`
}

// ManagePlanOutput holds the result of a manage_plan action.
type ManagePlanOutput struct {
	Action   string             `json:"action"`
	PlanID   string             `json:"plan_id"`
	Message  string             `json:"message"`
	Progress *plan.Progress     `json:"progress,omitempty"`
	Entries  []plan.EntryDetail `json:"entries,omitempty"` // populated by action=progress so update_entry callers have plan_entry_id + title
}

//nolint:gocritic // hugeParam: addTool generic requires value type I, cannot pass by pointer.
func (s *Server) managePlan(ctx context.Context, _ *mcp.CallToolRequest, input ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	planID, err := uuid.Parse(input.PlanID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid plan_id: %w", err)
	}

	switch input.Action {
	case "add_entries":
		return s.addPlanEntries(ctx, planID, &input)
	case "remove_entries":
		return s.removePlanEntries(ctx, planID, &input)
	case "update_entry":
		return s.updatePlanEntry(ctx, planID, &input)
	case "reorder":
		return s.reorderPlanEntries(ctx, planID, &input)
	case "update_plan":
		return s.updatePlan(ctx, planID, &input)
	case "progress":
		return s.planProgress(ctx, planID)
	default:
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid action %q (valid: add_entries, remove_entries, update_entry, reorder, update_plan, progress)", input.Action)
	}
}

func (s *Server) addPlanEntries(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if len(input.Entries) == 0 {
		return nil, ManagePlanOutput{}, fmt.Errorf("entries is required for add_entries")
	}

	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}
	if p.Status != plan.StatusDraft && p.Status != plan.StatusActive {
		return nil, ManagePlanOutput{}, fmt.Errorf("add_entries is only allowed on draft or active plans (current: %s)", p.Status)
	}

	// Resolve all target IDs upfront before starting transaction.
	// Each entry can be identified either by learning_target_id (UUID) or by
	// title (find-or-create using the plan's domain).
	type parsedEntry struct {
		id    uuid.UUID
		pos   int32
		phase *string
	}
	parsed := make([]parsedEntry, len(input.Entries))
	for i, entry := range input.Entries {
		var ltID uuid.UUID
		switch {
		case entry.LearningTargetID != "":
			var err error
			ltID, err = uuid.Parse(entry.LearningTargetID)
			if err != nil {
				return nil, ManagePlanOutput{}, fmt.Errorf("entries[%d]: invalid learning_target_id %q: %w", i, entry.LearningTargetID, err)
			}
		case entry.Title != "":
			var err error
			ltID, err = s.learn.FindOrCreateTarget(ctx, p.Domain, entry.Title, entry.ExternalID, entry.Difficulty)
			if err != nil {
				return nil, ManagePlanOutput{}, fmt.Errorf("entries[%d]: resolving %q: %w", i, entry.Title, err)
			}
		default:
			return nil, ManagePlanOutput{}, fmt.Errorf("entries[%d]: either learning_target_id or title is required", i)
		}
		parsed[i] = parsedEntry{id: ltID, pos: entry.Position, phase: entry.Phase}
	}

	// Batch insert in a transaction — all or nothing.
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		txPlans := s.plans.WithTx(tx)
		for _, e := range parsed {
			_, err := txPlans.AddEntry(ctx, plan.AddEntryParams{
				PlanID:           planID,
				LearningTargetID: e.id,
				Position:         e.pos,
				Phase:            e.phase,
			})
			if err != nil {
				return fmt.Errorf("adding entry %s: %w", e.id, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, ManagePlanOutput{}, err
	}

	s.logger.Info("manage_plan", "action", "add_entries", "plan_id", planID, "count", len(input.Entries))
	return nil, ManagePlanOutput{
		Action:  "add_entries",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("added %d entries", len(input.Entries)),
	}, nil
}

func (s *Server) removePlanEntries(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if len(input.EntryIDs) == 0 {
		return nil, ManagePlanOutput{}, fmt.Errorf("entry_ids is required for remove_entries")
	}

	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}
	if p.Status != plan.StatusDraft {
		return nil, ManagePlanOutput{}, fmt.Errorf("remove_entries is only allowed on draft plans (use skip or substitute for active plans)")
	}

	entryIDs := make([]uuid.UUID, len(input.EntryIDs))
	for i, raw := range input.EntryIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("invalid entry_id %q: %w", raw, err)
		}
		entryIDs[i] = id
	}

	if err := s.plans.RemoveEntries(ctx, planID, entryIDs); err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("removing entries: %w", err)
	}

	s.logger.Info("manage_plan", "action", "remove_entries", "plan_id", planID, "count", len(entryIDs))
	return nil, ManagePlanOutput{
		Action:  "remove_entries",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("removed %d entries", len(entryIDs)),
	}, nil
}

// prepareCompleteEntryParams fills the completion-specific fields on params
// (CompletedAt, CompletedByAttemptID) and enforces the target-alignment
// audit for completed_by_attempt_id — the attempt MUST be on the plan
// entry's learning_target. Without this check, the audit trail is just
// "Claude said it was done" with no verifiable connection between attempt
// evidence and plan entry. Misaligned completions are rejected outright
// so plan progress metrics stay trustworthy.
func (s *Server) prepareCompleteEntryParams(ctx context.Context, planID, entryID uuid.UUID, input *ManagePlanInput, params *plan.UpdateEntryStatusParams) error {
	now := time.Now()
	params.CompletedAt = &now

	aid, err := parseOptionalUUID(input.CompletedByAttemptID, "completed_by_attempt_id")
	if err != nil {
		return err
	}
	params.CompletedByAttemptID = aid

	if aid == nil {
		s.logger.Warn("manage_plan: completed without attempt id",
			"plan_id", planID, "entry_id", entryID)
		return nil
	}

	entry, err := s.plans.Entry(ctx, entryID)
	if err != nil {
		return fmt.Errorf("fetching entry for alignment check: %w", err)
	}
	attempt, err := s.learn.AttemptByID(ctx, *aid)
	if err != nil {
		return fmt.Errorf("fetching completed_by_attempt for alignment check: %w", err)
	}
	if attempt.LearningTargetID != entry.LearningTargetID {
		return fmt.Errorf(
			"%w: completed_by_attempt_id %s is on learning_target %s but plan entry %s is on learning_target %s",
			learning.ErrInvalidInput, *aid, attempt.LearningTargetID, entryID, entry.LearningTargetID,
		)
	}
	return nil
}

func (s *Server) updatePlanEntry(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if input.EntryID == nil || *input.EntryID == "" {
		return nil, ManagePlanOutput{}, fmt.Errorf("entry_id is required for update_entry")
	}
	if input.Status == nil || *input.Status == "" {
		return nil, ManagePlanOutput{}, fmt.Errorf("status is required for update_entry")
	}
	if !isValidPlanEntryStatus(*input.Status) {
		return nil, ManagePlanOutput{}, fmt.Errorf("status for update_entry must be one of: completed, skipped, substituted (got %q)", *input.Status)
	}

	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}
	if p.Status != plan.StatusActive {
		return nil, ManagePlanOutput{}, fmt.Errorf("update_entry is only allowed on active plans (current: %s)", p.Status)
	}

	entryID, err := uuid.Parse(*input.EntryID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid entry_id: %w", err)
	}

	status := plan.EntryStatus(*input.Status)
	switch status {
	case plan.EntryCompleted, plan.EntrySkipped:
		params := plan.UpdateEntryStatusParams{
			ID:     entryID,
			Status: status,
			Reason: input.Reason,
		}
		if status == plan.EntryCompleted {
			if err := s.prepareCompleteEntryParams(ctx, planID, entryID, input, &params); err != nil {
				return nil, ManagePlanOutput{}, err
			}
		}
		if _, err = s.plans.UpdateEntryStatus(ctx, params); err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("updating entry to %s: %w", status, err)
		}

	case plan.EntrySubstituted:
		if err := s.mpSubstitute(ctx, planID, entryID, input); err != nil {
			return nil, ManagePlanOutput{}, err
		}

	default:
		return nil, ManagePlanOutput{}, fmt.Errorf("invalid entry status %q (valid: completed, skipped, substituted)", *input.Status)
	}

	s.logger.Info("manage_plan", "action", "update_entry", "plan_id", planID, "entry_id", entryID, "status", *input.Status)
	return nil, ManagePlanOutput{
		Action:  "update_entry",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("entry %s → %s", entryID, *input.Status),
	}, nil
}

func (s *Server) mpSubstitute(ctx context.Context, planID, entryID uuid.UUID, input *ManagePlanInput) error {
	if input.SubstituteLearningTargetID == nil || *input.SubstituteLearningTargetID == "" {
		return fmt.Errorf("substitute_learning_target_id is required for status=substituted")
	}
	subLTID, err := uuid.Parse(*input.SubstituteLearningTargetID)
	if err != nil {
		return fmt.Errorf("invalid substitute_learning_target_id: %w", err)
	}

	// Wrap in transaction — AddEntry + UpdateEntryStatus must be atomic.
	return s.withActorTx(ctx, func(tx pgx.Tx) error {
		txPlans := s.plans.WithTx(tx)

		entries, err := txPlans.Entries(ctx, planID)
		if err != nil {
			return fmt.Errorf("fetching plan entries: %w", err)
		}
		var nextPos int32
		if len(entries) > 0 {
			maxEntry := slices.MaxFunc(entries, func(a, b plan.Entry) int {
				return cmp.Compare(a.Position, b.Position)
			})
			nextPos = maxEntry.Position + 1
		}

		newEntry, err := txPlans.AddEntry(ctx, plan.AddEntryParams{
			PlanID:           planID,
			LearningTargetID: subLTID,
			Position:         nextPos,
		})
		if err != nil {
			return fmt.Errorf("adding substitute entry: %w", err)
		}

		if _, err := txPlans.UpdateEntryStatus(ctx, plan.UpdateEntryStatusParams{
			ID:            entryID,
			Status:        plan.EntrySubstituted,
			SubstitutedBy: &newEntry.ID,
			Reason:        input.Reason,
		}); err != nil {
			return fmt.Errorf("marking entry as substituted: %w", err)
		}
		return nil
	})
}

func (s *Server) reorderPlanEntries(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if len(input.Positions) == 0 {
		return nil, ManagePlanOutput{}, fmt.Errorf("positions is required for reorder")
	}

	for _, pos := range input.Positions {
		entryID, err := uuid.Parse(pos.EntryID)
		if err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("invalid entry_id %q: %w", pos.EntryID, err)
		}
		if err := s.plans.UpdateEntryPosition(ctx, entryID, pos.Position); err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("updating position for entry %s: %w", pos.EntryID, err)
		}
	}

	s.logger.Info("manage_plan", "action", "reorder", "plan_id", planID, "count", len(input.Positions))
	return nil, ManagePlanOutput{
		Action:  "reorder",
		PlanID:  planID.String(),
		Message: fmt.Sprintf("reordered %d entries", len(input.Positions)),
	}, nil
}

func (s *Server) updatePlan(ctx context.Context, planID uuid.UUID, input *ManagePlanInput) (*mcp.CallToolResult, ManagePlanOutput, error) {
	if input.Status == nil || *input.Status == "" {
		return nil, ManagePlanOutput{}, fmt.Errorf("status is required for update_plan")
	}
	if !isValidPlanStatus(*input.Status) {
		return nil, ManagePlanOutput{}, fmt.Errorf("status for update_plan must be one of: active, paused, completed, abandoned (got %q)", *input.Status)
	}

	// Fetch current plan to validate transition.
	p, err := s.plans.Plan(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}

	newStatus := plan.Status(*input.Status)
	if err := validatePlanTransition(p.Status, newStatus); err != nil {
		return nil, ManagePlanOutput{}, err
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

func (s *Server) planProgress(ctx context.Context, planID uuid.UUID) (*mcp.CallToolResult, ManagePlanOutput, error) {
	// Verify plan exists before computing progress — without this, a bogus
	// plan_id returns {total:0, entries:[]} which looks like an empty plan.
	// Every other mp* action already does this lookup; progress was the only
	// read path where a wrong plan_id silently succeeded.
	if _, err := s.plans.Plan(ctx, planID); err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan: %w", err)
	}

	progress, err := s.plans.Progress(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan progress: %w", err)
	}
	entries, err := s.plans.EntriesDetailed(ctx, planID)
	if err != nil {
		return nil, ManagePlanOutput{}, fmt.Errorf("fetching plan entries: %w", err)
	}

	s.logger.Info("manage_plan", "action", "progress", "plan_id", planID, "entry_count", len(entries))
	return nil, ManagePlanOutput{
		Action:   "progress",
		PlanID:   planID.String(),
		Message:  fmt.Sprintf("%d/%d completed", progress.Completed, progress.Total),
		Progress: progress,
		Entries:  entries,
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

// parseOptionalUUID lives in internal/mcp/uuid.go — consolidated helper
// shared with every MCP-boundary UUID parse call (track_hypothesis,
// manage_feeds, manage_plan, etc.).
