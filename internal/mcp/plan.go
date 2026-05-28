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
	"strings"
	"time"
	"unicode/utf8"

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
	Reason                     *string `json:"reason,omitempty" jsonschema_description:"Justification for the transition. REQUIRED and non-blank when status=completed OR status=skipped; this is the audit trail per mcp-decision-policy §13 (skip is a decision — cross-agent review needs to know why an active plan entry was dropped). When force=true (completed only), reason MUST start with the literal text manual override: (no surrounding quotes) and be ≥ 60 characters. Reason is capped at 1024 characters."`
	SubstituteLearningTargetID *string `json:"substitute_learning_target_id,omitempty" jsonschema_description:"learning_targets.id of the replacement (for status=substituted)"`
	CompletedByAttemptID       *string `json:"completed_by_attempt_id,omitempty" jsonschema_description:"Attempt UUID that informed the completion decision. REQUIRED when status=completed unless force=true. The attempt's learning_target_id MUST match the plan entry's — misaligned IDs are rejected so the audit trail stays trustworthy."`
	Force                      *bool   `json:"force,omitempty" jsonschema_description:"Escape hatch for status=completed when no aligned attempt exists (plan retconned, target migrated, etc.). When true, completed_by_attempt_id may be omitted, but reason MUST start with the literal text manual override: (no surrounding quotes) and be ≥ 60 characters so the deviation is loud in the audit trail. Use sparingly — the normal path provides verifiable evidence; force replaces evidence with a written justification."`

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
			ltID, err = s.learn.FindOrCreateTarget(ctx, p.Domain, entry.Title, entry.ExternalID, entry.Difficulty, s.callerIdentity(ctx))
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

// validateUpdateEntryInput runs the cheap up-front checks for
// update_entry: entry_id and status presence, status enum membership,
// and the force-only-with-completed rule. Plan-state and entry-id
// parsing happen separately because they require store calls.
func validateUpdateEntryInput(input *ManagePlanInput) error {
	if input.EntryID == nil || *input.EntryID == "" {
		return fmt.Errorf("entry_id is required for update_entry")
	}
	if input.Status == nil || *input.Status == "" {
		return fmt.Errorf("status is required for update_entry")
	}
	if !isValidPlanEntryStatus(*input.Status) {
		return fmt.Errorf("status for update_entry must be one of: completed, skipped, substituted (got %q)", *input.Status)
	}
	// force is only meaningful for status=completed; reject elsewhere
	// so a caller who mistakenly leaves the flag set on a different
	// transition gets an explicit error instead of a silently-ignored
	// override request.
	if input.Force != nil && *input.Force && *input.Status != string(plan.EntryCompleted) {
		return fmt.Errorf("force=true is only valid with status=completed (got status=%q)", *input.Status)
	}
	return nil
}

// trimOptional applies strings.TrimSpace through an optional string,
// preserving nil. Used to normalise caller-supplied reason fields so
// audit text doesn't carry copy-paste leading/trailing whitespace.
func trimOptional(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	return &t
}

// forceReasonPrefix is the required leader on the reason string when
// completion is forced via input.Force. The prefix makes audit-log greps
// for the literal text `manual override:` reliable across the plan
// lifecycle. Caller-facing messages refer to it without surrounding
// quotes so a copy-paste of the hint produces a string that actually
// matches HasPrefix.
const forceReasonPrefix = "manual override:"

// forceReasonMinLength is the minimum reason length when force=true.
// 60 is chosen for audit-log readability rather than caller ergonomics:
// force completions are rare (escape hatch for plan retcon / target
// migration), but every one ends up grep'd later by Koopa during
// weekly review. A reason that lands under 60 runes tends to be a
// vague tag ("manual override: target retcon") that requires the
// reader to join activity_events back to source rows; a reason that
// reaches 60 typically self-explains the what/which. Asymmetric cost:
// caller pays 30s extra writing once, reader saves 5min reconstruction
// per visit — the right side to optimise. Dial down to 45 if 60 feels
// too tight in practice; dialing up later breaks any short reasons
// already written, while dialing down does not.
const forceReasonMinLength = 60

// reasonMaxLength caps the reason string so a misbehaving caller can't
// stuff structured logs by passing a multi-megabyte justification. The
// cap is generous (1 KB) — any legitimate audit reason fits well under.
const reasonMaxLength = 1024

// validateSkipEntryReason enforces the non-blank reason requirement for
// status=skipped transitions. Audit-trail parity with completed: cross-agent
// review must distinguish "skipped because solved offline" from "skipped
// because target archived" from "skipped because plan retconned". Skip is
// rare in normal usage; the friction of one sentence is dwarfed by the
// value of reconstructing decisions weeks later (mcp-decision-policy §13).
//
// Unlike completion, skip has no force-mode escape hatch — the "no aligned
// attempt exists" justification for completion forces doesn't apply to
// skip (skip means "we did not do this", not "we did this but the evidence
// is somewhere else"). A skip with no rationale should not be auditable
// as anything other than missing data.
func validateSkipEntryReason(reason string) error {
	if reason == "" {
		return fmt.Errorf("%w: reason is required when marking entry skipped (audit-trail policy mcp-decision-policy §13 — skip is a decision; cross-agent review needs to know why an active plan entry was dropped)", learning.ErrInvalidInput)
	}
	if utf8.RuneCountInString(reason) > reasonMaxLength {
		return fmt.Errorf("%w: reason exceeds %d characters (got %d) — keep audit text concise", learning.ErrInvalidInput, reasonMaxLength, utf8.RuneCountInString(reason))
	}
	return nil
}

// validateCompleteEntryReason enforces the reason-string contract for
// status=completed transitions. Normal path requires non-blank text;
// forced path requires both forceReasonPrefix and forceReasonMinLength
// so the manual override is structurally distinguishable from a normal
// completion in audit-log greps. Both paths reject reasons over
// reasonMaxLength.
func validateCompleteEntryReason(reason string, forced bool) error {
	if utf8.RuneCountInString(reason) > reasonMaxLength {
		return fmt.Errorf("%w: reason exceeds %d characters (got %d) — keep audit text concise", learning.ErrInvalidInput, reasonMaxLength, utf8.RuneCountInString(reason))
	}
	if !forced {
		if reason == "" {
			return fmt.Errorf("%w: reason is required when marking entry completed (audit-trail policy mcp-decision-policy.md §13)", learning.ErrInvalidInput)
		}
		return nil
	}
	if !strings.HasPrefix(reason, forceReasonPrefix) {
		return fmt.Errorf("%w: force=true requires reason to start with the literal text %s (got %q)", learning.ErrInvalidInput, forceReasonPrefix, reason)
	}
	if n := utf8.RuneCountInString(reason); n < forceReasonMinLength {
		return fmt.Errorf("%w: force=true requires reason length ≥ %d characters (got %d)", learning.ErrInvalidInput, forceReasonMinLength, n)
	}
	return nil
}

// prepareCompleteEntryParams fills the completion-specific fields on params
// (CompletedAt, CompletedByAttemptID) and enforces the audit-trail policy
// for plan-entry completion (mcp-decision-policy §13).
//
// Normal path (force=false / unset):
//   - completed_by_attempt_id REQUIRED — hard reject if missing.
//   - reason REQUIRED and non-blank.
//   - The attempt's learning_target_id MUST match the plan entry's. The
//     alignment check is the audit trail: every completion has verifiable
//     evidence in learning_attempts. Without this, "Claude said it was
//     done" is unfalsifiable.
//
// Force path (force=true):
//   - Designed for the rare cases where no aligned attempt exists (plan
//     retconned, target migrated, completion logged out of band).
//   - completed_by_attempt_id MAY be nil; alignment check is skipped.
//   - reason MUST start with forceReasonPrefix and meet
//     forceReasonMinLength so the deviation is a loud audit signal,
//     not a quiet bypass.
//
// activity_events.payload carries 'reason' (audit_learning_plan_entries
// trigger), so the audit distinction between forced and evidence-backed
// completions is structurally visible in the append-only log: a forced
// row has reason starting with forceReasonPrefix, an evidence-backed
// row carries the coach's free-text justification. completed_by_attempt_id
// is also in the payload — null on the force path, non-null otherwise.
func (s *Server) prepareCompleteEntryParams(ctx context.Context, planID, entryID uuid.UUID, input *ManagePlanInput, params *plan.UpdateEntryStatusParams) error {
	reason := ""
	if input.Reason != nil {
		reason = strings.TrimSpace(*input.Reason)
	}
	forced := input.Force != nil && *input.Force
	if err := validateCompleteEntryReason(reason, forced); err != nil {
		return err
	}
	// Persist the trimmed reason so the audit log doesn't carry trailing
	// whitespace from caller-side string concatenation. CompletedAt is
	// set after validation passes so a rejected call doesn't leave a
	// half-populated params struct that a future refactor might leak.
	params.Reason = &reason
	now := time.Now()
	params.CompletedAt = &now

	aid, err := parseOptionalUUID(input.CompletedByAttemptID, "completed_by_attempt_id")
	if err != nil {
		return err
	}
	params.CompletedByAttemptID = aid

	if aid == nil {
		if forced {
			s.logger.Info("manage_plan: forced completion without attempt id",
				"plan_id", planID, "entry_id", entryID, "reason", reason)
			return nil
		}
		return fmt.Errorf("%w: completed_by_attempt_id is required when marking entry completed (use force=true with a reason starting with %s if no aligned attempt exists)", learning.ErrInvalidInput, forceReasonPrefix)
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
	if err := validateUpdateEntryInput(input); err != nil {
		return nil, ManagePlanOutput{}, err
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
	case plan.EntryCompleted:
		params := plan.UpdateEntryStatusParams{
			ID:     entryID,
			Status: status,
			Reason: trimOptional(input.Reason),
		}
		if err := s.prepareCompleteEntryParams(ctx, planID, entryID, input, &params); err != nil {
			return nil, ManagePlanOutput{}, err
		}
		if _, err = s.plans.UpdateEntryStatus(ctx, params); err != nil {
			return nil, ManagePlanOutput{}, fmt.Errorf("updating entry to %s: %w", status, err)
		}

	case plan.EntrySkipped:
		reason := ""
		if input.Reason != nil {
			reason = strings.TrimSpace(*input.Reason)
		}
		if err := validateSkipEntryReason(reason); err != nil {
			return nil, ManagePlanOutput{}, err
		}
		params := plan.UpdateEntryStatusParams{
			ID:     entryID,
			Status: status,
			Reason: &reason,
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
