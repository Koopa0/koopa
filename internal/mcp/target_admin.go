// target_admin.go holds the manage_targets tool for learning target
// lifecycle operations. Currently only archive_target is wired;
// unarchive_target and richer actions land in follow-up commits per
// the C2 §B staged-shipping plan.
//
// Per project rule mcp-decision-policy §10, manage_targets is a
// multiplexer over actions on the same entity (learning_targets) —
// the cousin tools manage_concepts / manage_relations get their own
// multiplexers because dispatching on entity_type would be the
// flat-split anti-pattern.
//
// Authorization model (U2 self-bound):
//   - caller == row.created_by → permitted
//   - registry.Platform == "human" → permitted (override)
//   - otherwise → reject
//
// Same pattern as advance_work (requireTodoOwner) but with the row
// loaded from learning_targets instead of todos. Inline check keeps
// the package-doc rule "Self axis enforced inline" — no shared helper
// because the row source varies per tool.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/learning"
)

// ManageTargetsInput is the input for the manage_targets multiplexer.
//
// Action is the only required field. Per-action fields (TargetID for
// archive_target, etc.) are validated inside each branch so the schema
// stays a single envelope. CascadeRelations defaults to true — the
// design assumption is "archive a target = archive its outgoing
// relations so the graph never holds dangling edges" — but exposing
// the flag lets a caller archive a target while preserving its
// relations for forensic purposes (e.g. before bulk re-target).
type ManageTargetsInput struct {
	Action           string  `json:"action" jsonschema:"required" jsonschema_description:"Action: archive_target"`
	TargetID         *string `json:"target_id,omitempty" jsonschema_description:"Learning target UUID (required for archive_target)"`
	Reason           *string `json:"reason,omitempty" jsonschema_description:"Free-text reason for archive. Logged but not persisted on the target row (use agent_note(kind=context) for richer audit trails)."`
	CascadeRelations *bool   `json:"cascade_relations,omitempty" jsonschema_description:"When true (default), archive every learning_target_relations row referencing the target (anchor or related). Symmetric relations (same_pattern, similar_structure) are auto-cascaded both directions because the reverse edge sits in the same anchor|related filter. Pass false to leave the relation graph live so the target archives in isolation."`
	As               string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
}

// ManageTargetsOutput is the response shape. ArchivedTarget carries
// the post-archive row; CascadedRelations enumerates every relation
// row archived in the same batch so the caller can show "what got
// archived alongside the target" without a follow-up query.
//
// Named count fields (not a map) match the rest of the package's
// output convention — adding or removing a count is a visible diff,
// JSON key order is deterministic, and the wire field name follows
// snake_case without extra serialisation logic.
type ManageTargetsOutput struct {
	Action                 string                 `json:"action"`
	ArchivedTarget         *archivedTargetWire    `json:"archived_target,omitempty"`
	CascadedRelations      []archivedRelationWire `json:"cascaded_relations"`
	TargetCount            int                    `json:"target_count"`
	RelationsCascadedCount int                    `json:"relations_cascaded_count"`
}

type archivedTargetWire struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	Title          string `json:"title"`
	ArchivedAt     string `json:"archived_at"`
	ArchiveBatchID string `json:"archive_batch_id"`
}

type archivedRelationWire struct {
	ID             string `json:"id"`
	AnchorID       string `json:"anchor_id"`
	RelatedID      string `json:"related_id"`
	RelationType   string `json:"relation_type"`
	ArchivedAt     string `json:"archived_at"`
	ArchiveBatchID string `json:"archive_batch_id"`
}

func (s *Server) manageTargets(ctx context.Context, _ *mcp.CallToolRequest, input ManageTargetsInput) (*mcp.CallToolResult, ManageTargetsOutput, error) {
	switch input.Action {
	case "archive_target":
		return s.archiveTarget(ctx, &input)
	default:
		return nil, ManageTargetsOutput{}, fmt.Errorf("invalid action %q (valid: archive_target)", input.Action)
	}
}

func (s *Server) archiveTarget(ctx context.Context, input *ManageTargetsInput) (*mcp.CallToolResult, ManageTargetsOutput, error) {
	if input.TargetID == nil || *input.TargetID == "" {
		return nil, ManageTargetsOutput{}, fmt.Errorf("target_id is required for archive_target")
	}
	targetID, err := uuid.Parse(*input.TargetID)
	if err != nil {
		return nil, ManageTargetsOutput{}, fmt.Errorf("invalid target_id: %w", err)
	}

	// Pre-flight: load the row for ownership + archive-state check.
	// The TargetByID lookup does NOT filter archived; we need to
	// distinguish "not found" from "already archived" cleanly.
	existing, err := s.learn.TargetByID(ctx, targetID)
	switch {
	case errors.Is(err, learning.ErrNotFound):
		return nil, ManageTargetsOutput{}, fmt.Errorf("learning_target %s not found", targetID)
	case err != nil:
		return nil, ManageTargetsOutput{}, fmt.Errorf("looking up target %s: %w", targetID, err)
	case existing.IsArchived():
		return nil, ManageTargetsOutput{}, fmt.Errorf("%w: learning_target %s was already archived at %s", learning.ErrAlreadyArchived, targetID, existing.ArchivedAt.Format(time.RFC3339))
	}

	if err := s.requireTargetOwner(ctx, existing.CreatedBy); err != nil {
		return nil, ManageTargetsOutput{}, err
	}

	cascade := true
	if input.CascadeRelations != nil {
		cascade = *input.CascadeRelations
	}

	batchID := uuid.New()
	// Wrap the two UPDATEs (target + relations cascade) in one tx so a
	// pgx connection drop or context cancel between them can't leave
	// the target archived while its relations stay live — which would
	// break the archive_batch_id invariant that unarchive relies on
	// for batch-scoped restore. Per .claude/rules/database.md the tx
	// boundary lives in the handler.
	var (
		archived *learning.ArchivedTarget
		cascaded []learning.ArchivedRelation
	)
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		txStore := s.learn.WithTx(tx)
		var innerErr error
		archived, cascaded, innerErr = txStore.ArchiveTarget(ctx, targetID, batchID, cascade)
		return innerErr
	})
	if err != nil {
		if errors.Is(err, learning.ErrAlreadyArchived) {
			// Race with another caller that archived between our
			// pre-flight and the UPDATE inside the tx. The pre-flight
			// already returned ErrAlreadyArchived for the common case;
			// this branch is the sub-millisecond race. Wrap the
			// sentinel so callers can still errors.Is.
			return nil, ManageTargetsOutput{}, fmt.Errorf("%w: learning_target %s raced with concurrent archive after pre-flight", learning.ErrAlreadyArchived, targetID)
		}
		return nil, ManageTargetsOutput{}, fmt.Errorf("archiving target: %w", err)
	}

	reason := ""
	if input.Reason != nil {
		reason = *input.Reason
	}
	s.logger.Info("manage_targets",
		"action", "archive_target",
		"target_id", archived.ID,
		"batch_id", archived.ArchiveBatchID,
		"cascade_relations", cascade,
		"cascaded_count", len(cascaded),
		"caller", s.callerIdentity(ctx),
		"reason", reason)

	out := ManageTargetsOutput{
		Action: "archive_target",
		ArchivedTarget: &archivedTargetWire{
			ID:             archived.ID.String(),
			Domain:         archived.Domain,
			Title:          archived.Title,
			ArchivedAt:     archived.ArchivedAt.Format(time.RFC3339),
			ArchiveBatchID: archived.ArchiveBatchID.String(),
		},
		CascadedRelations:      relationsToWire(cascaded),
		TargetCount:            1,
		RelationsCascadedCount: len(cascaded),
	}
	return nil, out, nil
}

// requireTargetOwner enforces the U2 self-bound rule on learning
// targets: caller must match the row's created_by, with Platform=human
// as universal override. Parallel to requireTodoOwner (authz.go) —
// same primitive, different row source. See the package-doc Self-axis
// note for why this lives inline at the handler rather than as a
// shared helper.
//
// Like requireTodoOwner / requireAuthor, this gate uses callerIdentity
// (not ExplicitCallerIdentity) — the trust-model implications are
// consistent across the author/self axis.
func (s *Server) requireTargetOwner(ctx context.Context, owner string) error {
	name := s.callerIdentity(ctx)
	if name == owner {
		return nil
	}
	caller, ok := s.registry.Lookup(agent.Name(name))
	if !ok {
		return fmt.Errorf("manage_targets: caller %q is not registered", name)
	}
	if caller.Platform == "human" {
		return nil
	}
	return fmt.Errorf("manage_targets: caller %q is not the target owner; only the creator or human override may archive it", name)
}

// relationsToWire converts the Store DTO to the wire shape. Always
// returns a non-nil slice so the JSON envelope serialises cascaded_
// relations as [] when cascade was disabled or no relations existed.
func relationsToWire(rels []learning.ArchivedRelation) []archivedRelationWire {
	out := make([]archivedRelationWire, len(rels))
	for i := range rels {
		r := &rels[i]
		out[i] = archivedRelationWire{
			ID:             r.ID.String(),
			AnchorID:       r.AnchorID.String(),
			RelatedID:      r.RelatedID.String(),
			RelationType:   r.RelationType,
			ArchivedAt:     r.ArchivedAt.Format(time.RFC3339),
			ArchiveBatchID: r.ArchiveBatchID.String(),
		}
	}
	return out
}
