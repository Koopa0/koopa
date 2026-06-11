// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning/hypothesis"
)

// --- draft_hypothesis ---

// DraftHypothesisInput is the input for the draft_hypothesis tool. The
// created row always lands in state=draft — the v3.1 inert-drafts contract:
// the agent prepares material, only the owner makes it count (endorsement,
// verdicts, and deletion live in the admin UI, off the MCP surface).
type DraftHypothesisInput struct {
	Claim                 string  `json:"claim" jsonschema:"required" jsonschema_description:"One-line falsifiable prediction. Required — a hypothesis without a claim is not a hypothesis."`
	InvalidationCondition string  `json:"invalidation_condition" jsonschema:"required" jsonschema_description:"What evidence would disprove the claim. Required — a hypothesis without one is not falsifiable."`
	ObservedDate          *string `json:"observed_date,omitempty" jsonschema_description:"Date the pattern was first observed, YYYY-MM-DD. Defaults to today."`
	Content               string  `json:"content,omitempty" jsonschema_description:"Optional supporting narrative. claim is the one-line prediction; content is the analysis behind it."`
}

// DraftHypothesisOutput is the output of the draft_hypothesis tool.
type DraftHypothesisOutput struct {
	Hypothesis hypothesis.Record `json:"hypothesis"`
}

func (s *Server) draftHypothesis(ctx context.Context, _ *mcp.CallToolRequest, input DraftHypothesisInput) (*mcp.CallToolResult, DraftHypothesisOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "draft_hypothesis"); err != nil {
		return nil, DraftHypothesisOutput{}, err
	}
	if err := hypothesis.ValidateDraftFields(input.Claim, input.InvalidationCondition, input.Content); err != nil {
		return nil, DraftHypothesisOutput{}, err
	}

	observed := s.today()
	if input.ObservedDate != nil && *input.ObservedDate != "" {
		t, err := time.Parse(time.DateOnly, *input.ObservedDate)
		if err != nil {
			return nil, DraftHypothesisOutput{}, fmt.Errorf("invalid observed_date %q (expected YYYY-MM-DD): %w", *input.ObservedDate, err)
		}
		observed = t
	}

	var created *hypothesis.Record
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		created, err = s.hypotheses.WithTx(tx).Create(ctx, &hypothesis.CreateParams{
			CreatedBy:             s.callerIdentity(ctx),
			Content:               input.Content,
			Claim:                 input.Claim,
			InvalidationCondition: input.InvalidationCondition,
			ObservedDate:          observed,
			State:                 hypothesis.StateDraft,
		})
		return err
	})
	if err != nil {
		return nil, DraftHypothesisOutput{}, fmt.Errorf("drafting hypothesis: %w", err)
	}

	s.logger.Info("draft_hypothesis", "hypothesis_id", created.ID, "created_by", created.CreatedBy)
	return nil, DraftHypothesisOutput{Hypothesis: *created}, nil
}
