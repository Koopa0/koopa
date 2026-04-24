package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning/hypothesis"
)

// mcpMaxEvidenceSize caps a single track_hypothesis(add_evidence) entry's
// JSON payload at 32 KB. Mirrors the HTTP admin path's maxEvidenceSize so
// the atomic AppendEvidence path sees the same bound regardless of
// transport. The cap applies to the per-request entry, not the
// accumulated metadata blob.
const mcpMaxEvidenceSize = 32 * 1024

// --- track_hypothesis ---

// TrackHypothesisInput is the input for the track_hypothesis tool.
//
// For verify/invalidate actions at least one of ResolvedByAttemptID,
// ResolvedByObservationID, or a non-blank ResolutionSummary MUST be
// supplied. The handler enforces this before calling the store so
// chk_hypothesis_resolution is never relied upon for validation
// feedback. Archive does not require evidence and stays on UpdateState.
type TrackHypothesisInput struct {
	HypothesisID            string         `json:"hypothesis_id" jsonschema:"required" jsonschema_description:"Hypothesis UUID to update"`
	Action                  string         `json:"action" jsonschema:"required" jsonschema_description:"Action: verify, invalidate, archive, add_evidence"`
	Evidence                map[string]any `json:"evidence,omitempty" jsonschema_description:"Evidence data (for add_evidence action)"`
	ResolvedByAttemptID     *string        `json:"resolved_by_attempt_id,omitempty" jsonschema_description:"Attempt UUID that resolved the hypothesis (for verify/invalidate)"`
	ResolvedByObservationID *string        `json:"resolved_by_observation_id,omitempty" jsonschema_description:"Observation UUID that resolved the hypothesis (for verify/invalidate)"`
	ResolutionSummary       *string        `json:"resolution_summary,omitempty" jsonschema_description:"Free-text summary of how the hypothesis was resolved (for verify/invalidate, max 2 KB)"`
}

// TrackHypothesisOutput is the output of the track_hypothesis tool.
type TrackHypothesisOutput struct {
	Hypothesis hypothesis.Record `json:"hypothesis"`
	Updated    bool              `json:"updated"`
}

func (s *Server) trackHypothesis(ctx context.Context, _ *mcp.CallToolRequest, input TrackHypothesisInput) (*mcp.CallToolResult, TrackHypothesisOutput, error) {
	id, err := uuid.Parse(input.HypothesisID)
	if err != nil {
		return nil, TrackHypothesisOutput{}, fmt.Errorf("invalid hypothesis_id: %w", err)
	}

	switch input.Action {
	case "verify":
		return s.resolveHypothesis(ctx, id, hypothesis.StateVerified, input)
	case "invalidate":
		return s.resolveHypothesis(ctx, id, hypothesis.StateInvalidated, input)
	case "archive":
		return s.archiveHypothesis(ctx, id)
	case "add_evidence":
		return s.addHypothesisEvidence(ctx, id, input.Evidence)
	default:
		return nil, TrackHypothesisOutput{}, fmt.Errorf("invalid action %q (valid: verify, invalidate, archive, add_evidence)", input.Action)
	}
}

// resolveHypothesis routes a verify/invalidate transition through
// hypothesis.Store.UpdateResolution. UpdateState cannot be used here —
// transitions to verified/invalidated require evidence to satisfy
// chk_hypothesis_resolution, and UpdateState does not write the
// evidence columns.
func (s *Server) resolveHypothesis(ctx context.Context, id uuid.UUID, state hypothesis.State, input TrackHypothesisInput) (*mcp.CallToolResult, TrackHypothesisOutput, error) {
	params, err := parseResolveInput(input)
	if err != nil {
		return nil, TrackHypothesisOutput{}, err
	}

	rec, err := s.hypotheses.UpdateResolution(ctx, id, state, params)
	if err != nil {
		if errors.Is(err, hypothesis.ErrNotFound) {
			return nil, TrackHypothesisOutput{}, fmt.Errorf("hypothesis not found")
		}
		if errors.Is(err, hypothesis.ErrEvidenceRequired) {
			return nil, TrackHypothesisOutput{}, fmt.Errorf("at least one of resolved_by_attempt_id, resolved_by_observation_id, or resolution_summary is required")
		}
		if errors.Is(err, hypothesis.ErrEvidenceNotFound) {
			return nil, TrackHypothesisOutput{}, fmt.Errorf("referenced attempt or observation not found")
		}
		return nil, TrackHypothesisOutput{}, fmt.Errorf("resolving hypothesis: %w", err)
	}
	s.logger.Info("track_hypothesis", "id", id, "action", string(state))
	return nil, TrackHypothesisOutput{Hypothesis: *rec, Updated: true}, nil
}

// archiveHypothesis drives a transition to the archived state. Archive
// does not require evidence so it stays on the UpdateState path.
func (s *Server) archiveHypothesis(ctx context.Context, id uuid.UUID) (*mcp.CallToolResult, TrackHypothesisOutput, error) {
	rec, err := s.hypotheses.UpdateState(ctx, id, hypothesis.StateArchived)
	if err != nil {
		if errors.Is(err, hypothesis.ErrNotFound) {
			return nil, TrackHypothesisOutput{}, fmt.Errorf("hypothesis not found")
		}
		return nil, TrackHypothesisOutput{}, fmt.Errorf("updating hypothesis state: %w", err)
	}
	s.logger.Info("track_hypothesis", "id", id, "action", string(hypothesis.StateArchived))
	return nil, TrackHypothesisOutput{Hypothesis: *rec, Updated: true}, nil
}

// parseResolveInput adapts the MCP input envelope to the shared
// hypothesis.ValidateResolveInput helper and reformats its typed
// errors into MCP-facing messages. The validator enforces the
// invariants once; this function only handles transport translation
// (MCP returns a Go error directly; HTTP writes to api.Error).
//
// Error shape mirrors the HTTP handler so clients see a consistent
// contract regardless of transport: UUID errors name the field
// without leaking uuid.Parse internals, oversize summaries report
// the cap, and the "at least one source" message spells out the
// three candidate fields.
func parseResolveInput(input TrackHypothesisInput) (hypothesis.ResolveParams, error) {
	params, err := hypothesis.ValidateResolveInput(input.ResolvedByAttemptID, input.ResolvedByObservationID, input.ResolutionSummary)
	if err != nil {
		if fieldErr, ok := errors.AsType[*hypothesis.InvalidEvidenceIDError](err); ok {
			return hypothesis.ResolveParams{}, fmt.Errorf("invalid %s", fieldErr.Field)
		}
		switch {
		case errors.Is(err, hypothesis.ErrResolutionSummaryTooLong):
			return hypothesis.ResolveParams{}, fmt.Errorf("resolution_summary too large (max %d bytes)", hypothesis.MaxResolutionSummary)
		case errors.Is(err, hypothesis.ErrResolutionSummaryInvalid):
			return hypothesis.ResolveParams{}, fmt.Errorf("resolution_summary contains control characters")
		case errors.Is(err, hypothesis.ErrEvidenceRequired):
			return hypothesis.ResolveParams{}, fmt.Errorf("at least one of resolved_by_attempt_id, resolved_by_observation_id, or resolution_summary is required")
		}
		return hypothesis.ResolveParams{}, err
	}
	return params, nil
}

// addHypothesisEvidence appends a single evidence entry atomically via
// hypothesis.Store.AppendEvidence. The legacy read-modify-write path
// through UpdateMetadata raced under Read Committed — two concurrent
// MCP posts could each read the same metadata, each append, and the
// second write would overwrite the first silently. AppendEvidence
// pushes the concat into a single jsonb_set UPDATE so PostgreSQL
// serializes the append at row level.
//
// Contract mirrors the HTTP AddEvidence handler: evidence.type must be
// "supporting" or "counter", the marshaled entry is capped at
// mcpMaxEvidenceSize (32 KB), and the JSON object is persisted as-is.
func (s *Server) addHypothesisEvidence(ctx context.Context, id uuid.UUID, evidence map[string]any) (*mcp.CallToolResult, TrackHypothesisOutput, error) {
	if evidence == nil {
		return nil, TrackHypothesisOutput{}, fmt.Errorf("evidence is required")
	}
	evidenceType, _ := evidence["type"].(string)
	if evidenceType != "supporting" && evidenceType != "counter" {
		return nil, TrackHypothesisOutput{}, fmt.Errorf("evidence.type must be supporting or counter")
	}

	entryJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, TrackHypothesisOutput{}, fmt.Errorf("marshaling evidence entry: %w", err)
	}
	if len(entryJSON) > mcpMaxEvidenceSize {
		return nil, TrackHypothesisOutput{}, fmt.Errorf("evidence too large (max %d bytes)", mcpMaxEvidenceSize)
	}

	rec, err := s.hypotheses.AppendEvidence(ctx, id, evidenceType, entryJSON)
	if err != nil {
		if errors.Is(err, hypothesis.ErrNotFound) {
			return nil, TrackHypothesisOutput{}, fmt.Errorf("hypothesis not found")
		}
		return nil, TrackHypothesisOutput{}, fmt.Errorf("appending hypothesis evidence: %w", err)
	}

	s.logger.Info("track_hypothesis", "id", id, "action", "add_evidence")
	return nil, TrackHypothesisOutput{Hypothesis: *rec, Updated: true}, nil
}
