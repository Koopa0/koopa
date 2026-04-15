package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/hypothesis"
)

// --- track_insight ---
//
// MCP tool name stays track_insight for Cowork instruction compatibility.
// The underlying entity is hypothesis.Record — the "insight" vocabulary is
// being retired from the DB but the tool surface is stable.

// TrackInsightInput is the input for the track_insight tool.
type TrackInsightInput struct {
	InsightID FlexInt        `json:"insight_id" jsonschema:"required" jsonschema_description:"Hypothesis ID to update"`
	Action    string         `json:"action" jsonschema:"required" jsonschema_description:"Action: verify, invalidate, archive, add_evidence"`
	Evidence  map[string]any `json:"evidence,omitempty" jsonschema_description:"Evidence data (for add_evidence action)"`
}

// TrackInsightOutput is the output of the track_insight tool.
type TrackInsightOutput struct {
	Insight hypothesis.Record `json:"insight"`
	Updated bool              `json:"updated"`
}

func (s *Server) trackInsight(ctx context.Context, _ *mcp.CallToolRequest, input TrackInsightInput) (*mcp.CallToolResult, TrackInsightOutput, error) {
	id := int64(input.InsightID)
	if id <= 0 {
		return nil, TrackInsightOutput{}, fmt.Errorf("valid insight_id is required")
	}

	switch input.Action {
	case "verify":
		return s.updateHypothesisState(ctx, id, hypothesis.StateVerified)
	case "invalidate":
		return s.updateHypothesisState(ctx, id, hypothesis.StateInvalidated)
	case "archive":
		return s.updateHypothesisState(ctx, id, hypothesis.StateArchived)
	case "add_evidence":
		return s.addHypothesisEvidence(ctx, id, input.Evidence)
	default:
		return nil, TrackInsightOutput{}, fmt.Errorf("invalid action %q (valid: verify, invalidate, archive, add_evidence)", input.Action)
	}
}

func (s *Server) updateHypothesisState(ctx context.Context, id int64, state hypothesis.State) (*mcp.CallToolResult, TrackInsightOutput, error) {
	rec, err := s.hypotheses.UpdateState(ctx, id, state)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("updating hypothesis state: %w", err)
	}
	s.logger.Info("track_insight", "id", id, "action", string(state))
	return nil, TrackInsightOutput{Insight: *rec, Updated: true}, nil
}

func (s *Server) addHypothesisEvidence(ctx context.Context, id int64, evidence map[string]any) (*mcp.CallToolResult, TrackInsightOutput, error) {
	current, err := s.hypotheses.RecordByID(ctx, id)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("fetching hypothesis: %w", err)
	}

	meta := current.Metadata
	if meta == nil {
		meta = make(map[string]any)
	}

	var existing []any
	if v, ok := meta["supporting_evidence"].([]any); ok {
		existing = v
	}
	existing = append(existing, evidence)
	meta["supporting_evidence"] = existing

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("marshaling metadata: %w", err)
	}

	rec, err := s.hypotheses.UpdateMetadata(ctx, id, metaJSON)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("updating hypothesis metadata: %w", err)
	}

	s.logger.Info("track_insight", "id", id, "action", "add_evidence")
	return nil, TrackInsightOutput{Insight: *rec, Updated: true}, nil
}
