package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/insight"
)

// --- track_insight ---

// TrackInsightInput is the input for the track_insight tool.
type TrackInsightInput struct {
	InsightID FlexInt        `json:"insight_id" jsonschema:"required" jsonschema_description:"Insight ID to update"`
	Action    string         `json:"action" jsonschema:"required" jsonschema_description:"Action: verify, invalidate, archive, add_evidence"`
	Evidence  map[string]any `json:"evidence,omitempty" jsonschema_description:"Evidence data (for add_evidence action)"`
}

// TrackInsightOutput is the output of the track_insight tool.
type TrackInsightOutput struct {
	Insight insight.Insight `json:"insight"`
	Updated bool            `json:"updated"`
}

func (s *Server) trackInsight(ctx context.Context, _ *mcp.CallToolRequest, input TrackInsightInput) (*mcp.CallToolResult, TrackInsightOutput, error) {
	id := int64(input.InsightID)
	if id <= 0 {
		return nil, TrackInsightOutput{}, fmt.Errorf("valid insight_id is required")
	}

	switch input.Action {
	case "verify":
		return s.updateInsightStatus(ctx, id, insight.StatusVerified)
	case "invalidate":
		return s.updateInsightStatus(ctx, id, insight.StatusInvalidated)
	case "archive":
		return s.updateInsightStatus(ctx, id, insight.StatusArchived)
	case "add_evidence":
		return s.addInsightEvidence(ctx, id, input.Evidence)
	default:
		return nil, TrackInsightOutput{}, fmt.Errorf("invalid action %q (valid: verify, invalidate, archive, add_evidence)", input.Action)
	}
}

func (s *Server) updateInsightStatus(ctx context.Context, id int64, status insight.Status) (*mcp.CallToolResult, TrackInsightOutput, error) {
	ins, err := s.insights.UpdateStatus(ctx, id, status)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("updating insight status: %w", err)
	}
	s.logger.Info("track_insight", "id", id, "action", string(status))
	return nil, TrackInsightOutput{Insight: *ins, Updated: true}, nil
}

func (s *Server) addInsightEvidence(ctx context.Context, id int64, evidence map[string]any) (*mcp.CallToolResult, TrackInsightOutput, error) {
	// Fetch current insight to merge evidence into metadata.
	current, err := s.insights.ByID(ctx, id)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("fetching insight: %w", err)
	}

	meta := current.Metadata
	if meta == nil {
		meta = make(map[string]any)
	}

	// Append evidence to supporting_evidence array.
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

	ins, err := s.insights.UpdateMetadata(ctx, id, metaJSON)
	if err != nil {
		return nil, TrackInsightOutput{}, fmt.Errorf("updating insight metadata: %w", err)
	}

	s.logger.Info("track_insight", "id", id, "action", "add_evidence")
	return nil, TrackInsightOutput{Insight: *ins, Updated: true}, nil
}
