package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/weekly"
)

// --- weekly_summary ---
//
// Delegates to internal/weekly.Compute, which is the single source of
// truth for weekly review aggregation. The mastery rows are appended
// here because they are a learning-domain projection that lives outside
// the weekly package's responsibility.

// WeeklySummaryInput is the input for the weekly_summary tool.
type WeeklySummaryInput struct {
	WeekOf *string `json:"week_of,omitempty" jsonschema_description:"Monday of the target week YYYY-MM-DD (default: current week)"`
}

// WeeklySummaryOutput is the output of the weekly_summary tool.
type WeeklySummaryOutput struct {
	Review  weekly.Review `json:"review"`
	Mastery []MasteryRow  `json:"mastery"`
}

func (s *Server) weeklySummary(ctx context.Context, _ *mcp.CallToolRequest, input WeeklySummaryInput) (*mcp.CallToolResult, WeeklySummaryOutput, error) {
	now := time.Now().In(s.loc)
	weekStart := weekly.MondayOf(now)
	if input.WeekOf != nil && *input.WeekOf != "" {
		t, err := time.Parse(time.DateOnly, *input.WeekOf)
		if err != nil {
			return nil, WeeklySummaryOutput{}, fmt.Errorf("invalid week_of date: %w", err)
		}
		weekStart = weekly.MondayOf(t.In(s.loc))
	}

	review, err := weekly.Compute(ctx, s.todos, s.agentNotes, s.learn, weekStart)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("computing weekly review: %w", err)
	}

	masteryRaw, err := s.learn.ConceptMastery(ctx, nil, weekStart, "high")
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying concept mastery: %w", err)
	}

	return nil, WeeklySummaryOutput{
		Review:  review,
		Mastery: toMasteryRows(masteryRaw),
	}, nil
}
