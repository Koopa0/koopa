package mcp

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/daily"
	"github.com/Koopa0/koopa0.dev/internal/journal"
)

// --- reflection_context ---

// ReflectionContextInput is the input for the reflection_context tool.
type ReflectionContextInput struct {
	Date *string `json:"date,omitempty" jsonschema_description:"Target date YYYY-MM-DD (default: today)"`
}

// ReflectionContextOutput is the output of the reflection_context tool.
type ReflectionContextOutput struct {
	Date           string          `json:"date"`
	PlannedItems   []daily.Item    `json:"planned_items"`
	CompletedCount int             `json:"completed_count"`
	DeferredCount  int             `json:"deferred_count"`
	PlannedCount   int             `json:"planned_count"`
	CompletionRate float64         `json:"completion_rate"`
	TodayJournals  []journal.Entry `json:"today_journals"`
	TodayPlan      *journal.Entry  `json:"today_plan,omitempty"`
}

func (s *Server) reflectionContext(ctx context.Context, _ *mcp.CallToolRequest, input ReflectionContextInput) (*mcp.CallToolResult, ReflectionContextOutput, error) {
	date := s.today()
	if input.Date != nil && *input.Date != "" {
		t, err := time.Parse(time.DateOnly, *input.Date)
		if err != nil {
			return nil, ReflectionContextOutput{}, err
		}
		date = t
	}

	out := ReflectionContextOutput{Date: date.Format(time.DateOnly)}

	// Today's daily plan items with status
	if items, err := s.dayplan.ItemsByDate(ctx, date); err == nil {
		out.PlannedItems = items
		for i := range items {
			switch items[i].Status {
			case daily.StatusDone:
				out.CompletedCount++
			case daily.StatusDeferred:
				out.DeferredCount++
			case daily.StatusPlanned:
				out.PlannedCount++
			case daily.StatusDropped:
				// dropped items are not counted in any category
			}
		}
		total := len(items)
		if total > 0 {
			out.CompletionRate = float64(out.CompletedCount) / float64(total)
		}
	} else {
		s.logger.Warn("reflection_context: plan items", "error", err)
	}

	// Today's journal entries
	if entries, err := s.journal.EntriesByDateRange(ctx, date, date, nil, nil); err == nil {
		out.TodayJournals = entries
		for i := range entries {
			if entries[i].Kind == journal.KindPlan {
				out.TodayPlan = &entries[i]
				break
			}
		}
	} else {
		s.logger.Warn("reflection_context: journals", "error", err)
	}

	return nil, out, nil
}
