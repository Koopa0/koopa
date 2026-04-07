package mcp

import (
	"context"
	"fmt"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learnsession"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// --- weekly_summary ---

// WeeklySummaryInput is the input for the weekly_summary tool.
type WeeklySummaryInput struct {
	WeekOf *string `json:"week_of,omitempty" jsonschema_description:"Monday of the target week YYYY-MM-DD (default: current week)"`
}

// WeeklySummaryOutput is the output of the weekly_summary tool.
type WeeklySummaryOutput struct {
	WeekStart      string                           `json:"week_start"`
	WeekEnd        string                           `json:"week_end"`
	TasksCreated   int                              `json:"tasks_created"`
	TasksCompleted []task.CompletedTaskDetail       `json:"tasks_completed"`
	JournalEntries []journal.Entry                  `json:"journal_entries"`
	Sessions       []learnsession.Session           `json:"sessions"`
	Mastery        []learnsession.ConceptMasteryRow `json:"mastery"`
}

func (s *Server) weeklySummary(ctx context.Context, _ *sdkmcp.CallToolRequest, input WeeklySummaryInput) (*sdkmcp.CallToolResult, WeeklySummaryOutput, error) {
	now := time.Now().In(s.loc)
	weekStart := mondayOf(now)
	if input.WeekOf != nil && *input.WeekOf != "" {
		t, err := time.Parse(time.DateOnly, *input.WeekOf)
		if err != nil {
			return nil, WeeklySummaryOutput{}, fmt.Errorf("invalid week_of date: %w", err)
		}
		weekStart = mondayOf(t)
	}
	weekEnd := weekStart.AddDate(0, 0, 7)

	completed, err := s.tasks.CompletedTasksDetailSince(ctx, weekStart)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying completed tasks: %w", err)
	}

	created, err := s.tasks.TasksCreatedSince(ctx, weekStart)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying created tasks: %w", err)
	}

	journals, err := s.journal.EntriesByDateRange(ctx, weekStart, weekEnd, nil, nil)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying journal entries: %w", err)
	}

	sessions, err := s.learn.RecentSessions(ctx, nil, weekStart, 100)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying learning sessions: %w", err)
	}

	mastery, err := s.learn.ConceptMastery(ctx, nil, weekStart)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying concept mastery: %w", err)
	}

	return nil, WeeklySummaryOutput{
		WeekStart:      weekStart.Format(time.DateOnly),
		WeekEnd:        weekEnd.Format(time.DateOnly),
		TasksCreated:   len(created),
		TasksCompleted: completed,
		JournalEntries: journals,
		Sessions:       sessions,
		Mastery:        mastery,
	}, nil
}

// mondayOf returns the Monday of the week containing t.
func mondayOf(t time.Time) time.Time {
	weekday := t.Weekday()
	if weekday == time.Sunday {
		weekday = 7
	}
	monday := t.AddDate(0, 0, -int(weekday-time.Monday))
	return time.Date(monday.Year(), monday.Month(), monday.Day(), 0, 0, 0, 0, t.Location())
}
