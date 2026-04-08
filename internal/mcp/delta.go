package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// --- session_delta ---

// SessionDeltaInput is the input for the session_delta tool.
type SessionDeltaInput struct {
	Since *string `json:"since,omitempty" jsonschema_description:"ISO date YYYY-MM-DD to look back from (default: 24 hours ago)"`
}

// SessionDeltaOutput is the output of the session_delta tool.
type SessionDeltaOutput struct {
	Since          string                     `json:"since"`
	TasksCreated   []task.CreatedTaskDetail   `json:"tasks_created"`
	TasksCompleted []task.CompletedTaskDetail `json:"tasks_completed"`
	JournalEntries []journal.Entry            `json:"journal_entries"`
	SessionCount   int                        `json:"session_count"`
}

func (s *Server) sessionDelta(ctx context.Context, _ *mcp.CallToolRequest, input SessionDeltaInput) (*mcp.CallToolResult, SessionDeltaOutput, error) {
	since := time.Now().Add(-24 * time.Hour)
	if input.Since != nil && *input.Since != "" {
		t, err := time.Parse(time.DateOnly, *input.Since)
		if err != nil {
			return nil, SessionDeltaOutput{}, fmt.Errorf("invalid since date: %w", err)
		}
		since = t
	}

	created, err := s.tasks.TasksCreatedSince(ctx, since)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying created tasks: %w", err)
	}

	completed, err := s.tasks.CompletedTasksDetailSince(ctx, since)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying completed tasks: %w", err)
	}

	journals, err := s.journal.EntriesByDateRange(ctx, since, time.Now(), nil, nil)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying journal entries: %w", err)
	}

	sessions, err := s.learn.RecentSessions(ctx, nil, since, 100)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying learning sessions: %w", err)
	}

	return nil, SessionDeltaOutput{
		Since:          since.Format(time.DateOnly),
		TasksCreated:   created,
		TasksCompleted: completed,
		JournalEntries: journals,
		SessionCount:   len(sessions),
	}, nil
}
