package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa0.dev/internal/agent/note"
	"github.com/Koopa0/koopa0.dev/internal/todo"
)

// --- session_delta ---

// SessionDeltaInput is the input for the session_delta tool.
type SessionDeltaInput struct {
	Since *string `json:"since,omitempty" jsonschema_description:"ISO date YYYY-MM-DD to look back from (default: 24 hours ago)"`
}

// SessionDeltaOutput is the output of the session_delta tool.
type SessionDeltaOutput struct {
	Since          string                 `json:"since"`
	TasksCreated   []todo.CreatedDetail   `json:"tasks_created"`
	TasksCompleted []todo.CompletedDetail `json:"tasks_completed"`
	JournalEntries []agentnote.Note      `json:"journal_entries"`
	SessionCount   int                    `json:"session_count"`
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

	created, err := s.todos.ItemsCreatedSince(ctx, since)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying created todo items: %w", err)
	}

	completed, err := s.todos.CompletedItemsDetailSince(ctx, since)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying completed todo items: %w", err)
	}

	notes, err := s.agentNotes.NotesInRange(ctx, since, time.Now(), nil, nil)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying agent notes: %w", err)
	}

	sessions, err := s.learn.RecentSessions(ctx, nil, since, 100)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying learning sessions: %w", err)
	}

	return nil, SessionDeltaOutput{
		Since:          since.Format(time.DateOnly),
		TasksCreated:   created,
		TasksCompleted: completed,
		JournalEntries: notes,
		SessionCount:   len(sessions),
	}, nil
}
