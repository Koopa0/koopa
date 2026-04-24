package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/todo"
)

// --- capture_inbox ---

// CaptureInboxInput is the input for the capture_inbox tool.
// Agent-to-agent work runs through the tasks table; capture_inbox writes a
// personal GTD todo only.
type CaptureInboxInput struct {
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Task title"`
	Description string  `json:"description,omitempty" jsonschema_description:"Optional task description"`
	Project     string  `json:"project,omitempty" jsonschema_description:"Project slug, alias, or title (fuzzy matched)"`
	Energy      *string `json:"energy,omitempty" jsonschema_description:"Energy level: high, medium, or low"`
	Due         *string `json:"due,omitempty" jsonschema_description:"Due date YYYY-MM-DD (stored as field value, does NOT affect status)"`
}

// CaptureInboxOutput is the output of the capture_inbox tool.
type CaptureInboxOutput struct {
	Task todo.Item `json:"task"`
}

func (s *Server) captureInbox(ctx context.Context, _ *mcp.CallToolRequest, input CaptureInboxInput) (*mcp.CallToolResult, CaptureInboxOutput, error) {
	if input.Title == "" {
		return nil, CaptureInboxOutput{}, fmt.Errorf("title is required")
	}

	var due *time.Time
	if input.Due != nil && *input.Due != "" {
		t, err := time.Parse(time.DateOnly, *input.Due)
		if err != nil {
			return nil, CaptureInboxOutput{}, fmt.Errorf("invalid due date %q (expected YYYY-MM-DD): %w", *input.Due, err)
		}
		due = &t
	}

	var projectID *uuid.UUID
	if input.Project != "" {
		projectID = s.resolveProjectID(ctx, input.Project)
	}

	var created *todo.Item
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		created, err = todo.NewStore(tx).Create(ctx, &todo.CreateParams{
			Title:       input.Title,
			Description: input.Description,
			ProjectID:   projectID,
			Due:         due,
			Energy:      input.Energy,
			Priority:    nil,
			CreatedBy:   s.callerIdentity(ctx),
		})
		return err
	})
	if err != nil {
		return nil, CaptureInboxOutput{}, fmt.Errorf("capturing to inbox: %w", err)
	}

	s.logger.Info("capture_inbox", "task_id", created.ID, "title", created.Title)
	return nil, CaptureInboxOutput{Task: *created}, nil
}
