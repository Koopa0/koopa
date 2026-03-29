package task

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MapNotionStatus maps a Notion task status to the local enum.
func MapNotionStatus(notionStatus string) Status {
	switch notionStatus {
	case "Not Started", "To Do":
		return StatusTodo
	case "In Progress", "Doing":
		return StatusInProgress
	case "Done":
		return StatusDone
	default:
		return StatusTodo
	}
}

// NotionStatusFromInput maps MCP display names to Notion task status names.
func NotionStatusFromInput(s string) string {
	switch s {
	case "To Do", "todo":
		return "To Do"
	case "Doing", "In Progress", "in-progress":
		return "Doing"
	case "Done", "done":
		return "Done"
	default:
		return "To Do"
	}
}

// ProjectResolver resolves a Notion project page ID to a local project UUID.
// Used during task sync to set the project FK.
type ProjectResolver interface {
	IDByNotionPageID(ctx context.Context, notionPageID string) (uuid.UUID, error)
}

// SyncFromNotionInput holds extracted Notion properties for task sync.
// All fields are primitives -- the notion package extracts them before calling.
type SyncFromNotionInput struct {
	PageID        string
	Title         string
	Status        string // raw Notion status name
	Due           *time.Time
	Energy        string
	Priority      string
	RecurInterval *int32
	RecurUnit     string
	MyDay         bool
	Description   string
	ProjectPageID string // resolved Notion page ID for the project (with parent-task fallback)
}

// SyncFromNotion upserts a task from extracted Notion properties.
// projectResolver is optional; if nil, project FK is not set.
func (s *Store) SyncFromNotion(ctx context.Context, input *SyncFromNotionInput, projectResolver ProjectResolver) error {
	localStatus := MapNotionStatus(input.Status)

	var projectID *uuid.UUID
	if input.ProjectPageID != "" && projectResolver != nil {
		if id, err := projectResolver.IDByNotionPageID(ctx, input.ProjectPageID); err == nil {
			projectID = &id
		}
	}

	_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:         input.Title,
		Status:        localStatus,
		Due:           input.Due,
		ProjectID:     projectID,
		NotionPageID:  input.PageID,
		Energy:        input.Energy,
		Priority:      input.Priority,
		RecurInterval: input.RecurInterval,
		RecurUnit:     input.RecurUnit,
		MyDay:         input.MyDay,
		Description:   input.Description,
		Assignee:      "human",
	})
	if err != nil {
		return fmt.Errorf("upserting task: %w", err)
	}
	return nil
}
