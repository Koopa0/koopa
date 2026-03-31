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

// RecurringDoneHandler is called when a recurring task is synced with status "Done".
// It should apply the complete-and-advance logic instead of writing done.
// Set via SetRecurringDoneHandler. If nil, recurring Done is synced as-is (legacy behavior).
type RecurringDoneHandler func(ctx context.Context, t *Task) error

// SyncFromNotion upserts a task from extracted Notion properties.
// projectResolver is optional; if nil, project FK is not set.
// If the incoming status is "Done" for a recurring task and recurringDoneHandler is set,
// the handler is called instead of writing status='done'.
func (s *Store) SyncFromNotion(ctx context.Context, input *SyncFromNotionInput, projectResolver ProjectResolver) error {
	localStatus := MapNotionStatus(input.Status)

	var projectID *uuid.UUID
	if input.ProjectPageID != "" && projectResolver != nil {
		if id, err := projectResolver.IDByNotionPageID(ctx, input.ProjectPageID); err == nil {
			projectID = &id
		}
	}

	// Intercept: recurring task marked Done in Notion → complete-and-advance
	isRecurring := input.RecurInterval != nil && *input.RecurInterval > 0
	if isRecurring && localStatus == StatusDone && s.recurringDoneHandler != nil {
		// First, upsert without the Done status (keep current status)
		existing, _ := s.TaskByNotionPageID(ctx, input.PageID)
		keepStatus := StatusTodo
		if existing != nil {
			keepStatus = existing.Status
		}

		_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:         input.Title,
			Status:        keepStatus, // don't write Done
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
			return fmt.Errorf("upserting recurring task: %w", err)
		}

		// Fetch the upserted task to pass to the handler
		t, err := s.TaskByNotionPageID(ctx, input.PageID)
		if err != nil {
			return fmt.Errorf("fetching recurring task after upsert: %w", err)
		}
		return s.recurringDoneHandler(ctx, t)
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

// SetRecurringDoneHandler sets the handler called when a recurring task is synced as Done.
func (s *Store) SetRecurringDoneHandler(h RecurringDoneHandler) {
	s.recurringDoneHandler = h
}
