package goal

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// MapNotionStatus maps a Notion goal status to the local enum.
// UB 3.0 uses: Dream, Active, Achieved (mapped from status groups: to_do, in_progress, complete).
func MapNotionStatus(notionStatus string) Status {
	switch notionStatus {
	case "Not Started", "Dream":
		return StatusNotStarted
	case "In Progress", "Doing", "Active":
		return StatusInProgress
	case "Done", "Achieved":
		return StatusDone
	case "Abandoned":
		return StatusAbandoned
	default:
		return StatusNotStarted
	}
}

// StatusToNotion maps a local goal status to the Notion status name.
func StatusToNotion(s Status) string {
	switch s {
	case StatusNotStarted:
		return "Dream"
	case StatusInProgress:
		return "Active"
	case StatusDone:
		return "Achieved"
	case StatusAbandoned:
		return "Abandoned"
	default:
		return "Dream"
	}
}

// SyncFromNotionInput holds extracted Notion properties for goal sync.
// All fields are primitives -- the notion package extracts them before calling.
type SyncFromNotionInput struct {
	PageID   string
	Title    string
	Status   string // raw Notion status name
	Area     *uuid.UUID
	Deadline *time.Time
}

// SyncFromNotion upserts a goal from extracted Notion properties.
func (s *Store) SyncFromNotion(ctx context.Context, input *SyncFromNotionInput) (*Goal, error) {
	if input.Title == "" {
		return nil, fmt.Errorf("notion goal page %s has no title", input.PageID)
	}

	localStatus := MapNotionStatus(input.Status)

	g, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        input.Title,
		Status:       localStatus,
		Area:         input.Area,
		Deadline:     input.Deadline,
		NotionPageID: input.PageID,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting goal: %w", err)
	}
	return g, nil
}
