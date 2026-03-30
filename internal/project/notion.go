package project

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/tag"
)

// MapNotionStatus maps a Notion UB 3.0 project status to the local enum.
func MapNotionStatus(notionStatus string) Status {
	switch notionStatus {
	case "Planned":
		return StatusPlanned
	case "On Hold":
		return StatusOnHold
	case "Doing":
		return StatusInProgress
	case "Ongoing":
		return StatusMaintained
	case "Done":
		return StatusCompleted
	default:
		return StatusInProgress
	}
}

// StatusToNotion maps a local project status to the Notion status name.
func StatusToNotion(s Status) string {
	switch s {
	case StatusPlanned:
		return "Planned"
	case StatusInProgress:
		return "Doing"
	case StatusOnHold:
		return "On Hold"
	case StatusMaintained:
		return "Ongoing"
	case StatusCompleted, StatusArchived:
		return "Done"
	default:
		return "Doing"
	}
}

// SyncFromNotionInput holds extracted Notion properties for project sync.
// All fields are primitives -- the notion package extracts them before calling.
type SyncFromNotionInput struct {
	PageID      string
	Title       string
	Status      string // raw Notion status name
	Description string
	Area        string
	GoalID      *uuid.UUID
	Deadline    *time.Time
}

// SyncFromNotion upserts a project from extracted Notion properties.
func (s *Store) SyncFromNotion(ctx context.Context, input *SyncFromNotionInput) (*Project, error) {
	if input.Title == "" {
		return nil, fmt.Errorf("notion page %s has no title", input.PageID)
	}

	localStatus := MapNotionStatus(input.Status)

	idSuffix := input.PageID
	if len(idSuffix) > 8 {
		idSuffix = idSuffix[:8]
	}
	slug := tag.Slugify(input.Title) + "-" + idSuffix

	p, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Slug:         slug,
		Title:        input.Title,
		Description:  input.Description,
		Status:       localStatus,
		Area:         input.Area,
		GoalID:       input.GoalID,
		Deadline:     input.Deadline,
		NotionPageID: input.PageID,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting project: %w", err)
	}
	return p, nil
}
