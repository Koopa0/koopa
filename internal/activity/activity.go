// Package activity records and queries activity events from all sources.
// Package activity records and queries activity events from all sources.
package activity

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Event is a presentation-layer view of an activity_events row. Some fields
// use wire-friendly names that diverge from the schema column names:
//
//   - Timestamp  ← activity_events.occurred_at
//   - Title      ← activity_events.entity_title
//   - Metadata   ← activity_events.payload
//   - Project    ← projects.slug (joined via activity_events.project_id)
//
// EntityID, EntityType, ChangeKind, and Actor keep the schema names. Actor
// is the agent that caused the change — schema-mandatory, always present.
// See internal/activity/query.sql for the exact projection.
type Event struct {
	ID         uuid.UUID       `json:"id"`
	EntityID   *string         `json:"entity_id,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
	ChangeKind string          `json:"change_kind"`
	EntityType string          `json:"entity_type"`
	Actor      string          `json:"actor"`
	Project    *string         `json:"project,omitempty"`
	Title      *string         `json:"title,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// DiffStats holds GitHub diff statistics for a push event.
type DiffStats struct {
	LinesAdded   int `json:"lines_added"`
	LinesRemoved int `json:"lines_removed"`
	FilesChanged int `json:"files_changed"`
	CommitCount  int `json:"commit_count"`
}

// ChangelogDay groups events for a single calendar date.
type ChangelogDay struct {
	Date       string           `json:"date"`
	EventCount int              `json:"event_count"`
	Events     []ChangelogEvent `json:"events"`
}

// ChangelogEvent is a simplified event for the changelog view. Fields
// mirror the canonical activity_events schema vocabulary. Actor is
// non-optional — activity_events.actor is NOT NULL FK to agents.name.
type ChangelogEvent struct {
	ID         uuid.UUID `json:"id"`
	EntityType string    `json:"entity_type"`
	EntityID   *string   `json:"entity_id,omitempty"`
	ChangeKind string    `json:"change_kind"`
	Actor      string    `json:"actor"`
	Project    *string   `json:"project,omitempty"`
	Title      *string   `json:"title,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// ChangelogResponse wraps the day-grouped changelog under a top-level
// `days` key.
type ChangelogResponse struct {
	Days []ChangelogDay `json:"days"`
}

var (
	// ErrNotFound indicates the event does not exist.
	ErrNotFound = errors.New("activity: not found")

	// ErrConflict indicates a duplicate event (dedup hit).
	ErrConflict = errors.New("activity: conflict")
)
