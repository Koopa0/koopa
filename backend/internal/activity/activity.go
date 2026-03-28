// Package activity records and queries activity events from all sources.
package activity

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Event represents a recorded activity event.
type Event struct {
	ID        int64           `json:"id"`
	SourceID  *string         `json:"source_id,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	EventType string          `json:"event_type"`
	Source    string          `json:"source"`
	Project   *string         `json:"project,omitempty"`
	Repo      *string         `json:"repo,omitempty"`
	Ref       *string         `json:"ref,omitempty"`
	Title     *string         `json:"title,omitempty"`
	Body      *string         `json:"body,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// RecordParams are the parameters for recording an activity event.
type RecordParams struct {
	SourceID  *string
	Timestamp time.Time
	EventType string
	Source    string
	Project   *string
	Repo      *string
	Ref       *string
	Title     *string
	Body      *string
	Metadata  json.RawMessage
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

// ChangelogEvent is a simplified event for the changelog view.
type ChangelogEvent struct {
	Source    string    `json:"source"`
	EventType string    `json:"event_type"`
	Project   *string   `json:"project,omitempty"`
	Title     *string   `json:"title,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Recorder records activity events.
// Defined here (producer) because 3+ consumers use the identical contract.
type Recorder interface {
	CreateEvent(ctx context.Context, p *RecordParams) (int64, error)
}

var (
	// ErrNotFound indicates the event does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate event (dedup hit).
	ErrConflict = errors.New("conflict")
)
