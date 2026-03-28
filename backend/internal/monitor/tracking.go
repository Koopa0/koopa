// Package monitor provides tracking topic configuration for automated
// data collection. Topics define keywords and sources to monitor.
package monitor

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Topic represents a topic to track for data collection.
type Topic struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Keywords  []string  `json:"keywords"`
	Sources   []string  `json:"sources"`
	Enabled   bool      `json:"enabled"`
	Schedule  string    `json:"schedule"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateParams are the parameters for creating a tracking topic.
type CreateParams struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
	Sources  []string `json:"sources"`
	Enabled  *bool    `json:"enabled,omitempty"`
	Schedule string   `json:"schedule"`
}

// UpdateParams are the parameters for updating a tracking topic.
type UpdateParams struct {
	Name     *string  `json:"name,omitempty"`
	Keywords []string `json:"keywords,omitempty"`
	Sources  []string `json:"sources,omitempty"`
	Enabled  *bool    `json:"enabled,omitempty"`
	Schedule *string  `json:"schedule,omitempty"`
}

var (
	// ErrNotFound indicates the tracking topic does not exist.
	ErrNotFound = errors.New("not found")
)
