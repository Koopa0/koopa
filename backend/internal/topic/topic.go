// Package topic provides topic management for content categorization.
package topic

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Topic represents a content category.
type Topic struct {
	ID           uuid.UUID `json:"id"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Icon         *string   `json:"icon,omitempty"`
	ContentCount int       `json:"content_count"`
	SortOrder    int       `json:"sort_order"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CreateParams are the parameters for creating a topic.
type CreateParams struct {
	Slug        string  `json:"slug"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Icon        *string `json:"icon,omitempty"`
	SortOrder   int     `json:"sort_order"`
}

// UpdateParams are the parameters for updating a topic.
type UpdateParams struct {
	Slug        *string `json:"slug,omitempty"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Icon        *string `json:"icon,omitempty"`
	SortOrder   *int    `json:"sort_order,omitempty"`
}

// TopicSlug is a lightweight topic reference for AI classification.
type TopicSlug struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

var (
	// ErrNotFound indicates the topic does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate slug.
	ErrConflict = errors.New("conflict")
)
