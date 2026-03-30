// Package topic provides topic management for content categorization.
package topic

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
)

// ContentByTopicLister lists published content for a given topic.
// Defined by the consumer (topic) — the producer (content.Store) satisfies it implicitly.
type ContentByTopicLister interface {
	ContentsByTopicID(ctx context.Context, topicID uuid.UUID, page, perPage int) ([]content.Content, int, error)
}

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

// TagCount is a tag with its frequency within a topic.
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// Slug is a lightweight topic reference for AI classification.
type Slug struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

var (
	// ErrNotFound indicates the topic does not exist.
	ErrNotFound = errors.New("topic: not found")

	// ErrConflict indicates a duplicate slug.
	ErrConflict = errors.New("topic: conflict")
)
