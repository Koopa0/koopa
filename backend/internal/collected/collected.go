// Package collected provides collected data management.
package collected

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents the status of collected data.
type Status string

const (
	StatusUnread  Status = "unread"
	StatusRead    Status = "read"
	StatusCurated Status = "curated"
	StatusIgnored Status = "ignored"
)

// CollectedData represents externally collected data.
type CollectedData struct {
	ID               uuid.UUID  `json:"id"`
	SourceURL        string     `json:"source_url"`
	SourceName       string     `json:"source_name"`
	Title            string     `json:"title"`
	OriginalContent  *string    `json:"original_content,omitempty"`
	RelevanceScore   float32    `json:"relevance_score"`
	Topics           []string   `json:"topics"`
	Status           Status     `json:"status"`
	CuratedContentID *uuid.UUID `json:"curated_content_id,omitempty"`
	CollectedAt      time.Time  `json:"collected_at"`
	URLHash          string     `json:"url_hash"`
	UserFeedback     *string    `json:"user_feedback,omitempty"`
	FeedbackAt       *time.Time `json:"feedback_at,omitempty"`
	FeedID           *uuid.UUID `json:"feed_id,omitempty"`
}

// Feedback represents user feedback on collected data.
type Feedback string

const (
	// FeedbackUp indicates positive feedback.
	FeedbackUp Feedback = "up"

	// FeedbackDown indicates negative feedback.
	FeedbackDown Feedback = "down"
)

// CreateParams are the parameters for creating collected data.
type CreateParams struct {
	SourceURL       string     `json:"source_url"`
	SourceName      string     `json:"source_name"`
	Title           string     `json:"title"`
	OriginalContent *string    `json:"original_content,omitempty"`
	Topics          []string   `json:"topics"`
	URLHash         string     `json:"url_hash"`
	FeedID          *uuid.UUID `json:"feed_id,omitempty"`
	RelevanceScore  float32    `json:"relevance_score"`
}

// Filter holds collected data listing parameters.
type Filter struct {
	Page    int
	PerPage int
	Status  *string
}

var (
	// ErrNotFound indicates the collected data does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate URL hash.
	ErrConflict = errors.New("conflict")

	// ErrInvalidInput indicates the request fails validation.
	ErrInvalidInput = errors.New("invalid input")
)
