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
	AISummary        *string    `json:"ai_summary,omitempty"`
	RelevanceScore   float32    `json:"relevance_score"`
	Topics           []string   `json:"topics"`
	Status           Status     `json:"status"`
	CuratedContentID *uuid.UUID `json:"curated_content_id,omitempty"`
	CollectedAt      time.Time  `json:"collected_at"`
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
)
