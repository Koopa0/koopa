// Package review provides content review queue management.
package review

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Review represents a review queue entry.
type Review struct {
	ID            uuid.UUID  `json:"id"`
	ContentID     uuid.UUID  `json:"content_id"`
	ReviewLevel   string     `json:"review_level"`
	Status        string     `json:"status"`
	ReviewerNotes *string    `json:"reviewer_notes,omitempty"`
	ContentTitle  string     `json:"content_title,omitempty"`
	ContentSlug   string     `json:"content_slug,omitempty"`
	ContentType   string     `json:"content_type,omitempty"`
	SubmittedAt   time.Time  `json:"submitted_at"`
	ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
}

// Status is the lifecycle state of a review queue entry.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

var (
	// ErrNotFound indicates the review does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate or conflicting review operation.
	ErrConflict = errors.New("conflict")
)
