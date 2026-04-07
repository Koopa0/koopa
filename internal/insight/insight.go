// Package insight provides hypothesis tracking storage.
//
// Insights are not general notes — they have a hypothesis,
// an invalidation condition, and a lifecycle:
// unverified → verified/invalidated → archived.
package insight

import (
	"encoding/json"
	"errors"
	"time"
)

var ErrNotFound = errors.New("insight: not found")

// Status represents an insight's lifecycle state.
type Status string

const (
	StatusUnverified  Status = "unverified"
	StatusVerified    Status = "verified"
	StatusInvalidated Status = "invalidated"
	StatusArchived    Status = "archived"
)

// Insight represents a tracked hypothesis.
type Insight struct {
	ID                    int64          `json:"id"`
	Source                string         `json:"source"`
	Content               string         `json:"content"`
	Status                Status         `json:"status"`
	Hypothesis            string         `json:"hypothesis"`
	InvalidationCondition string         `json:"invalidation_condition"`
	Metadata              map[string]any `json:"metadata,omitempty"`
	ObservedDate          time.Time      `json:"observed_date"`
	CreatedAt             time.Time      `json:"created_at"`
}

// CreateParams holds parameters for creating an insight.
type CreateParams struct {
	Source                string
	Content               string
	Hypothesis            string
	InvalidationCondition string
	Metadata              json.RawMessage
	ObservedDate          time.Time
}
