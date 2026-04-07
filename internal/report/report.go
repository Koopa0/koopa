// Package report provides IPC report storage.
//
// Reports are participant output — optionally in response to a directive.
// No target column; recipients are implicit (directive source or HQ).
package report

import (
	"encoding/json"
	"errors"
	"time"
)

var ErrNotFound = errors.New("report: not found")

// Report represents a participant output.
type Report struct {
	ID           int64          `json:"id"`
	Source       string         `json:"source"`
	InResponseTo *int64         `json:"in_response_to,omitempty"`
	Content      string         `json:"content"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	ReportedDate time.Time      `json:"reported_date"`
	CreatedAt    time.Time      `json:"created_at"`
}

// CreateParams holds parameters for creating a report.
type CreateParams struct {
	Source       string
	InResponseTo *int64
	Content      string
	Metadata     json.RawMessage
	ReportedDate time.Time
}
