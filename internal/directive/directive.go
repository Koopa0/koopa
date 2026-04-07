// Package directive provides IPC directive storage.
//
// Directives are coordination instructions between participants.
// For work assignment to execution agents, use tasks.assignee.
package directive

import (
	"encoding/json"
	"errors"
	"time"
)

var ErrNotFound = errors.New("directive: not found")

// Directive represents a coordination instruction between participants.
type Directive struct {
	ID             int64          `json:"id"`
	Source         string         `json:"source"`
	Target         string         `json:"target"`
	Priority       string         `json:"priority"`
	AcknowledgedAt *time.Time     `json:"acknowledged_at,omitempty"`
	AcknowledgedBy *string        `json:"acknowledged_by,omitempty"`
	Content        string         `json:"content"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	IssuedDate     time.Time      `json:"issued_date"`
	CreatedAt      time.Time      `json:"created_at"`
}

// CreateParams holds parameters for creating a directive.
type CreateParams struct {
	Source     string
	Target     string
	Priority   string
	Content    string
	Metadata   json.RawMessage
	IssuedDate time.Time
}
