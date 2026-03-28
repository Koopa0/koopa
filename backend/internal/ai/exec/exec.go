// Package exec provides an in-process worker pool for executing AI flows
// with persistent tracking via the flow_runs database table.
package exec

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents a flow run execution status.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Run represents a flow execution record persisted in the flow_runs table.
type Run struct {
	ID          uuid.UUID       `json:"id"`
	FlowName    string          `json:"flow_name"`
	ContentID   *uuid.UUID      `json:"content_id,omitempty"`
	Input       json.RawMessage `json:"input"`
	Output      json.RawMessage `json:"output,omitempty"`
	Status      Status          `json:"status"`
	Error       *string         `json:"error,omitempty"`
	Attempt     int             `json:"attempt"`
	MaxAttempts int             `json:"max_attempts"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	EndedAt     *time.Time      `json:"ended_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// Filter holds flow run listing parameters.
type Filter struct {
	Page    int
	PerPage int
	Status  *Status
}

// Submitter submits a flow run for async processing.
// Defined here (producer) because 3+ consumers use the identical contract.
type Submitter interface {
	Submit(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) error
}

var (
	// ErrNotFound indicates the flow run does not exist.
	ErrNotFound = errors.New("not found")
)
