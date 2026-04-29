// Package task owns the inter-agent coordination tasks table, plus the
// task_messages conversation log that travels with it. A task is a single
// unit of work one agent asks another to do; its lifecycle is
// submitted → working → completed | canceled, enforced by the
// chk_tasks_state_timestamps CHECK and the trg_tasks_completion_requires_outputs
// trigger.
//
// Vocabulary discipline (from migration 001 + schema-design rules):
//
//   - task = inter-agent coordination work unit (this package)
//   - todo = personal GTD work item (internal/todo)
//
// The two are different concepts and never share infrastructure.
//
// On the wire, task message and artifact `parts` columns store JSONB arrays
// of a2a.Part values in a2a-go's flattened form. Construction goes through
// a2a-go (a2a.NewTextPart, a2a.NewDataPart) — Go code in this package never
// hand-rolls the Part shape.
package task

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

// State is the lifecycle position of a task. Matches the task_state enum.
type State string

// Task lifecycle states (matches the task_state ENUM in migrations 001+003).
const (
	StateSubmitted         State = "submitted"
	StateWorking           State = "working"
	StateCompleted         State = "completed"
	StateCanceled          State = "canceled"
	StateRevisionRequested State = "revision_requested"
)

// Role is the side of a conversation a message belongs to. Matches the
// message_role enum.
type Role string

// Message roles (matches the message_role ENUM in migration 001).
const (
	RoleRequest  Role = "request"
	RoleResponse Role = "response"
)

// Task is the primary record of an inter-agent coordination unit.
//
// Source and Target on this struct are the agent-mental-model field names
// that match the MCP wire shape ("source agent issues a task to target
// agent"). The schema column names are created_by and assignee respectively
// — the mapping happens inside store.go and query.sql, never escaping
// outside this package.
type Task struct {
	ID                  uuid.UUID       `json:"id"`
	Source              string          `json:"source"`
	Target              string          `json:"target"`
	Title               string          `json:"title"`
	State               State           `json:"state"`
	Deadline            *time.Time      `json:"deadline,omitempty"`
	Priority            *string         `json:"priority,omitempty"`
	SubmittedAt         time.Time       `json:"submitted_at"`
	AcceptedAt          *time.Time      `json:"accepted_at,omitempty"`
	CompletedAt         *time.Time      `json:"completed_at,omitempty"`
	CanceledAt          *time.Time      `json:"canceled_at,omitempty"`
	RevisionRequestedAt *time.Time      `json:"revision_requested_at,omitempty"`
	Metadata            json.RawMessage `json:"metadata,omitempty"`
}

// Message is a single request/response turn on a task. Parts are a2a-go
// Part values; serialization is handled by a2a-go's MarshalJSON when the
// store writes the row.
type Message struct {
	ID        uuid.UUID   `json:"id"`
	TaskID    uuid.UUID   `json:"task_id"`
	Role      Role        `json:"role"`
	Position  int32       `json:"position"`
	Parts     []*a2a.Part `json:"parts"`
	CreatedAt time.Time   `json:"created_at"`
}

// SubmitInput holds the input for Store.Submit.
//
// RequestParts is the initial request message attached to the new task. The
// schema requires task_messages.parts to be a non-empty JSONB array (1..16
// parts, ≤32 KB total) — the store enforces the same bounds in Go before
// the round-trip so callers see a sentinel error, not a CHECK violation.
type SubmitInput struct {
	Source       string
	Target       string
	Title        string
	Deadline     *time.Time // optional
	Priority     *string    // optional: "high" | "medium" | "low"
	RequestParts []*a2a.Part
	Metadata     json.RawMessage // optional; nil → '{}'
}

// CompleteInput holds the input for Store.Complete. Both response message
// parts and the artifact are required by the schema's
// trg_tasks_completion_requires_outputs trigger — there is no path to
// completion without supplying them, so they are mandatory in the type.
type CompleteInput struct {
	TaskID        uuid.UUID
	ResponseParts []*a2a.Part
	ArtifactName  string
	ArtifactDesc  string
	ArtifactParts []*a2a.Part
}

// Sentinel errors. Handlers branch on errors.Is to translate to HTTP / MCP
// shapes; do NOT branch on string content.
var (
	// ErrNotFound is returned when a task lookup misses.
	ErrNotFound = errors.New("task: not found")

	// ErrConflict is returned on unique-constraint or invalid-state-transition
	// situations (e.g. re-accepting an already-working task).
	ErrConflict = errors.New("task: conflict")

	// ErrInvalidInput wraps DB CHECK violations for inputs that the caller
	// could in principle have validated up-front: blank title, self-assignment,
	// out-of-bounds parts count, oversized parts payload.
	ErrInvalidInput = errors.New("task: invalid input")

	// ErrCompletionOutputsMissing is returned when Complete is called against
	// a task that does not have at least one response message and at least
	// one artifact after the in-tx inserts. In normal usage this should be
	// impossible because Complete is atomic-by-construction; it surfaces only
	// if the underlying tx is interrupted between inserts and the state
	// transition.
	ErrCompletionOutputsMissing = errors.New("task: completion requires response message and artifact")
)
