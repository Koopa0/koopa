// Package artifact owns the artifacts table — structured deliverables
// attached to coordination tasks. Distinct from task_messages: a message is
// a conversation turn (1..16 parts, ≤32 KB), an artifact is a deliverable
// (1..32 parts, ≤256 KB) with a name and an optional description.
//
// Anything larger than the artifact bound belongs in external object
// storage referenced by an a2a.Part data field.
//
// On the wire, artifact parts are JSONB arrays of a2a.Part values in
// a2a-go's flattened form — the same encoding as task_messages.parts.
// Construction goes through a2a-go (a2a.NewTextPart, a2a.NewDataPart);
// Go code in this package never hand-rolls the Part shape.
package artifact

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

// Artifact is a structured deliverable, optionally bound to a task.
// TaskID is nil for standalone (self-initiated) artifacts.
type Artifact struct {
	ID          uuid.UUID   `json:"id"`
	TaskID      *uuid.UUID  `json:"task_id"`
	CreatedBy   *string     `json:"created_by,omitempty"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Parts       []*a2a.Part `json:"parts"`
	CreatedAt   time.Time   `json:"created_at"`
}

// AddInput is the parameter struct for Store.Add. Parts is required and
// non-empty; the schema's chk_artifacts_parts_count CHECK enforces the
// 1..32 bound and chk_artifacts_parts_size enforces the 256 KB bound.
//
// TaskID is optional: nil for standalone (self-initiated) artifacts,
// non-nil for task-bound artifacts. Standalone artifacts require CreatedBy.
type AddInput struct {
	TaskID      *uuid.UUID
	CreatedBy   string
	Name        string
	Description string
	Parts       []*a2a.Part
}

// Sentinel errors. Handlers branch on errors.Is to translate to HTTP / MCP
// shapes; do NOT branch on string content.
var (
	// ErrNotFound is returned when an artifact lookup misses.
	ErrNotFound = errors.New("artifact: not found")

	// ErrInvalidInput wraps DB CHECK violations: blank name, out-of-bounds
	// parts count, oversized parts payload.
	ErrInvalidInput = errors.New("artifact: invalid input")
)
