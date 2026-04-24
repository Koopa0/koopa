// Package note provides storage for Zettelkasten knowledge artifacts.
//
// Notes are Koopa-private knowledge artifacts with a maturity-based lifecycle
// (seed → stub → evergreen → needs_revision → archived). They are structurally
// and semantically distinct from contents (public editorial writing going
// through draft → review → published) — notes have no publish state and
// contents have no maturity axis.
//
// This package is the sole write and read path for the notes table.
//
// Naming: this package lives alongside internal/agent/note (the runtime
// narrative log for agent planning/reflection). The two are intentionally
// distinct — agent_note is a session-scoped append-only log; note is a
// long-term knowledge artifact. A bare "note" in code or docs is ambiguous —
// prefer "agent_note" vs "note-type artifact" / "Zettelkasten note".
package note

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Kind is the note sub-type. Mirrors the note_kind PostgreSQL ENUM.
type Kind string

const (
	KindSolve           Kind = "solve-note"
	KindConcept         Kind = "concept-note"
	KindDebugPostmortem Kind = "debug-postmortem"
	KindDecisionLog     Kind = "decision-log"
	KindReading         Kind = "reading-note"
	KindMusing          Kind = "musing"
)

// Valid reports whether k is a recognized kind.
func (k Kind) Valid() bool {
	switch k {
	case KindSolve, KindConcept, KindDebugPostmortem,
		KindDecisionLog, KindReading, KindMusing:
		return true
	default:
		return false
	}
}

// Maturity is the refinement stage of a note. Mirrors the note_maturity
// PostgreSQL ENUM.
type Maturity string

const (
	MaturitySeed          Maturity = "seed"
	MaturityStub          Maturity = "stub"
	MaturityEvergreen     Maturity = "evergreen"
	MaturityNeedsRevision Maturity = "needs_revision"
	MaturityArchived      Maturity = "archived"
)

// Valid reports whether m is a recognized maturity.
func (m Maturity) Valid() bool {
	switch m {
	case MaturitySeed, MaturityStub, MaturityEvergreen,
		MaturityNeedsRevision, MaturityArchived:
		return true
	default:
		return false
	}
}

// Note is the Zettelkasten artifact as stored. Concepts are not embedded — use
// Store.ConceptsForNote or the junction queries when concept resolution is needed.
type Note struct {
	ID        uuid.UUID      `json:"id"`
	Slug      string         `json:"slug"`
	Title     string         `json:"title"`
	Body      string         `json:"body"`
	Kind      Kind           `json:"kind"`
	Maturity  Maturity       `json:"maturity"`
	CreatedBy string         `json:"created_by"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// CreateParams are the required fields for Store.Create.
// Slug is caller-supplied (not auto-generated) to keep slug authority with the
// tool layer where slug conventions and collision-resolution policy live.
type CreateParams struct {
	Slug      string         `json:"slug"`
	Title     string         `json:"title"`
	Body      string         `json:"body"`
	Kind      Kind           `json:"kind"`
	Maturity  Maturity       `json:"maturity,omitempty"` // optional; defaults to MaturitySeed
	CreatedBy string         `json:"created_by"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// UpdateParams hold optional editable fields. A nil pointer means "unchanged".
// Maturity is intentionally absent — use UpdateMaturity instead, so maturity
// transitions can be audited and annotated separately from body/title edits.
type UpdateParams struct {
	Slug     *string         `json:"slug,omitempty"`
	Title    *string         `json:"title,omitempty"`
	Body     *string         `json:"body,omitempty"`
	Kind     *Kind           `json:"kind,omitempty"`
	Metadata *map[string]any `json:"metadata,omitempty"`
}

// Filter holds list parameters.
type Filter struct {
	Page     int
	PerPage  int
	Kind     *Kind
	Maturity *Maturity
}

// ConceptRef is a lightweight concept reference for note detail enrichment.
type ConceptRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// TargetRef is a lightweight learning_target reference for note detail
// enrichment. Consumers needing full target detail hit /learning/* paths.
type TargetRef struct {
	ID     uuid.UUID `json:"id"`
	Title  string    `json:"title"`
	Domain string    `json:"domain"`
}

var (
	// ErrNotFound indicates the note does not exist.
	ErrNotFound = errors.New("note: not found")

	// ErrConflict indicates a duplicate slug.
	ErrConflict = errors.New("note: conflict")

	// ErrInvalidKind signals an unrecognized kind value on input.
	ErrInvalidKind = errors.New("note: invalid kind")

	// ErrInvalidMaturity signals an unrecognized maturity value on input.
	ErrInvalidMaturity = errors.New("note: invalid maturity")
)
