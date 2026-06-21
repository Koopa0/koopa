// Copyright 2026 Koopa. All rights reserved.

// Package reading provides Koopa's private literature shelf and reading
// diary: one Reading per book, many dated Reflections threaded under it.
//
// The domain is deeply private by design. It has zero agent surface — no
// MCP tool touches these tables, they are not part of the search_knowledge
// corpus (no embeddings, no tsvector), and the only access path is the
// admin HTTP API in handler.go. Evaluation happens exclusively through
// reflections; there is intentionally no rating field (owner decision).
//
// This package is the sole read and write path for the readings and
// reading_reflections tables.
package reading

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is the shelf state of a reading. Mirrors the CHECK constraint on
// readings.status.
type Status string

const (
	StatusWantToRead Status = "want_to_read"
	StatusReading    Status = "reading"
	StatusFinished   Status = "finished"
	StatusAbandoned  Status = "abandoned"
)

// Valid reports whether s is a recognized status.
func (s Status) Valid() bool {
	switch s {
	case StatusWantToRead, StatusReading, StatusFinished, StatusAbandoned:
		return true
	default:
		return false
	}
}

// Reading is one book on the shelf as stored. Reflections are not
// embedded — use Store.Reflections when the diary thread is needed.
type Reading struct {
	ID         uuid.UUID
	Title      string
	Author     string // empty when not recorded
	Status     Status
	StartedOn  *time.Time // nil until reading starts (or never recorded)
	FinishedOn *time.Time // nil until the reading concludes
	IsPublic   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Reflection is one dated diary entry under a reading. The book page shows
// them as a thread ordered by EntryDate, then CreatedAt.
type Reflection struct {
	ID        uuid.UUID
	ReadingID uuid.UUID
	EntryDate time.Time // the diary date, not necessarily the typing date
	Body      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateParams are the fields for Store.Create. Status defaults to
// StatusWantToRead when empty.
type CreateParams struct {
	Title     string
	Author    string
	Status    Status
	StartedOn *time.Time
}

// UpdateParams hold optional editable fields for Store.Update. A nil
// pointer means "unchanged" — provided dates cannot be cleared back to
// NULL through this path (same convention as goal milestones).
type UpdateParams struct {
	Title      *string
	Author     *string
	Status     *Status
	StartedOn  *time.Time
	FinishedOn *time.Time
	IsPublic   *bool
}

// UpdateReflectionParams hold optional editable fields for
// Store.UpdateReflection. A nil pointer means "unchanged".
type UpdateReflectionParams struct {
	Body      *string
	EntryDate *time.Time
}

var (
	// ErrNotFound indicates the reading or reflection does not exist —
	// including a reflection that exists but under a different reading
	// (membership mismatch).
	ErrNotFound = errors.New("reading: not found")

	// ErrInvalidInput signals a value that fails domain validation
	// (unrecognized status, blank required text).
	ErrInvalidInput = errors.New("reading: invalid input")
)

// containsControlChars reports whether s contains any ASCII C0 control
// (0x00-0x1F), DEL (0x7F), or Unicode C1 control (0x80-0x9F). Used for
// single-line fields (title, author) where no control character is
// legitimate. Same range as internal/goal.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// containsProseControlChars reports whether s contains a control character
// that is forbidden in free-text prose: the containsControlChars set
// EXCEPT HT (0x09), LF (0x0A), and CR (0x0D). Diary bodies are multi-line
// prose where line breaks and tabs are legitimate formatting.
func containsProseControlChars(s string) bool {
	for _, r := range s {
		switch {
		case r == 0x09, r == 0x0a, r == 0x0d:
			// HT, LF, CR — legitimate whitespace in free-text.
			continue
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return true
		}
	}
	return false
}
