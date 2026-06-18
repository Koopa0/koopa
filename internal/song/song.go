// Copyright 2026 Koopa. All rights reserved.

// Package song provides Koopa's private ヨルシカ song shelf and reflection
// diary: one Song per track, many dated Reflections threaded under it.
//
// The whole shelf is ヨルシカ — there is no artist column. The distinct
// dimension over the reading shelf it mirrors is a Japanese-study reference
// layer: lyrics, an owner translation, and vocabulary notes. Those fields are
// owner-filled and never generated — this package stores what the client
// sends, it never synthesizes content.
//
// The domain is deeply private by design. It has zero agent surface — no
// MCP tool touches these tables, they are not part of the search_knowledge
// corpus (no embeddings, no tsvector), and the only access path is the
// admin HTTP API in handler.go. There is intentionally no rating, score, or
// progress field (owner decision); evaluation happens through reflections.
//
// This package is the sole read and write path for the songs and
// song_reflections tables.
package song

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Song is one track on the shelf as stored. The study fields (LyricsJa,
// Translation, Vocabulary) are owner-filled and empty until entered.
// Reflections are not embedded — use Store.Reflections when the diary thread
// is needed.
type Song struct {
	ID          uuid.UUID
	TitleJa     string
	Album       string // free-text grouping label; empty when not recorded
	LyricsJa    string // owner-filled study lyrics; empty until entered
	Translation string // owner translation; empty until entered
	Vocabulary  string // owner study notes; empty until entered
	IsPublic    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Reflection is one dated diary entry under a song. The song page shows them
// as a thread ordered by EntryDate, then CreatedAt.
type Reflection struct {
	ID        uuid.UUID
	SongID    uuid.UUID
	EntryDate time.Time // the diary date, not necessarily the typing date
	Body      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateParams are the fields for Store.Create. Every field is optional
// except Title — the study fields default to empty for the owner to fill.
type CreateParams struct {
	Title       string
	Album       string
	LyricsJa    string
	Translation string
	Vocabulary  string
}

// UpdateParams hold optional editable fields for Store.Update. A nil pointer
// means "unchanged".
type UpdateParams struct {
	Title       *string
	Album       *string
	LyricsJa    *string
	Translation *string
	Vocabulary  *string
	IsPublic    *bool
}

// UpdateReflectionParams hold optional editable fields for
// Store.UpdateReflection. A nil pointer means "unchanged".
type UpdateReflectionParams struct {
	Body      *string
	EntryDate *time.Time
}

// ErrNotFound indicates the song or reflection does not exist — including a
// reflection that exists but under a different song (membership mismatch). It
// is the only sentinel the store surfaces: songs have no status enum, so all
// other validation (blank, control characters) is rejected in the handler
// before any store call.
var ErrNotFound = errors.New("song: not found")

// containsControlChars reports whether s contains any ASCII C0 control
// (0x00-0x1F), DEL (0x7F), or Unicode C1 control (0x80-0x9F). Used for
// single-line fields (title, album) where no control character is
// legitimate. Same range as internal/reading.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// containsProseControlChars reports whether s contains a control character
// that is forbidden in free-text prose: the containsControlChars set EXCEPT
// HT (0x09), LF (0x0A), and CR (0x0D). The study fields (lyrics, translation,
// vocabulary) and diary bodies are multi-line prose where line breaks and
// tabs are legitimate formatting — same exemption as internal/reading
// reflection bodies.
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
