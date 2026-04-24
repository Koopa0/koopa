// Package tag provides canonical tag management and normalization for the knowledge system.
package tag

import (
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Tag is a canonical tag in the tags table.
type Tag struct {
	ID          uuid.UUID  `json:"id"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	ParentID    *uuid.UUID `json:"parent_id,omitempty"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Alias maps a raw tag string to a canonical tag (or nil if unmapped).
type Alias struct {
	ID               uuid.UUID  `json:"id"`
	RawTag           string     `json:"raw_tag"`
	TagID            *uuid.UUID `json:"tag_id,omitempty"`
	ResolutionSource string     `json:"resolution_source"`
	Confirmed        bool       `json:"confirmed"`
	ConfirmedAt      *time.Time `json:"confirmed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// Resolved is the result of the 4-step normalization pipeline for a single raw tag.
type Resolved struct {
	RawTag           string
	TagID            *uuid.UUID // nil = unmapped (step 4)
	ResolutionSource string     // "auto-exact", "auto-ci", "auto-slug", "unmapped"
}

var (
	// ErrNotFound indicates the tag or alias does not exist.
	ErrNotFound = errors.New("tag: not found")
	// ErrConflict indicates a duplicate slug or constraint violation.
	ErrConflict = errors.New("tag: conflict")
	// ErrHasReferences indicates a tag cannot be deleted because aliases or notes reference it.
	ErrHasReferences = errors.New("has references")
)

// CreateParams are the parameters for creating a canonical tag.
type CreateParams struct {
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	ParentID    *uuid.UUID `json:"parent_id,omitempty"`
	Description string     `json:"description"`
}

// UpdateParams are the parameters for updating a canonical tag.
type UpdateParams struct {
	Slug        *string    `json:"slug,omitempty"`
	Name        *string    `json:"name,omitempty"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Description *string    `json:"description,omitempty"`
}

// MapAliasParams are the parameters for mapping an alias to a canonical tag.
type MapAliasParams struct {
	TagID uuid.UUID `json:"tag_id"`
}

// MergeParams holds parameters for merging two tags.
type MergeParams struct {
	SourceID uuid.UUID `json:"source_id"`
	TargetID uuid.UUID `json:"target_id"`
}

// MergeResult holds statistics from a tag merge operation. Each field
// reports the number of rows reassigned from the source tag to the
// target tag for one of the three junction tables.
type MergeResult struct {
	AliasesMoved      int64 `json:"aliases_moved"`
	ContentTagsMoved  int64 `json:"content_tags_moved"`
	BookmarkTagsMoved int64 `json:"bookmark_tags_moved"`
}

// containsControlChars returns true if s contains any control character (null bytes, etc.).
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// Slugify normalizes a raw tag string to a URL-safe slug.
// Lowercase, replace spaces and special chars with hyphens, collapse consecutive hyphens.
func Slugify(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))

	prev := false // was previous char a hyphen?
	for _, r := range strings.TrimSpace(raw) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			prev = false
		case r == '-' || r == '_' || r == ' ' || r == '/' || r == '.' || r == ':':
			if !prev && b.Len() > 0 {
				b.WriteByte('-')
				prev = true
			}
		}
	}

	s := b.String()
	// trim trailing hyphen
	return strings.TrimRight(s, "-")
}
