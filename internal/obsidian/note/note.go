// Package note manages obsidian knowledge notes synced from the vault.
package note

import (
	"errors"
	"time"
)

// Note represents a knowledge note from the notes table.
type Note struct {
	ID               int64      `json:"id"`
	FilePath         string     `json:"file_path"`
	Title            *string    `json:"title,omitempty"`
	Type             *string    `json:"type,omitempty"`
	Provenance       *string    `json:"provenance,omitempty"`
	Context          *string    `json:"context,omitempty"`
	Maturity         *string    `json:"maturity,omitempty"`
	Tags             []string   `json:"tags"` // raw frontmatter tags (JSONB)
	Difficulty       *string    `json:"difficulty,omitempty"`
	LeetcodeID       *int32     `json:"leetcode_id,omitempty"`
	Book             *string    `json:"book,omitempty"`
	Chapter          *string    `json:"chapter,omitempty"`
	ExternalProvider *string    `json:"external_provider,omitempty"`
	ExternalRef      *string    `json:"external_ref,omitempty"`
	ContentText      *string    `json:"content_text,omitempty"`
	ContentHash      *string    `json:"content_hash,omitempty"`
	GitCreatedAt     *time.Time `json:"git_created_at,omitempty"`
	GitUpdatedAt     *time.Time `json:"git_updated_at,omitempty"`
	SyncedAt         *time.Time `json:"synced_at,omitempty"`
}

// UpsertParams holds the parameters for upserting a knowledge note.
type UpsertParams struct {
	FilePath         string
	Title            *string
	Type             *string
	Provenance       *string
	Context          *string
	Maturity         *string
	Tags             []string // raw frontmatter tags → stored as JSONB
	Difficulty       *string
	LeetcodeID       *int32
	Book             *string
	Chapter          *string
	ExternalProvider *string
	ExternalRef      *string
	ContentText      *string
	ContentHash      *string
}

// SearchResult is a note with a relevance score from full-text search.
type SearchResult struct {
	Note
	Rank float32
}

// SearchFilter holds optional frontmatter filters for note queries.
type SearchFilter struct {
	Type       *string
	Provenance *string
	Context    *string
	Book       *string
	After      *time.Time
	Before     *time.Time
}

// Link represents a wikilink edge from one note to a target path.
type Link struct {
	TargetPath string
	LinkText   *string
}

// SimilarityResult is a note with a cosine similarity score from semantic search.
type SimilarityResult struct {
	Note
	Similarity float64
}

// EmbeddingCandidate is a note that needs embedding generation.
type EmbeddingCandidate struct {
	ID          int64
	FilePath    string
	Title       *string
	ContentText *string
}

// MergedResult is a note with a combined score from Reciprocal Rank Fusion
// across text and filter search results.
type MergedResult struct {
	Note
	Score float64
}

var ErrNotFound = errors.New("note: not found")
