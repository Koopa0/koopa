// Package note manages obsidian knowledge notes synced from the vault.
package note

import (
	"errors"
	"time"
)

// Note represents a knowledge note from the obsidian_notes table.
type Note struct {
	ID           int64
	FilePath     string
	Title        *string
	Type         *string
	Source       *string
	Context      *string
	Status       *string
	Tags         []string // raw frontmatter tags (JSONB)
	Difficulty   *string
	LeetcodeID   *int32
	Book         *string
	Chapter      *string
	NotionTaskID *string
	ContentText  *string
	SearchText   *string
	ContentHash  *string
	GitCreatedAt *time.Time
	GitUpdatedAt *time.Time
	SyncedAt     *time.Time
}

// UpsertParams holds the parameters for upserting a knowledge note.
type UpsertParams struct {
	FilePath     string
	Title        *string
	Type         *string
	Source       *string
	Context      *string
	Status       *string
	Tags         []string // raw frontmatter tags → stored as JSONB
	Difficulty   *string
	LeetcodeID   *int32
	Book         *string
	Chapter      *string
	NotionTaskID *string
	ContentText  *string
	SearchText   *string
	ContentHash  *string
}

// SearchResult is a note with a relevance score from full-text search.
type SearchResult struct {
	Note
	Rank float32
}

// SearchFilter holds optional frontmatter filters for note queries.
type SearchFilter struct {
	Type    *string
	Source  *string
	Context *string
	Book    *string
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

var ErrNotFound = errors.New("not found")
