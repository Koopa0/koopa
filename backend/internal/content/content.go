// Package content provides content management for the knowledge engine.
package content

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Type represents a content type.
type Type string

const (
	TypeArticle  Type = "article"
	TypeEssay    Type = "essay"
	TypeBuildLog Type = "build-log"
	TypeTIL      Type = "til"
	TypeNote     Type = "note"
	TypeBookmark Type = "bookmark"
	TypeDigest   Type = "digest"
)

// Valid reports whether t is a known content type.
func (t Type) Valid() bool {
	switch t {
	case TypeArticle, TypeEssay, TypeBuildLog, TypeTIL, TypeNote, TypeBookmark, TypeDigest:
		return true
	default:
		return false
	}
}

// Status represents a content status.
type Status string

const (
	StatusDraft     Status = "draft"
	StatusReview    Status = "review"
	StatusPublished Status = "published"
	StatusArchived  Status = "archived"
)

// SourceType represents the origin of the content.
type SourceType string

const (
	SourceObsidian    SourceType = "obsidian"
	SourceNotion      SourceType = "notion"
	SourceAIGenerated SourceType = "ai-generated"
	SourceExternal    SourceType = "external"
	SourceManual      SourceType = "manual"
)

// ReviewLevel represents the review strictness.
type ReviewLevel string

const (
	ReviewAuto     ReviewLevel = "auto"
	ReviewLight    ReviewLevel = "light"
	ReviewStandard ReviewLevel = "standard"
	ReviewStrict   ReviewLevel = "strict"
)

// TopicRef is a lightweight topic reference embedded in content.
type TopicRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// Content represents a piece of content.
type Content struct {
	ID          uuid.UUID       `json:"id"`
	Slug        string          `json:"slug"`
	Title       string          `json:"title"`
	Body        string          `json:"body"`
	Excerpt     string          `json:"excerpt"`
	Type        Type            `json:"type"`
	Status      Status          `json:"status"`
	Tags        []string        `json:"tags"`
	Topics      []TopicRef      `json:"topics"`
	Source      *string         `json:"source,omitempty"`
	SourceType  *SourceType     `json:"source_type,omitempty"`
	SeriesID    *string         `json:"series_id,omitempty"`
	SeriesOrder *int            `json:"series_order,omitempty"`
	ReviewLevel ReviewLevel     `json:"review_level"`
	AIMetadata  json.RawMessage `json:"ai_metadata,omitempty"`
	ReadingTime int             `json:"reading_time"`
	CoverImage  *string         `json:"cover_image,omitempty"`
	PublishedAt *time.Time      `json:"published_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Filter holds content listing parameters.
type Filter struct {
	Page    int
	PerPage int
	Type    *Type
	Tag     *string
}

// CreateParams are the parameters for creating content.
type CreateParams struct {
	Slug        string          `json:"slug"`
	Title       string          `json:"title"`
	Body        string          `json:"body"`
	Excerpt     string          `json:"excerpt"`
	Type        Type            `json:"type"`
	Status      Status          `json:"status"`
	Tags        []string        `json:"tags"`
	TopicIDs    []uuid.UUID     `json:"topic_ids"`
	Source      *string         `json:"source,omitempty"`
	SourceType  *SourceType     `json:"source_type,omitempty"`
	SeriesID    *string         `json:"series_id,omitempty"`
	SeriesOrder *int            `json:"series_order,omitempty"`
	ReviewLevel ReviewLevel     `json:"review_level"`
	AIMetadata  json.RawMessage `json:"ai_metadata,omitempty"`
	ReadingTime int             `json:"reading_time"`
	CoverImage  *string         `json:"cover_image,omitempty"`
}

// UpdateParams are the parameters for updating content.
type UpdateParams struct {
	Slug        *string         `json:"slug,omitempty"`
	Title       *string         `json:"title,omitempty"`
	Body        *string         `json:"body,omitempty"`
	Excerpt     *string         `json:"excerpt,omitempty"`
	Type        *Type           `json:"type,omitempty"`
	Status      *Status         `json:"status,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	TopicIDs    []uuid.UUID     `json:"topic_ids,omitempty"`
	Source      *string         `json:"source,omitempty"`
	SourceType  *SourceType     `json:"source_type,omitempty"`
	SeriesID    *string         `json:"series_id,omitempty"`
	SeriesOrder *int            `json:"series_order,omitempty"`
	ReviewLevel *ReviewLevel    `json:"review_level,omitempty"`
	AIMetadata  json.RawMessage `json:"ai_metadata,omitempty"`
	ReadingTime *int            `json:"reading_time,omitempty"`
	CoverImage  *string         `json:"cover_image,omitempty"`
}

// RelatedContent is a content item with a similarity score.
type RelatedContent struct {
	Slug       string     `json:"slug"`
	Title      string     `json:"title"`
	Excerpt    string     `json:"excerpt"`
	Type       Type       `json:"type"`
	Similarity float64    `json:"similarity"`
	Topics     []TopicRef `json:"topics"`
}

// GraphNode represents a node in the knowledge graph.
type GraphNode struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	ContentType string `json:"content_type,omitempty"`
	Topic       string `json:"topic,omitempty"`
	Count       int    `json:"count,omitempty"`
}

// GraphLink represents an edge in the knowledge graph.
type GraphLink struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Type       string   `json:"type"`
	Similarity *float64 `json:"similarity,omitempty"`
}

// KnowledgeGraph is the full graph response.
type KnowledgeGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Links []GraphLink `json:"links"`
}

// EmbeddingContent holds a published content with its embedding vector for graph computation.
type EmbeddingContent struct {
	ID        uuid.UUID
	Slug      string
	Title     string
	Type      Type
	Embedding []float32
}

var (
	// ErrNotFound indicates the content does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate slug.
	ErrConflict = errors.New("conflict")
)
