// Package collected manages externally collected data items from RSS feeds
// and other sources, including curation, feedback, and collection statistics.
package collected

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents the status of collected data.
type Status string

const (
	// StatusUnread indicates the item has not been reviewed yet.
	StatusUnread Status = "unread"

	// StatusRead indicates the item has been seen but not curated.
	StatusRead Status = "read"

	// StatusCurated indicates the item was promoted to content.
	StatusCurated Status = "curated"

	// StatusIgnored indicates the item was dismissed.
	StatusIgnored Status = "ignored"
)

// Item represents externally collected data.
type Item struct {
	ID               uuid.UUID  `json:"id"`
	SourceURL        string     `json:"source_url"`
	SourceName       string     `json:"source_name"`
	Title            string     `json:"title"`
	OriginalContent  *string    `json:"original_content,omitempty"`
	RelevanceScore   float32    `json:"relevance_score"`
	Topics           []string   `json:"topics"`
	Status           Status     `json:"status"`
	CuratedContentID *uuid.UUID `json:"curated_content_id,omitempty"`
	CollectedAt      time.Time  `json:"collected_at"`
	URLHash          string     `json:"url_hash"`
	UserFeedback     *string    `json:"user_feedback,omitempty"`
	FeedbackAt       *time.Time `json:"feedback_at,omitempty"`
	FeedID           *uuid.UUID `json:"feed_id,omitempty"`
}

// Feedback represents user feedback on collected data.
type Feedback string

const (
	// FeedbackUp indicates positive feedback.
	FeedbackUp Feedback = "up"

	// FeedbackDown indicates negative feedback.
	FeedbackDown Feedback = "down"
)

// CreateParams are the parameters for creating collected data.
type CreateParams struct {
	SourceURL       string     `json:"source_url"`
	SourceName      string     `json:"source_name"`
	Title           string     `json:"title"`
	OriginalContent *string    `json:"original_content,omitempty"`
	Topics          []string   `json:"topics"`
	URLHash         string     `json:"url_hash"`
	FeedID          *uuid.UUID `json:"feed_id,omitempty"`
	RelevanceScore  float32    `json:"relevance_score"`
}

// Filter holds collected data listing parameters.
type Filter struct {
	Page    int
	PerPage int
	Status  *string
	Sort    string // "" or "relevance"
}

// FeedStat holds collection statistics for a single feed.
type FeedStat struct {
	FeedID          uuid.UUID  `json:"feed_id"`
	FeedName        string     `json:"feed_name"`
	TotalItems      int        `json:"total_items"`
	AvgScore        float64    `json:"avg_score"`
	LastCollectedAt *time.Time `json:"last_collected_at,omitempty"`
}

// GlobalStat holds aggregated collection statistics across all feeds.
type GlobalStat struct {
	TotalItems   int     `json:"total_items"`
	TotalFeeds   int     `json:"total_feeds"`
	AvgScore     float64 `json:"avg_score"`
	UnreadCount  int     `json:"unread_count"`
	CuratedCount int     `json:"curated_count"`
}

// Stats holds per-feed and global collection statistics.
type Stats struct {
	Feeds  []FeedStat `json:"feeds"`
	Global GlobalStat `json:"global"`
}

var (
	// ErrNotFound indicates the collected data does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate URL hash.
	ErrConflict = errors.New("conflict")

	// ErrInvalidInput indicates the request fails validation.
	ErrInvalidInput = errors.New("invalid input")
)
