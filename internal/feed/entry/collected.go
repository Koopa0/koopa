// Copyright 2026 Koopa. All rights reserved.

// Package entry manages externally collected data items from RSS feeds
// and other sources, including curation.
package entry

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents the status of collected data. Values mirror the
// feed_entries.status enum; the entry endpoints carry them as raw strings.
type Status string

// Item represents externally collected data.
type Item struct {
	ID               uuid.UUID  `json:"id"`
	SourceURL        string     `json:"source_url"`
	FeedName         string     `json:"feed_name"`
	Title            string     `json:"title"`
	OriginalContent  *string    `json:"original_content,omitempty"`
	Status           Status     `json:"status"`
	CuratedContentID *uuid.UUID `json:"curated_content_id,omitempty"`
	CollectedAt      time.Time  `json:"collected_at"`
	PublishedAt      *time.Time `json:"published_at,omitempty"`
	URLHash          string     `json:"url_hash"`
	FeedID           *uuid.UUID `json:"feed_id,omitempty"`
}

// NewItem is one candidate row for Store.CreateNewItems. FeedID is not a
// per-item field — CreateNewItems takes a single feedID applied to the
// whole batch, since a collector run always collects for one feed.
type NewItem struct {
	SourceURL       string
	Title           string
	OriginalContent string
	URLHash         string
	PublishedAt     *time.Time
}

// Filter holds collected data listing parameters.
type Filter struct {
	Page    int
	PerPage int
	Status  *string
}

var (
	// ErrNotFound indicates the collected data does not exist.
	ErrNotFound = errors.New("entry: not found")

	// ErrConflict indicates a duplicate URL hash.
	ErrConflict = errors.New("entry: conflict")
)
