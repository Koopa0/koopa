// Copyright 2026 Koopa. All rights reserved.

// Package entry manages externally collected data items from RSS feeds
// and other sources, including curation.
package entry

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

// CreateParams are the parameters for creating collected data.
type CreateParams struct {
	SourceURL       string     `json:"source_url"`
	Title           string     `json:"title"`
	OriginalContent string     `json:"original_content"`
	URLHash         string     `json:"url_hash"`
	FeedID          *uuid.UUID `json:"feed_id,omitempty"`
	PublishedAt     *time.Time `json:"published_at,omitempty"`
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

	// ErrInvalidInput indicates the request fails validation.
	ErrInvalidInput = errors.New("invalid input")
)
