// Package bookmark provides storage and HTTP handlers for external
// resources that the curator recommends with a personal note.
//
// Bookmarks are split from the contents table because they differ from
// first-party content (article / essay / build-log / til / note /
// digest) in several load-bearing ways: they have an external canonical
// URL, they skip editorial review (curate = publish), they do not
// participate in editorial_queue, and their RSS surface differs from
// first-party articles. See migrations/001_initial.up.sql for the
// schema.
//
// This package is the sole write and read path for bookmarks. Legacy
// contents.type='bookmark' rows are no longer produced.
package bookmark

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Channel records how the bookmark entered the system.
// Matches the bookmarks.capture_channel column (schema CHECK values).
type Channel string

const (
	// ChannelRSS — curated from a feed_entries row.
	ChannelRSS Channel = "rss"
	// ChannelManual — pasted by the curator.
	ChannelManual Channel = "manual"
	// ChannelShared — received via an external channel (e.g. DM, share sheet).
	ChannelShared Channel = "shared"
)

// Valid reports whether c is a known capture channel.
func (c Channel) Valid() bool {
	switch c {
	case ChannelRSS, ChannelManual, ChannelShared:
		return true
	default:
		return false
	}
}

// TopicRef is a lightweight topic reference embedded in a bookmark.
type TopicRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// Bookmark represents an external resource curated with commentary.
type Bookmark struct {
	ID                uuid.UUID  `json:"id"`
	URL               string     `json:"url"`
	URLHash           string     `json:"url_hash"`
	Slug              string     `json:"slug"`
	Title             string     `json:"title"`
	Excerpt           string     `json:"excerpt"`
	Note              string     `json:"note"`
	CaptureChannel    Channel    `json:"capture_channel"`
	SourceFeedEntryID *uuid.UUID `json:"source_feed_entry_id,omitempty"`
	CuratedBy         string     `json:"curated_by"`
	CuratedAt         time.Time  `json:"curated_at"`
	IsPublic          bool       `json:"is_public"`
	PublishedAt       time.Time  `json:"published_at"`
	Topics            []TopicRef `json:"topics"`
	Tags              []string   `json:"tags"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// PublicFilter holds parameters for the public read surface (is_public=true).
type PublicFilter struct {
	Page    int
	PerPage int
	Since   *time.Time
}

// Filter holds parameters for the full bookmark list — no visibility
// restriction. IsPublic is an optional filter (nil = all; pointer to a
// value = filter to that value).
type Filter struct {
	Page     int
	PerPage  int
	IsPublic *bool
}

// CreateParams are the parameters for creating a bookmark.
//
// URLHash is computed by the caller (handler or MCP tool) from URL
// before calling Create. The store does not re-compute — keeping hash
// logic out of the store avoids binding the store to a specific
// canonicalisation policy.
type CreateParams struct {
	URL            string     `json:"url"`
	URLHash        string     `json:"url_hash"`
	Slug           string     `json:"slug"`
	Title          string     `json:"title"`
	Excerpt        string     `json:"excerpt"`
	Note           string     `json:"note"`
	CaptureChannel Channel    `json:"capture_channel"`
	FeedEntryID    *uuid.UUID `json:"source_feed_entry_id,omitempty"`
	CuratedBy      string     `json:"curated_by"`
	IsPublic       bool       `json:"is_public"`
	PublishedAt    time.Time  `json:"published_at"`
	TopicIDs       []uuid.UUID
}

// UpdateParams holds the editable fields for Store.Update. A nil pointer
// means "unchanged". Title / Excerpt / Note are partial scalar updates;
// TopicIDs and TagIDs use full-replace semantics — providing a pointer
// (even to an empty slice) deletes the existing rows and writes the new set.
// URL, slug, capture_channel, curated_by, is_public, and published_at are
// deliberately excluded — URL is the identity, the rest belong to lifecycle.
type UpdateParams struct {
	Title    *string
	Excerpt  *string
	Note     *string
	TopicIDs *[]uuid.UUID
	TagIDs   *[]uuid.UUID
}

var (
	// ErrNotFound indicates the bookmark does not exist.
	ErrNotFound = errors.New("bookmark: not found")

	// ErrConflict indicates a duplicate url_hash or slug.
	ErrConflict = errors.New("bookmark: conflict")
)
