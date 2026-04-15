// Package bookmark provides storage and HTTP handlers for external
// resources that the curator recommends with a personal note.
//
// Bookmarks are split from the contents table because they differ from
// first-party content (article / essay / build-log / til / note /
// digest) in several load-bearing ways: they have an external canonical
// URL, they skip editorial review (curate = publish), they do not
// participate in editorial_queue, and their RSS surface differs from
// first-party articles. See migrations/005_bookmarks_schema.up.sql
// for the schema and the Next phase design pass for the rationale.
//
// During the M1/M2 window this package coexists with legacy
// contents.type='bookmark' rows. Read endpoints serve from bookmarks
// only. The M3 cutover (not in this package's responsibility) redirects
// legacy read paths and retires the old write path.
package bookmark

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// SourceType records how the bookmark entered the system.
type SourceType string

const (
	// SourceRSS — curated from a feed_entries row.
	SourceRSS SourceType = "rss"
	// SourceManual — pasted by the curator.
	SourceManual SourceType = "manual"
	// SourceShared — received via an external channel (e.g. DM, share sheet).
	SourceShared SourceType = "shared"
)

// Valid reports whether s is a known source type.
func (s SourceType) Valid() bool {
	switch s {
	case SourceRSS, SourceManual, SourceShared:
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
	SourceType        SourceType `json:"source_type"`
	SourceFeedEntryID *uuid.UUID `json:"source_feed_entry_id,omitempty"`
	CuratedBy         string     `json:"curated_by"`
	CuratedAt         time.Time  `json:"curated_at"`
	IsPublic          bool       `json:"is_public"`
	PublishedAt       *time.Time `json:"published_at,omitempty"`
	Topics            []TopicRef `json:"topics"`
	Tags              []string   `json:"tags"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// Filter holds public list parameters.
type Filter struct {
	Page    int
	PerPage int
	Since   *time.Time
}

// AdminFilter holds admin list parameters. Admins see private bookmarks.
type AdminFilter struct {
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
	URL         string     `json:"url"`
	URLHash     string     `json:"url_hash"`
	Slug        string     `json:"slug"`
	Title       string     `json:"title"`
	Excerpt     string     `json:"excerpt"`
	Note        string     `json:"note"`
	SourceType  SourceType `json:"source_type"`
	FeedEntryID *uuid.UUID `json:"source_feed_entry_id,omitempty"`
	CuratedBy   string     `json:"curated_by"`
	IsPublic    bool       `json:"is_public"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	TopicIDs    []uuid.UUID
}

var (
	// ErrNotFound indicates the bookmark does not exist.
	ErrNotFound = errors.New("bookmark: not found")

	// ErrConflict indicates a duplicate url_hash or slug.
	ErrConflict = errors.New("bookmark: conflict")
)
