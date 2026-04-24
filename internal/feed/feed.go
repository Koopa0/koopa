// Package feed provides RSS/Atom feed management for external content collection.
package feed

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FilterConfig defines per-feed URL filtering rules.
type FilterConfig struct {
	DenyPaths         []string `json:"deny_paths,omitempty"`
	DenyTitlePatterns []string `json:"deny_title_patterns,omitempty"`
	AllowTags         []string `json:"allow_tags,omitempty"`
	DenyTags          []string `json:"deny_tags,omitempty"`
}

// MatchURL reports whether the given item URL should be skipped by this filter.
func (fc *FilterConfig) MatchURL(rawURL string) bool {
	if len(fc.DenyPaths) == 0 {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, prefix := range fc.DenyPaths {
		if strings.HasPrefix(u.Path, prefix) {
			return true
		}
	}
	return false
}

// MatchTitle reports whether the given title should be skipped by this filter.
// Patterns are Go regexp strings (e.g. "(?i)sponsored").
func (fc *FilterConfig) MatchTitle(title string) bool {
	if len(fc.DenyTitlePatterns) == 0 {
		return false
	}
	for _, pattern := range fc.DenyTitlePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// fall back to case-insensitive substring match for invalid patterns
			if strings.Contains(strings.ToLower(title), strings.ToLower(pattern)) {
				return true
			}
			continue
		}
		if re.MatchString(title) {
			return true
		}
	}
	return false
}

// MatchTags reports whether the given tags should be skipped by this filter.
// Returns true (skip) if:
//   - AllowTags is set and none of the item tags match
//   - DenyTags is set and any of the item tags match
func (fc *FilterConfig) MatchTags(tags []string) bool {
	if len(fc.AllowTags) > 0 && !hasAnyTag(tags, fc.AllowTags) {
		return true
	}
	if len(fc.DenyTags) > 0 && hasAnyTag(tags, fc.DenyTags) {
		return true
	}
	return false
}

// hasAnyTag reports whether any tag in tags case-insensitively matches any entry in targets.
func hasAnyTag(tags, targets []string) bool {
	for _, tag := range tags {
		for _, target := range targets {
			if strings.EqualFold(tag, target) {
				return true
			}
		}
	}
	return false
}

// Skip reports whether an item should be skipped based on all filter rules.
func (fc *FilterConfig) Skip(itemURL, title string, tags []string) bool {
	return fc.MatchURL(itemURL) || fc.MatchTitle(title) || fc.MatchTags(tags)
}

// ParseFilterConfig unmarshals a JSON filter config, returning zero value on error.
func ParseFilterConfig(raw json.RawMessage) FilterConfig {
	if len(raw) == 0 || string(raw) == "{}" {
		return FilterConfig{}
	}
	var fc FilterConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return FilterConfig{}
	}
	return fc
}

// Schedule constants define feed polling frequencies. These values MUST match
// the schema CHECK constraint on feeds.schedule (hourly, daily, weekly,
// biweekly, monthly).
const (
	ScheduleHourly   = "hourly"
	ScheduleDaily    = "daily"
	ScheduleWeekly   = "weekly"
	ScheduleBiweekly = "biweekly"
	ScheduleMonthly  = "monthly"
)

// MaxConsecutiveFailures is the threshold after which a feed is auto-disabled.
const MaxConsecutiveFailures = 5

// Feed represents an RSS/Atom feed source.
type Feed struct {
	ID                  uuid.UUID    `json:"id"`
	URL                 string       `json:"url"`
	Name                string       `json:"name"`
	Schedule            string       `json:"schedule"`
	Topics              []string     `json:"topics"`
	Enabled             bool         `json:"enabled"`
	Priority            string       `json:"priority"`
	Etag                string       `json:"etag"`
	LastModified        string       `json:"last_modified"`
	LastFetchedAt       *time.Time   `json:"last_fetched_at,omitempty"`
	ConsecutiveFailures int          `json:"consecutive_failures"`
	LastError           string       `json:"last_error"`
	DisabledReason      string       `json:"disabled_reason"`
	Filter              FilterConfig `json:"filter_config"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
}

// CreateParams are the parameters for creating a feed.
//
// TopicIDs, when non-empty, is written atomically into the feed_topics
// junction inside the same transaction as the feed insert. Callers are
// responsible for presenting topic_id values that are valid UUIDs and
// that reference existing topics; feed_topics enforces the FK and a
// violation surfaces as ErrTopicNotFound.
type CreateParams struct {
	URL      string       `json:"url"`
	Name     string       `json:"name"`
	Schedule string       `json:"schedule"`
	TopicIDs []uuid.UUID  `json:"topic_ids,omitempty"`
	Filter   FilterConfig `json:"filter_config"`
}

// UpdateParams are the parameters for updating a feed.
//
// TopicIDs is a three-state field:
//   - nil        — leave the feed_topics junction unchanged
//   - empty ([]) — clear every association
//   - populated  — replace the junction with exactly these topic ids
//
// The handler is responsible for mapping the wire-level JSON into the
// correct nil vs empty form; once TopicIDs reaches the store the three
// states above are observed literally.
type UpdateParams struct {
	URL      *string       `json:"url,omitempty"`
	Name     *string       `json:"name,omitempty"`
	Schedule *string       `json:"schedule,omitempty"`
	TopicIDs []uuid.UUID   `json:"topic_ids,omitempty"`
	Enabled  *bool         `json:"enabled,omitempty"`
	Filter   *FilterConfig `json:"filter_config,omitempty"`
}

var (
	// ErrNotFound indicates the feed does not exist.
	ErrNotFound = errors.New("feed: not found")

	// ErrConflict indicates a duplicate feed URL.
	ErrConflict = errors.New("feed: conflict")

	// ErrTopicNotFound indicates a topic_id in TopicIDs does not reference
	// an existing row in topics. Surfaced as HTTP 400 TOPIC_NOT_FOUND so
	// the client can correct the request without exposing the underlying
	// foreign-key diagnostic.
	ErrTopicNotFound = errors.New("feed: referenced topic_id not found")

	// ErrTooManyTopicIDs indicates the caller provided more topic_id
	// values than the per-request cap. The handler maps this to 400
	// BAD_REQUEST so the client can shrink the request before retrying.
	ErrTooManyTopicIDs = errors.New("feed: too many topic_ids")

	// ErrInvalidTopicID indicates at least one topic_id could not be
	// parsed as a UUID. The handler maps this to 400 BAD_REQUEST.
	ErrInvalidTopicID = errors.New("feed: invalid topic_id")

	// ErrNotTransactional indicates a mutation that must run inside a
	// transaction (because it writes the feed row and the feed_topics
	// junction together) was invoked on a non-transactional store. This
	// is a wiring error — production admin routes always bind via
	// WithTx — so the handler surfaces it as 500 rather than exposing
	// the programming mistake to clients.
	ErrNotTransactional = errors.New("feed: mutation requires a transactional store")
)

// ValidSchedule reports whether s is a known schedule value. The accepted set
// (hourly, daily, weekly, biweekly, monthly) mirrors the schema CHECK on
// feeds.schedule.
func ValidSchedule(s string) bool {
	switch s {
	case ScheduleHourly, ScheduleDaily, ScheduleWeekly, ScheduleBiweekly, ScheduleMonthly:
		return true
	}
	return false
}
