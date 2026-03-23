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

// Schedule constants define feed polling frequencies.
const (
	ScheduleHourly4 = "hourly_4"
	ScheduleDaily   = "daily"
	ScheduleWeekly  = "weekly"
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
type CreateParams struct {
	URL      string       `json:"url"`
	Name     string       `json:"name"`
	Schedule string       `json:"schedule"`
	Topics   []string     `json:"topics"`
	Filter   FilterConfig `json:"filter_config"`
}

// UpdateParams are the parameters for updating a feed.
type UpdateParams struct {
	URL      *string       `json:"url,omitempty"`
	Name     *string       `json:"name,omitempty"`
	Schedule *string       `json:"schedule,omitempty"`
	Topics   []string      `json:"topics,omitempty"`
	Enabled  *bool         `json:"enabled,omitempty"`
	Filter   *FilterConfig `json:"filter_config,omitempty"`
}

var (
	// ErrNotFound indicates the feed does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate feed URL.
	ErrConflict = errors.New("conflict")
)

// ValidSchedule reports whether s is a known schedule value.
func ValidSchedule(s string) bool {
	switch s {
	case ScheduleHourly4, ScheduleDaily, ScheduleWeekly:
		return true
	}
	return false
}
