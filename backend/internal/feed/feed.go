// Package feed provides RSS/Atom feed management for external content collection.
package feed

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

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
	ID                  uuid.UUID  `json:"id"`
	URL                 string     `json:"url"`
	Name                string     `json:"name"`
	Schedule            string     `json:"schedule"`
	Topics              []string   `json:"topics"`
	Enabled             bool       `json:"enabled"`
	Etag                string     `json:"etag"`
	LastModified        string     `json:"last_modified"`
	LastFetchedAt       *time.Time `json:"last_fetched_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastError           string     `json:"last_error"`
	DisabledReason      string     `json:"disabled_reason"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// CreateParams are the parameters for creating a feed.
type CreateParams struct {
	URL      string   `json:"url"`
	Name     string   `json:"name"`
	Schedule string   `json:"schedule"`
	Topics   []string `json:"topics"`
}

// UpdateParams are the parameters for updating a feed.
type UpdateParams struct {
	URL      *string  `json:"url,omitempty"`
	Name     *string  `json:"name,omitempty"`
	Schedule *string  `json:"schedule,omitempty"`
	Topics   []string `json:"topics,omitempty"`
	Enabled  *bool    `json:"enabled,omitempty"`
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
