// Package notion handles Notion webhook events and API integration for UB 3.0.
package notion

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors for source operations.
var (
	// ErrNotFound indicates the requested source does not exist.
	ErrNotFound = errors.New("notion: not found")

	// ErrConflict indicates a unique constraint violation (duplicate database_id).
	ErrConflict = errors.New("notion: conflict")
)

// SyncMode constants for notion source sync strategies.
const (
	SyncModeFull   = "full"
	SyncModeEvents = "events"
)

// ValidSyncMode reports whether s is a valid sync mode.
func ValidSyncMode(s string) bool {
	return s == SyncModeFull || s == SyncModeEvents
}

// allowedPollIntervals is the set of accepted poll_interval values.
var allowedPollIntervals = map[string]bool{
	"5 minutes":  true,
	"10 minutes": true,
	"15 minutes": true,
	"30 minutes": true,
	"1 hour":     true,
	"2 hours":    true,
	"4 hours":    true,
	"6 hours":    true,
	"12 hours":   true,
	"24 hours":   true,
}

// ValidPollInterval reports whether s is an accepted poll interval value.
func ValidPollInterval(s string) bool {
	return allowedPollIntervals[s]
}

// Source represents a registered Notion database for sync.
type Source struct {
	ID           uuid.UUID       `json:"id"`
	DatabaseID   string          `json:"database_id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Role         *string         `json:"role,omitempty"`
	SyncMode     string          `json:"sync_mode"`
	PropertyMap  json.RawMessage `json:"property_map"`
	PollInterval string          `json:"poll_interval"`
	Enabled      bool            `json:"enabled"`
	LastSyncedAt *time.Time      `json:"last_synced_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// CreateSourceParams holds parameters for registering a new source.
type CreateSourceParams struct {
	DatabaseID   string          `json:"database_id"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Role         *string         `json:"role,omitempty"`
	SyncMode     string          `json:"sync_mode"`
	PropertyMap  json.RawMessage `json:"property_map"`
	PollInterval string          `json:"poll_interval"`
}

// UpdateSourceParams holds parameters for updating a source.
type UpdateSourceParams struct {
	Name         *string          `json:"name,omitempty"`
	Description  *string          `json:"description,omitempty"`
	SyncMode     *string          `json:"sync_mode,omitempty"`
	PropertyMap  *json.RawMessage `json:"property_map,omitempty"`
	PollInterval *string          `json:"poll_interval,omitempty"`
	Enabled      *bool            `json:"enabled,omitempty"`
}

// Config holds Notion integration configuration.
type Config struct {
	APIKey        string
	WebhookSecret string
}

// WebhookPayload is the Notion webhook event structure (API version 2025-09-03).
type WebhookPayload struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      WebhookData `json:"data"`
	Entity    Entity      `json:"entity"`
}

// WebhookData contains the parent information for routing.
type WebhookData struct {
	Parent WebhookParent `json:"parent"`
}

// WebhookParent identifies the source database.
type WebhookParent struct {
	Type         string `json:"type"`
	DataSourceID string `json:"data_source_id"`
}

// Entity identifies the Notion page that changed.
type Entity struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Role constants for system-assigned Notion source roles.
const (
	RoleProjects = "projects"
	RoleTasks    = "tasks"
	RoleBooks    = "books"
	RoleGoals    = "goals"
)

// ValidRole reports whether s is a valid source role.
// Empty string is valid (means no role assigned).
func ValidRole(s string) bool {
	switch s {
	case "", RoleProjects, RoleTasks, RoleBooks, RoleGoals:
		return true
	}
	return false
}

var (
	// ErrSkipped indicates the event was intentionally skipped.
	ErrSkipped = errors.New("skipped")
)
