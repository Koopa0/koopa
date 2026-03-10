// Package notion handles Notion webhook events and API integration for UB 3.0.
package notion

import "errors"

// Config holds Notion integration configuration.
type Config struct {
	APIKey        string
	WebhookSecret string
	ProjectsDB    string // data_source_id for C1 Projects
	TasksDB       string // data_source_id for C2 Tasks
	BooksDB       string // data_source_id for C5 Books
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

// database identifies which sync path to take.
type database int

const (
	dbUnknown  database = iota
	dbProjects          // C1: project sync
	dbTasks             // C2: task activity
	dbBooks             // C5: book bookmark
)

var (
	// ErrSkipped indicates the event was intentionally skipped.
	ErrSkipped = errors.New("skipped")
)
