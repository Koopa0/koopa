// Package project provides project portfolio management.
package project

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents a project's lifecycle status.
type Status string

const (
	// StatusPlanned indicates the project is planned but not yet started.
	StatusPlanned Status = "planned"

	// StatusInProgress indicates the project is actively being developed.
	StatusInProgress Status = "in-progress"

	// StatusOnHold indicates the project is paused.
	StatusOnHold Status = "on-hold"

	// StatusCompleted indicates the project is finished.
	StatusCompleted Status = "completed"

	// StatusMaintained indicates the project is in maintenance mode.
	StatusMaintained Status = "maintained"

	// StatusArchived indicates the project is archived and no longer active.
	StatusArchived Status = "archived"
)

// Project represents a portfolio project.
type Project struct {
	ID              uuid.UUID  `json:"id"`
	Slug            string     `json:"slug"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	LongDescription *string    `json:"long_description,omitempty"`
	Role            *string    `json:"role,omitempty"`
	TechStack       []string   `json:"tech_stack"`
	Highlights      []string   `json:"highlights"`
	Problem         *string    `json:"problem,omitempty"`
	Solution        *string    `json:"solution,omitempty"`
	Architecture    *string    `json:"architecture,omitempty"`
	Results         *string    `json:"results,omitempty"`
	GithubURL       *string    `json:"github_url,omitempty"`
	LiveURL         *string    `json:"live_url,omitempty"`
	Featured        bool       `json:"featured"`
	IsPublic        bool       `json:"is_public"`
	SortOrder       int        `json:"sort_order"`
	Status          Status     `json:"status"`
	NotionPageID    *string    `json:"notion_page_id,omitempty"`
	Repo            *string    `json:"repo,omitempty"`
	AreaID          *uuid.UUID `json:"area_id,omitempty"`
	GoalID          *uuid.UUID `json:"goal_id,omitempty"`
	Deadline        *time.Time `json:"deadline,omitempty"`
	LastActivityAt  *time.Time `json:"last_activity_at,omitempty"`
	ExpectedCadence *string    `json:"expected_cadence,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CreateParams are the parameters for creating a project.
type CreateParams struct {
	Slug            string   `json:"slug"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	LongDescription *string  `json:"long_description,omitempty"`
	Role            *string  `json:"role,omitempty"`
	TechStack       []string `json:"tech_stack"`
	Highlights      []string `json:"highlights"`
	Problem         *string  `json:"problem,omitempty"`
	Solution        *string  `json:"solution,omitempty"`
	Architecture    *string  `json:"architecture,omitempty"`
	Results         *string  `json:"results,omitempty"`
	GithubURL       *string  `json:"github_url,omitempty"`
	LiveURL         *string  `json:"live_url,omitempty"`
	Featured        bool     `json:"featured"`
	IsPublic        bool     `json:"is_public"`
	SortOrder       int      `json:"sort_order"`
	Status          Status   `json:"status"`
}

// UpdateParams are the parameters for updating a project.
type UpdateParams struct {
	Slug            *string  `json:"slug,omitempty"`
	Title           *string  `json:"title,omitempty"`
	Description     *string  `json:"description,omitempty"`
	LongDescription *string  `json:"long_description,omitempty"`
	Role            *string  `json:"role,omitempty"`
	TechStack       []string `json:"tech_stack,omitempty"`
	Highlights      []string `json:"highlights,omitempty"`
	Problem         *string  `json:"problem,omitempty"`
	Solution        *string  `json:"solution,omitempty"`
	Architecture    *string  `json:"architecture,omitempty"`
	Results         *string  `json:"results,omitempty"`
	GithubURL       *string  `json:"github_url,omitempty"`
	LiveURL         *string  `json:"live_url,omitempty"`
	Featured        *bool    `json:"featured,omitempty"`
	IsPublic        *bool    `json:"is_public,omitempty"`
	SortOrder       *int     `json:"sort_order,omitempty"`
	Status          *Status  `json:"status,omitempty"`
}

// UpsertByNotionParams are the parameters for upserting a project from Notion.
type UpsertByNotionParams struct {
	Slug         string
	Title        string
	Description  string
	Status       Status
	AreaID       *uuid.UUID
	GoalID       *uuid.UUID
	Deadline     *time.Time
	NotionPageID string
}

var (
	// ErrNotFound indicates the project does not exist.
	ErrNotFound = errors.New("project: not found")

	// ErrConflict indicates a duplicate slug.
	ErrConflict = errors.New("project: conflict")
)
