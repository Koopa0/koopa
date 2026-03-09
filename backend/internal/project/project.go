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
	StatusInProgress Status = "in-progress"
	StatusCompleted  Status = "completed"
	StatusMaintained Status = "maintained"
	StatusArchived   Status = "archived"
)

// Project represents a portfolio project.
type Project struct {
	ID              uuid.UUID `json:"id"`
	Slug            string    `json:"slug"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	LongDescription *string   `json:"long_description,omitempty"`
	Role            string    `json:"role"`
	TechStack       []string  `json:"tech_stack"`
	Highlights      []string  `json:"highlights"`
	Problem         *string   `json:"problem,omitempty"`
	Solution        *string   `json:"solution,omitempty"`
	Architecture    *string   `json:"architecture,omitempty"`
	Results         *string   `json:"results,omitempty"`
	GithubURL       *string   `json:"github_url,omitempty"`
	LiveURL         *string   `json:"live_url,omitempty"`
	Featured        bool      `json:"featured"`
	SortOrder       int       `json:"sort_order"`
	Status          Status    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CreateParams are the parameters for creating a project.
type CreateParams struct {
	Slug            string   `json:"slug"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	LongDescription *string  `json:"long_description,omitempty"`
	Role            string   `json:"role"`
	TechStack       []string `json:"tech_stack"`
	Highlights      []string `json:"highlights"`
	Problem         *string  `json:"problem,omitempty"`
	Solution        *string  `json:"solution,omitempty"`
	Architecture    *string  `json:"architecture,omitempty"`
	Results         *string  `json:"results,omitempty"`
	GithubURL       *string  `json:"github_url,omitempty"`
	LiveURL         *string  `json:"live_url,omitempty"`
	Featured        bool     `json:"featured"`
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
	SortOrder       *int     `json:"sort_order,omitempty"`
	Status          *Status  `json:"status,omitempty"`
}

var (
	// ErrNotFound indicates the project does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict indicates a duplicate slug.
	ErrConflict = errors.New("conflict")
)
