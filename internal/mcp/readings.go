// Copyright 2026 Koopa. All rights reserved.

// readings.go holds list_readings and get_reading, the agent's read-only
// window onto Koopa's reading shelf. The readings domain is otherwise
// Koopa-private: it carries no agent write path, is absent from the
// search_knowledge corpus, and is mutated only through the admin HTTP API.
// These two tools let an agent SEE what Koopa is reading (e.g. to ground a
// conversation in a book the owner has on the shelf) without granting any
// ability to change it.
//
// Both tools are gated by requireRegisteredCaller — the same weak identity
// gate the other read tools use — so the zero-privilege "unknown" fallback
// cannot read the private shelf. There is no caller-scoping: the shelf has a
// single human owner, so any registered agent reads the whole shelf.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/reading"
)

// ListReadingsInput is the input for list_readings: an optional status
// filter and the caller self-identification. An empty status returns the
// whole shelf; a non-empty value must be one of the four shelf states.
type ListReadingsInput struct {
	Status string `json:"status,omitempty" jsonschema_description:"Optional shelf-state filter: want_to_read, reading, finished, or abandoned. Omit (or pass empty) for the whole shelf. Any other non-empty value is rejected."`
	As     string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call."`
}

// ReadingListItem is one book on the shelf as list_readings returns it.
// Dates are YYYY-MM-DD strings (null when unset); goal_id is null when the
// book serves no goal.
type ReadingListItem struct {
	ID         string  `json:"id"`
	Title      string  `json:"title"`
	Author     string  `json:"author"`
	Status     string  `json:"status"`
	StartedOn  *string `json:"started_on"`
	FinishedOn *string `json:"finished_on"`
	IsPublic   bool    `json:"is_public"`
	GoalID     *string `json:"goal_id"`
}

// ListReadingsOutput is the output of list_readings.
type ListReadingsOutput struct {
	Readings []ReadingListItem `json:"readings"`
}

func (s *Server) listReadings(ctx context.Context, _ *mcp.CallToolRequest, in ListReadingsInput) (*mcp.CallToolResult, ListReadingsOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "list_readings"); err != nil {
		return nil, ListReadingsOutput{}, err
	}

	var statusArg *reading.Status
	if in.Status != "" {
		st := reading.Status(in.Status)
		if !st.Valid() {
			return nil, ListReadingsOutput{}, fmt.Errorf("invalid status %q: must be one of want_to_read, reading, finished, abandoned", in.Status)
		}
		statusArg = &st
	}

	rows, err := s.readings.Readings(ctx, statusArg)
	if err != nil {
		return nil, ListReadingsOutput{}, fmt.Errorf("listing readings: %w", err)
	}

	items := make([]ReadingListItem, len(rows))
	for i := range rows {
		items[i] = ReadingListItem{
			ID:         rows[i].ID.String(),
			Title:      rows[i].Title,
			Author:     rows[i].Author,
			Status:     string(rows[i].Status),
			StartedOn:  dateString(rows[i].StartedOn),
			FinishedOn: dateString(rows[i].FinishedOn),
			IsPublic:   rows[i].IsPublic,
			GoalID:     uuidString(rows[i].GoalID),
		}
	}
	return nil, ListReadingsOutput{Readings: items}, nil
}

// GetReadingInput is the input for get_reading: a reading id and the caller
// self-identification.
type GetReadingInput struct {
	ID string `json:"id" jsonschema:"required" jsonschema_description:"UUID of the reading (book) to fetch, with its diary thread."`
	As string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call."`
}

// ReadingDetail is one book plus its full reflection thread.
type ReadingDetail struct {
	ID         string  `json:"id"`
	Title      string  `json:"title"`
	Author     string  `json:"author"`
	Status     string  `json:"status"`
	StartedOn  *string `json:"started_on"`
	FinishedOn *string `json:"finished_on"`
	IsPublic   bool    `json:"is_public"`
	GoalID     *string `json:"goal_id"`
}

// ReflectionItem is one dated diary entry under a reading.
type ReflectionItem struct {
	ID        string    `json:"id"`
	EntryDate string    `json:"entry_date"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// GetReadingOutput is the output of get_reading: the book and its diary
// thread in entry_date order (created_at tiebreak).
type GetReadingOutput struct {
	Reading     ReadingDetail    `json:"reading"`
	Reflections []ReflectionItem `json:"reflections"`
}

func (s *Server) getReading(ctx context.Context, _ *mcp.CallToolRequest, in GetReadingInput) (*mcp.CallToolResult, GetReadingOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "get_reading"); err != nil {
		return nil, GetReadingOutput{}, err
	}

	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, GetReadingOutput{}, fmt.Errorf("invalid id %q: %w", in.ID, err)
	}

	rd, err := s.readings.Reading(ctx, id)
	if err != nil {
		if errors.Is(err, reading.ErrNotFound) {
			return nil, GetReadingOutput{}, fmt.Errorf("no reading %s: it does not exist", id)
		}
		return nil, GetReadingOutput{}, fmt.Errorf("fetching reading %s: %w", id, err)
	}

	refs, err := s.readings.Reflections(ctx, id)
	if err != nil {
		return nil, GetReadingOutput{}, fmt.Errorf("listing reflections for reading %s: %w", id, err)
	}

	items := make([]ReflectionItem, len(refs))
	for i := range refs {
		items[i] = ReflectionItem{
			ID:        refs[i].ID.String(),
			EntryDate: refs[i].EntryDate.Format(time.DateOnly),
			Body:      refs[i].Body,
			CreatedAt: refs[i].CreatedAt,
		}
	}

	return nil, GetReadingOutput{
		Reading: ReadingDetail{
			ID:         rd.ID.String(),
			Title:      rd.Title,
			Author:     rd.Author,
			Status:     string(rd.Status),
			StartedOn:  dateString(rd.StartedOn),
			FinishedOn: dateString(rd.FinishedOn),
			IsPublic:   rd.IsPublic,
			GoalID:     uuidString(rd.GoalID),
		},
		Reflections: items,
	}, nil
}

// dateString formats a DATE column (nil-safe) as YYYY-MM-DD, mirroring the
// reading admin handler's wire convention. nil → nil (JSON null).
func dateString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	return new(t.Format(time.DateOnly))
}

// uuidString renders a nullable UUID as its string form. nil → nil (JSON
// null) so an unlinked book reports goal_id: null rather than a zero UUID.
func uuidString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	return new(id.String())
}
