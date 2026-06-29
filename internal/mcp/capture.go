// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/todo"
)

// --- capture_inbox ---

// CaptureInboxInput is the input for the capture_inbox tool. capture_inbox
// writes a single personal GTD todo into the owner's inbox for triage.
type CaptureInboxInput struct {
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Todo title. The created todo enters state=inbox; it must be clarified to state=todo (via the admin UI) before it can be passed to plan_day."`
	Description string  `json:"description,omitempty" jsonschema_description:"Optional detail. Rendered as Markdown in the clarify dialog — separate paragraphs with a blank line and use '-' lists for multiple points so it stays readable; do not write one unbroken wall of text. Keep it a capture (context + why it matters + any links), not an essay."`
	Project     string  `json:"project,omitempty" jsonschema_description:"Project slug, alias, or title (fuzzy matched)"`
	Energy      *string `json:"energy,omitempty" jsonschema_description:"Energy level. One of: \"high\", \"medium\", \"low\". Other values are rejected at the handler layer."`
	Due         *string `json:"due,omitempty" jsonschema_description:"Due date YYYY-MM-DD (stored as field value, does NOT affect status)"`

	// Optional recurrence — capture a routine in one call instead of capture +
	// set_todo_recurrence. Exactly one mode (weekdays OR interval+unit) or
	// neither (a plain one-off). Like due/energy, it is a captured attribute,
	// not an activation: the recurring todo lands in state=inbox and stays
	// dormant (excluded from the due-today recurrence surface) until the owner
	// clarifies it.
	Weekdays []string `json:"weekdays,omitempty" jsonschema_description:"Weekday-mode recurrence: any of mon,tue,wed,thu,fri,sat,sun (all seven = daily). Mutually exclusive with interval/unit. Omit for a one-off."`
	Interval *int     `json:"interval,omitempty" jsonschema_description:"Interval-mode recurrence: recur every N units from the last completion. Requires unit; must be > 0. Mutually exclusive with weekdays."`
	Unit     *string  `json:"unit,omitempty" jsonschema_description:"Interval-mode unit: days, weeks, months, or years. Required with interval."`
}

// CaptureInboxOutput is the output of the capture_inbox tool.
type CaptureInboxOutput struct {
	Todo todo.Item `json:"todo"`
}

//nolint:gocritic // hugeParam: the MCP SDK passes the tool input struct by value
func (s *Server) captureInbox(ctx context.Context, _ *mcp.CallToolRequest, input CaptureInboxInput) (*mcp.CallToolResult, CaptureInboxOutput, error) {
	due, rec, hasRecurrence, err := validateCaptureInput(&input)
	if err != nil {
		return nil, CaptureInboxOutput{}, err
	}

	var projectID *uuid.UUID
	if input.Project != "" {
		projectID = s.resolveProjectID(ctx, input.Project)
	}

	caller := s.callerIdentity(ctx)
	var created *todo.Item
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := todo.NewStore(tx)
		var err error
		created, err = store.Create(ctx, &todo.CreateParams{
			Title:       input.Title,
			Description: input.Description,
			ProjectID:   projectID,
			Due:         due,
			Energy:      input.Energy,
			Priority:    nil,
			CreatedBy:   caller,
		})
		if err != nil {
			return err
		}
		if hasRecurrence {
			// Caller-scoped: the just-created todo is created_by=caller, so the
			// scope matches. The recurring inbox todo stays dormant until clarify.
			if err := store.SetRecurrence(ctx, created.ID, caller, rec); err != nil {
				return err
			}
			created.RecurWeekdays = rec.Weekdays
			created.RecurInterval = rec.Interval
			created.RecurUnit = rec.Unit
		}
		return nil
	})
	if err != nil {
		return nil, CaptureInboxOutput{}, fmt.Errorf("capturing to inbox: %w", err)
	}

	s.logger.Info("capture_inbox", "todo_id", created.ID, "title", created.Title)
	return nil, CaptureInboxOutput{Todo: *created}, nil
}

// validateCaptureInput validates the capture fields and resolves the optional
// due date and recurrence before any write, so a bad value fails fast with a
// clear message instead of a CHECK error mid-transaction. hasRecurrence is
// false (and rec is the zero value) when no recurrence fields are supplied —
// a plain one-off capture.
func validateCaptureInput(input *CaptureInboxInput) (due *time.Time, rec todo.Recurrence, hasRecurrence bool, err error) {
	if input.Title == "" {
		return nil, rec, false, fmt.Errorf("title is required")
	}
	if goal.ContainsControlChars(input.Title) {
		return nil, rec, false, fmt.Errorf("title must not contain control characters")
	}
	if goal.ContainsControlChars(input.Description) {
		return nil, rec, false, fmt.Errorf("description must not contain control characters")
	}
	if input.Energy != nil && *input.Energy != "" && !isValidEnergy(*input.Energy) {
		return nil, rec, false, fmt.Errorf("energy must be one of: high, medium, low (got %q)", *input.Energy)
	}

	if input.Due != nil && *input.Due != "" {
		t, parseErr := time.Parse(time.DateOnly, *input.Due)
		if parseErr != nil {
			return nil, rec, false, fmt.Errorf("invalid due date %q (expected YYYY-MM-DD): %w", *input.Due, parseErr)
		}
		due = &t
	}

	hasRecurrence = len(input.Weekdays) > 0 || input.Interval != nil || input.Unit != nil
	if hasRecurrence {
		rec, _, err = buildRecurrence(input.Weekdays, input.Interval, input.Unit, false)
		if err != nil {
			return nil, rec, false, err
		}
	}
	return due, rec, hasRecurrence, nil
}
