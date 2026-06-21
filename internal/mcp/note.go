// Copyright 2026 Koopa. All rights reserved.

// note.go holds the Zettelkasten note MCP tools: create_note and
// update_note. Two flat handlers, no multiplexer (multiplexers only
// when all actions share the same workflow + ≤6 actions; two distinct
// note-lifecycle intents do not justify one). Maturity transitions are
// not on the MCP surface — they go through the admin HTTP endpoint.
//
// Not to be confused with agent_note.go — that file handles the
// runtime log on internal/agent/note. Keeping the filename parallel to
// the Go package structure (internal/note here, internal/agent/note
// there) is intentional.
//
// # Authorization stance — intentionally open
//
// Both handlers (create_note, update_note) accept any registered
// caller without an author allowlist. Notes form
// the AI-for-human / human-for-human knowledge layer: any agent that
// observes something note-worthy may write it down, and the
// front-end review surface (maturity transitions, curation tools) is
// where quality is enforced — not at the write boundary. Restricting
// authorship would force agents to launder their observations through
// agent_notes(kind=context|reflection) and lose the slug-addressable
// knowledge graph that notes provide.
//
// This contrasts with content (publishing is gated to the human in the
// admin UI) and with high-commitment entities — goals, projects,
// learning plans — which the agent surface cannot create at all. Notes
// are not commitments and never publish; the looser rule is
// intentional, not an oversight.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/note"
)

// NoteDetail is the wire shape for a single note in tool replies.
type NoteDetail struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Kind      string `json:"kind"`
	Maturity  string `json:"maturity"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// NoteReply is the shared reply envelope for every note mutation tool.
type NoteReply struct {
	Note *NoteDetail `json:"note"`
}

// ---------------------------------------------------------------
// create_note
// ---------------------------------------------------------------

// CreateNoteInput is the tight input for create_note.
type CreateNoteInput struct {
	As    string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making this call. Stamped on notes.created_by."`
	Slug  string `json:"slug" jsonschema:"required" jsonschema_description:"URL-safe slug. Lowercase alphanumeric + hyphens. Globally unique within notes."`
	Title string `json:"title" jsonschema:"required" jsonschema_description:"Display title. Must be non-blank."`
	Body  string `json:"body,omitempty" jsonschema_description:"Note body in markdown. Defaults to empty string."`
	Kind  string `json:"kind" jsonschema:"required" jsonschema_description:"One of: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing."`
}

func (s *Server) createNote(ctx context.Context, _ *mcp.CallToolRequest, input CreateNoteInput) (*mcp.CallToolResult, NoteReply, error) {
	if err := s.requireRegisteredCaller(ctx, "create_note"); err != nil {
		return nil, NoteReply{}, err
	}
	if input.Slug == "" {
		return nil, NoteReply{}, fmt.Errorf("slug is required")
	}
	if input.Title == "" {
		return nil, NoteReply{}, fmt.Errorf("title is required")
	}
	if goal.ContainsControlChars(input.Title) {
		return nil, NoteReply{}, fmt.Errorf("title must not contain control characters")
	}
	if goal.ContainsControlChars(input.Body) {
		return nil, NoteReply{}, fmt.Errorf("body must not contain control characters")
	}
	kind := note.Kind(input.Kind)
	if !kind.Valid() {
		return nil, NoteReply{}, fmt.Errorf("invalid kind %q (one of: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing)", input.Kind)
	}

	var n *note.Note
	err := s.withActorTx(ctx, func(tx pgx.Tx) error {
		var createErr error
		n, createErr = s.notes.WithTx(tx).Create(ctx, &note.CreateParams{
			Slug:      input.Slug,
			Title:     input.Title,
			Body:      input.Body,
			Kind:      kind,
			CreatedBy: s.callerIdentity(ctx),
		})
		return createErr
	})
	if err != nil {
		if errors.Is(err, note.ErrConflict) {
			return nil, NoteReply{}, fmt.Errorf("slug already exists: %q", input.Slug)
		}
		if errors.Is(err, note.ErrInvalidInput) {
			return nil, NoteReply{}, fmt.Errorf("invalid note input: slug must be url-safe and title must not be blank")
		}
		return nil, NoteReply{}, fmt.Errorf("creating note: %w", err)
	}

	s.logger.Info("create_note", "id", n.ID, "kind", n.Kind)
	return nil, NoteReply{Note: toNoteDetail(n)}, nil
}

// ---------------------------------------------------------------
// update_note
// ---------------------------------------------------------------

// UpdateNoteInput is the tight input for update_note. Maturity is
// intentionally NOT in this tool — transitions go through the admin HTTP
// endpoint (POST /api/admin/knowledge/notes/{id}/maturity), not MCP.
type UpdateNoteInput struct {
	As     string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	NoteID string  `json:"note_id" jsonschema:"required" jsonschema_description:"UUID of the note to update."`
	Slug   *string `json:"slug,omitempty" jsonschema_description:"Optional new slug."`
	Title  *string `json:"title,omitempty" jsonschema_description:"Optional new title."`
	Body   *string `json:"body,omitempty" jsonschema_description:"Optional new body."`
	Kind   *string `json:"kind,omitempty" jsonschema_description:"Optional new kind."`
}

func (s *Server) updateNote(ctx context.Context, _ *mcp.CallToolRequest, input UpdateNoteInput) (*mcp.CallToolResult, NoteReply, error) {
	if err := s.requireRegisteredCaller(ctx, "update_note"); err != nil {
		return nil, NoteReply{}, err
	}
	if input.NoteID == "" {
		return nil, NoteReply{}, fmt.Errorf("note_id is required")
	}
	id, err := uuid.Parse(input.NoteID)
	if err != nil {
		return nil, NoteReply{}, fmt.Errorf("invalid note_id: %w", err)
	}
	if input.Title != nil && goal.ContainsControlChars(*input.Title) {
		return nil, NoteReply{}, fmt.Errorf("title must not contain control characters")
	}
	if input.Body != nil && goal.ContainsControlChars(*input.Body) {
		return nil, NoteReply{}, fmt.Errorf("body must not contain control characters")
	}

	params := note.UpdateParams{
		Slug:  input.Slug,
		Title: input.Title,
		Body:  input.Body,
	}
	if input.Kind != nil && *input.Kind != "" {
		k := note.Kind(*input.Kind)
		if !k.Valid() {
			return nil, NoteReply{}, fmt.Errorf("invalid kind %q", *input.Kind)
		}
		params.Kind = &k
	}

	var n *note.Note
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var updateErr error
		n, updateErr = s.notes.WithTx(tx).Update(ctx, id, params)
		return updateErr
	})
	if err != nil {
		if errors.Is(err, note.ErrNotFound) {
			return nil, NoteReply{}, fmt.Errorf("note %s not found", id)
		}
		if errors.Is(err, note.ErrConflict) {
			return nil, NoteReply{}, fmt.Errorf("slug conflict on update")
		}
		if errors.Is(err, note.ErrInvalidInput) {
			return nil, NoteReply{}, fmt.Errorf("invalid note input: slug must be url-safe and title must not be blank")
		}
		return nil, NoteReply{}, fmt.Errorf("updating note: %w", err)
	}

	s.logger.Info("update_note", "id", n.ID)
	return nil, NoteReply{Note: toNoteDetail(n)}, nil
}

// ---------------------------------------------------------------
// helpers
// ---------------------------------------------------------------

func toNoteDetail(n *note.Note) *NoteDetail {
	if n == nil {
		return nil
	}
	return &NoteDetail{
		ID:        n.ID.String(),
		Slug:      n.Slug,
		Title:     n.Title,
		Body:      n.Body,
		Kind:      string(n.Kind),
		Maturity:  string(n.Maturity),
		CreatedBy: n.CreatedBy,
		CreatedAt: n.CreatedAt.Format(time.RFC3339),
		UpdatedAt: n.UpdatedAt.Format(time.RFC3339),
	}
}
