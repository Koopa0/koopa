// Copyright 2026 Koopa. All rights reserved.

// content_tools.go holds list_content and revise_content — the agent half of
// the content-collaboration loop. An agent submits a source-bound snapshot with
// propose_content (created_by = itself); the owner reviews it in admin and
// either publishes or sends it back (status=changes_requested + review_note).
// list_content lets that same agent read the disposition of the content it
// proposed (including the owner's review_note), and revise_content lets it
// address the feedback and return the row to review.
//
// # Caller-scoping
//
// Both tools are scoped to the resolved caller identity: they act ONLY on the
// content whose created_by equals the caller, never legacy owner-authored
// content or another agent's. There is no created_by input parameter — the
// scope is structural, derived from callerIdentity, so it cannot be widened.
// list_content is read-only; revise_content's caller-scoped UPDATE returns
// not-found for any row the caller did not create or that is not in a revisable
// state, never leaking which.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/goal"
)

// --- list_content ---

// ListContentInput is the input for the list_content tool. It carries only the
// caller self-identification — there are no filters. The readback is
// caller-scoped to the resolved identity, never a free-form filter over the
// owner's or another agent's content.
type ListContentInput struct {
	As string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent whose proposed content to read back. The list is scoped to this resolved identity; it is never a free-form filter over other agents' or the owner's content."`
}

// ContentListItem is one row of list_content: a content piece the calling agent
// proposed, with its current status so the agent can read the disposition. When
// the owner sent the draft back, review_note carries the revision reason.
type ContentListItem struct {
	ID               string  `json:"id"`
	Slug             string  `json:"slug"`
	Title            string  `json:"title"`
	Type             string  `json:"type"`
	Status           string  `json:"status"`
	ReviewNote       *string `json:"review_note,omitempty"`
	SourceVaultPath  string  `json:"source_vault_path"`
	SourceGitBlobSHA string  `json:"source_git_blob_sha"`
	PublishedAt      *string `json:"published_at,omitempty"`
	CreatedAt        string  `json:"created_at"`
}

// ListContentOutput is the output of the list_content tool.
type ListContentOutput struct {
	Items []ContentListItem `json:"items"`
}

func (s *Server) listContent(ctx context.Context, _ *mcp.CallToolRequest, _ ListContentInput) (*mcp.CallToolResult, ListContentOutput, error) {
	caller := s.callerIdentity(ctx)
	rows, err := s.contents.ContentsByCreator(ctx, caller)
	if err != nil {
		return nil, ListContentOutput{}, fmt.Errorf("listing content created by %q: %w", caller, err)
	}

	items := make([]ContentListItem, len(rows))
	for i := range rows {
		r := &rows[i]
		var publishedAt *string
		if r.PublishedAt != nil {
			formatted := r.PublishedAt.Format(time.RFC3339)
			publishedAt = &formatted
		}
		items[i] = ContentListItem{
			ID:               r.ID.String(),
			Slug:             r.Slug,
			Title:            r.Title,
			Type:             string(r.Type),
			Status:           string(r.Status),
			ReviewNote:       r.ReviewNote,
			SourceVaultPath:  r.SourceVaultPath,
			SourceGitBlobSHA: r.SourceGitBlobSHA,
			PublishedAt:      publishedAt,
			CreatedAt:        r.CreatedAt.Format(time.RFC3339),
		}
	}
	return nil, ListContentOutput{Items: items}, nil
}

// --- revise_content ---

// ReviseContentInput is the input for revise_content: the id of content the
// caller created and a complete replacement snapshot. Like list_content there is no
// created_by parameter — the write is scoped to the resolved caller identity, so
// an agent can only revise its own content, never the owner's or another
// agent's. Title/body/excerpt and a new source binding move atomically.
type ReviseContentInput struct {
	ID               string  `json:"id" jsonschema:"required" jsonschema_description:"UUID of content YOU created (created_by = your resolved identity) that is in review or changes_requested. Revising content created by anyone else, or a published row, returns not-found and changes nothing."`
	Body             *string `json:"body" jsonschema:"required" jsonschema_description:"Complete Markdown body from the new Vault snapshot."`
	Excerpt          *string `json:"excerpt" jsonschema:"required" jsonschema_description:"Complete excerpt for the new snapshot. Use an empty string when the snapshot has no excerpt."`
	Title            *string `json:"title" jsonschema:"required" jsonschema_description:"Complete title from the new Vault snapshot."`
	SourceVaultPath  string  `json:"source_vault_path" jsonschema:"required" jsonschema_description:"Vault-relative Markdown source path for this revision."`
	SourceGitBlobSHA string  `json:"source_git_blob_sha" jsonschema:"required" jsonschema_description:"New lowercase 40- or 64-hex Git blob ID. Reusing the current SHA is rejected."`
	As               string  `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call. The revise is scoped to this resolved identity; it can only edit content you created."`
}

// ReviseContentOutput is the output of revise_content: the revised content row,
// now back in review with the owner's review_note cleared.
type ReviseContentOutput struct {
	Content *content.Content        `json:"content"`
	Source  *content.SourceSnapshot `json:"source"`
}

func (s *Server) reviseContent(ctx context.Context, _ *mcp.CallToolRequest, input ReviseContentInput) (*mcp.CallToolResult, ReviseContentOutput, error) {
	id, err := uuid.Parse(strings.TrimSpace(input.ID))
	if err != nil {
		return nil, ReviseContentOutput{}, fmt.Errorf("invalid id %q: %w", input.ID, err)
	}
	if err := validateReviseContentInput(input); err != nil {
		return nil, ReviseContentOutput{}, err
	}

	caller := s.callerIdentity(ctx)

	var revised *content.Content
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var reviseErr error
		revised, reviseErr = s.contents.WithTx(tx).ReviseByCreator(ctx, &content.RevisionParams{
			ID:               id,
			CreatedBy:        caller,
			Body:             *input.Body,
			Excerpt:          *input.Excerpt,
			Title:            *input.Title,
			SourceVaultPath:  input.SourceVaultPath,
			SourceGitBlobSHA: input.SourceGitBlobSHA,
		})
		return reviseErr
	})
	if err != nil {
		if errors.Is(err, content.ErrSourceUnchanged) {
			return nil, ReviseContentOutput{}, fmt.Errorf("revision must submit a new Git blob SHA")
		}
		if errors.Is(err, content.ErrNotFound) {
			return nil, ReviseContentOutput{}, fmt.Errorf("no content %s created by %q in a revisable state: it does not exist, you did not create it, or it is not in review/changes_requested", id, caller)
		}
		return nil, ReviseContentOutput{}, fmt.Errorf("revising content %s: %w", id, err)
	}

	s.logger.Info("revise_content", "content_id", revised.ID, "slug", revised.Slug, "created_by", caller)
	return nil, ReviseContentOutput{Content: revised, Source: revised.Source()}, nil
}

func validateReviseContentInput(input ReviseContentInput) error {
	if input.Body == nil || input.Title == nil || input.Excerpt == nil {
		return fmt.Errorf("title, body, and excerpt are required for a complete source snapshot")
	}
	// Title / excerpt are single-line fields (strict control-char check); body
	// is multi-line Markdown (prose check permits HT/LF/CR). Mirrors
	// propose_content's validation split.
	if goal.ContainsControlChars(*input.Title) {
		return fmt.Errorf("title must not contain control characters")
	}
	if goal.ContainsControlChars(*input.Excerpt) {
		return fmt.Errorf("excerpt must not contain control characters")
	}
	if containsProseControlChars(*input.Body) {
		return fmt.Errorf("body must not contain control characters")
	}
	if err := content.CheckFieldLengths(input.Title, input.Excerpt, input.Body); err != nil {
		return err
	}
	if strings.TrimSpace(*input.Title) == "" {
		return fmt.Errorf("title is required")
	}
	if strings.TrimSpace(*input.Body) == "" {
		return fmt.Errorf("body is required")
	}
	return content.ValidateSourceSnapshot(input.SourceVaultPath, input.SourceGitBlobSHA)
}
