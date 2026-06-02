// Copyright 2026 Koopa. All rights reserved.

// content_tools.go is the MCP surface for the content lifecycle — eight
// flat tool handlers (create_content, update_content,
// submit_content_for_review, revert_content_to_draft, publish_content,
// archive_content, list_content, read_content). Each has its own
// narrow input struct and its own MCP annotations (via
// ops.CreateContent / ops.PublishContent / …).
//
// Implementation split:
//   - content_tools.go (this file) — MCP boundary: one input struct +
//     one thin handler per user intent.
//   - content.go                   — internal workhorses fed by every
//     handler in this file. The old manage_content multiplexer lived
//     there; the shared ManageContentInput shape survives as an
//     internal call-target, not a tool.
//
// If you add a new content tool: declare it in ops/catalog.go, wire it
// in server.go, and add the input+handler here. Do NOT put business
// logic in this file.

package mcp

import (
	"context"
	"fmt"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------
// create_content
// ---------------------------------------------------------------

type CreateContentInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification — the agent creating this content."`
	Title       string  `json:"title" jsonschema:"required" jsonschema_description:"Content title."`
	ContentType string  `json:"content_type" jsonschema:"required" jsonschema_description:"One of: article, essay, build-log, til, digest. Notes use create_note."`
	Slug        *string `json:"slug,omitempty" jsonschema_description:"Optional URL-safe slug. Server derives from title when omitted."`
	Body        *string `json:"body,omitempty" jsonschema_description:"Content body (markdown)."`
	Project     *string `json:"project,omitempty" jsonschema_description:"Optional project slug/alias/title to associate."`
}

func (s *Server) createContentTool(ctx context.Context, _ *mcp.CallToolRequest, input CreateContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	internal := ManageContentInput{
		Title:       &input.Title,
		ContentType: &input.ContentType,
		Slug:        input.Slug,
		Body:        input.Body,
		Project:     input.Project,
	}
	return s.createContent(ctx, &internal)
}

// ---------------------------------------------------------------
// update_content
// ---------------------------------------------------------------

type UpdateContentInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentID   string  `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID."`
	Title       *string `json:"title,omitempty"`
	Body        *string `json:"body,omitempty"`
	Slug        *string `json:"slug,omitempty"`
	ContentType *string `json:"content_type,omitempty" jsonschema_description:"Change content type (rare)."`
	// Status is accepted only to REJECT it: update_content is fields-only and
	// does not move the lifecycle. Sending a status here returns an error
	// pointing at the dedicated transition tools.
	Status *string `json:"status,omitempty" jsonschema_description:"REJECTED. update_content does not change status — use submit_content_for_review / revert_content_to_draft / publish_content / archive_content for lifecycle transitions."`
}

func (s *Server) updateContentTool(ctx context.Context, _ *mcp.CallToolRequest, input UpdateContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.Status != nil && *input.Status != "" {
		return nil, ManageContentOutput{}, fmt.Errorf("update_content does not change status — use submit_content_for_review, revert_content_to_draft, publish_content, or archive_content for lifecycle transitions")
	}
	internal := ManageContentInput{
		ContentID:   &input.ContentID,
		Title:       input.Title,
		Body:        input.Body,
		Slug:        input.Slug,
		ContentType: input.ContentType,
		// Status intentionally NOT forwarded — update_content is fields-only.
	}
	return s.updateContent(ctx, &internal)
}

// ---------------------------------------------------------------
// submit_content_for_review
// ---------------------------------------------------------------

type SubmitContentForReviewInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID to transition draft → review."`
}

func (s *Server) submitContentForReviewTool(ctx context.Context, _ *mcp.CallToolRequest, input SubmitContentForReviewInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if err := s.requireAuthor(ctx, "submit_content_for_review", "content-studio", "learning-studio"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	// draft → review; review → review idempotent no-op; published/archived/other rejected.
	c, err := s.transitionContentStatus(ctx, input.ContentID, content.StatusReview, content.StatusDraft)
	if err != nil {
		return nil, ManageContentOutput{}, mapContentTransitionErr(err, input.ContentID,
			"submit_content_for_review", "must be in draft state (already-review is an idempotent no-op)")
	}
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "submit_for_review"}, nil
}

// ---------------------------------------------------------------
// revert_content_to_draft
// ---------------------------------------------------------------

type RevertContentToDraftInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID to transition review → draft."`
}

func (s *Server) revertContentToDraftTool(ctx context.Context, _ *mcp.CallToolRequest, input RevertContentToDraftInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if err := s.requireAuthor(ctx, "revert_content_to_draft", "content-studio", "learning-studio"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	// review → draft; draft → draft idempotent no-op; published/archived/other rejected.
	c, err := s.transitionContentStatus(ctx, input.ContentID, content.StatusDraft, content.StatusReview)
	if err != nil {
		return nil, ManageContentOutput{}, mapContentTransitionErr(err, input.ContentID,
			"revert_content_to_draft", "must be in review state (already-draft is an idempotent no-op)")
	}
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "revert_to_draft"}, nil
}

// ---------------------------------------------------------------
// publish_content  (HUMAN-ONLY — explicit `as` + Platform='human' gated)
// ---------------------------------------------------------------

type PublishContentInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification. MUST be an explicit human agent name — the server default does NOT confer publish authority."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID to publish. Review-gated: only status=review transitions to published. Already-published is an idempotent no-op; draft/archived are rejected (status=review required)."`
}

func (s *Server) publishContentTool(ctx context.Context, _ *mcp.CallToolRequest, input PublishContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	internal := ManageContentInput{ContentID: &input.ContentID}
	return s.publishContent(ctx, &internal)
}

// ---------------------------------------------------------------
// archive_content
// ---------------------------------------------------------------

type ArchiveContentInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID to archive."`
}

func (s *Server) archiveContentTool(ctx context.Context, _ *mcp.CallToolRequest, input ArchiveContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if err := s.requireAuthor(ctx, "archive_content", "content-studio", "learning-studio"); err != nil {
		return nil, ManageContentOutput{}, err
	}
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	// draft/review → archived; archived → archived idempotent no-op. Published
	// is rejected: depublication is a separate lifecycle decision and must not
	// be hidden inside archive_content.
	c, err := s.transitionContentStatus(ctx, input.ContentID, content.StatusArchived, content.StatusDraft, content.StatusReview)
	if err != nil {
		return nil, ManageContentOutput{}, mapContentTransitionErr(err, input.ContentID,
			"archive_content", "must be in draft or review state; published content must be depublished separately before archiving")
	}
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "archive"}, nil
}

// ---------------------------------------------------------------
// list_content  (read-only)
// ---------------------------------------------------------------

type ListContentInput struct {
	As          string  `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentType *string `json:"content_type,omitempty" jsonschema_description:"Filter by type (article, essay, build-log, til, digest)."`
	Status      *string `json:"status,omitempty" jsonschema_description:"Filter by status (draft, review, published, archived)."`
	Project     *string `json:"project,omitempty" jsonschema_description:"Filter by project slug."`
	Limit       FlexInt `json:"limit,omitempty" jsonschema_description:"Max results (default 20, max 50)."`
}

func (s *Server) listContentTool(ctx context.Context, _ *mcp.CallToolRequest, input ListContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.Status != nil && *input.Status != "" && !isValidContentStatus(*input.Status) {
		return nil, ManageContentOutput{}, fmt.Errorf("status must be one of: draft, review, published, archived (got %q)", *input.Status)
	}
	internal := ManageContentInput{
		ContentType: input.ContentType,
		Status:      input.Status,
		Project:     input.Project,
		Limit:       input.Limit,
	}
	return s.listContent(ctx, &internal)
}

// ---------------------------------------------------------------
// read_content  (read-only)
// ---------------------------------------------------------------

type ReadContentInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID."`
}

func (s *Server) readContentTool(ctx context.Context, _ *mcp.CallToolRequest, input ReadContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	internal := ManageContentInput{ContentID: &input.ContentID}
	return s.readContent(ctx, &internal)
}
