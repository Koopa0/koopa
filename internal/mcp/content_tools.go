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
	Status      *string `json:"status,omitempty" jsonschema_description:"Change status (any of: draft, review, published, archived). Prefer the lifecycle tools for transitions — this is for direct admin override."`
}

func (s *Server) updateContentTool(ctx context.Context, _ *mcp.CallToolRequest, input UpdateContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.Status != nil && *input.Status != "" && !isValidContentStatus(*input.Status) {
		return nil, ManageContentOutput{}, fmt.Errorf("status must be one of: draft, review, published, archived (got %q)", *input.Status)
	}
	internal := ManageContentInput{
		ContentID:   &input.ContentID,
		Title:       input.Title,
		Body:        input.Body,
		Slug:        input.Slug,
		ContentType: input.ContentType,
		Status:      input.Status,
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
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	status := "review"
	internal := ManageContentInput{
		ContentID: &input.ContentID,
		Status:    &status,
	}
	return s.updateContent(ctx, &internal)
}

// ---------------------------------------------------------------
// revert_content_to_draft
// ---------------------------------------------------------------

type RevertContentToDraftInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID to transition review → draft."`
}

func (s *Server) revertContentToDraftTool(ctx context.Context, _ *mcp.CallToolRequest, input RevertContentToDraftInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	status := "draft"
	internal := ManageContentInput{
		ContentID: &input.ContentID,
		Status:    &status,
	}
	return s.updateContent(ctx, &internal)
}

// ---------------------------------------------------------------
// publish_content  (HUMAN-ONLY — explicit `as` + Platform='human' gated)
// ---------------------------------------------------------------

type PublishContentInput struct {
	As        string `json:"as,omitempty" jsonschema_description:"Self-identification. MUST be an explicit human agent name — the server default does NOT confer publish authority."`
	ContentID string `json:"content_id" jsonschema:"required" jsonschema_description:"Content UUID to publish (must be in status=review)."`
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
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required")
	}
	status := "archived"
	internal := ManageContentInput{
		ContentID: &input.ContentID,
		Status:    &status,
	}
	return s.updateContent(ctx, &internal)
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
