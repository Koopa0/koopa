package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

// --- manage_content ---

type ManageContentInput struct {
	Action      string  `json:"action" jsonschema:"required" jsonschema_description:"Action: create, update, publish"`
	ContentID   *string `json:"content_id,omitempty" jsonschema_description:"Content UUID (required for update/publish)"`
	Title       *string `json:"title,omitempty" jsonschema_description:"Content title (required for create)"`
	Body        *string `json:"body,omitempty" jsonschema_description:"Content body (markdown)"`
	ContentType *string `json:"content_type,omitempty" jsonschema_description:"Type: article, essay, build-log, til, note, bookmark, digest"`
	Project     *string `json:"project,omitempty" jsonschema_description:"Project slug/alias/title"`
}

type ManageContentOutput struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Action string `json:"action"`
}

func (s *Server) manageContent(ctx context.Context, _ *mcp.CallToolRequest, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	switch input.Action {
	case "create":
		return s.mcCreateContent(ctx, input)
	case "update":
		return s.mcUpdateContent(ctx, input)
	case "publish":
		return s.mcPublishContent(ctx, input)
	default:
		return nil, ManageContentOutput{}, fmt.Errorf("invalid action %q (valid: create, update, publish)", input.Action)
	}
}

func (s *Server) mcCreateContent(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.Title == nil || *input.Title == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("title is required for create")
	}
	if input.ContentType == nil || *input.ContentType == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_type is required for create")
	}

	body := ""
	if input.Body != nil {
		body = *input.Body
	}

	slug := strings.ToLower(strings.ReplaceAll(*input.Title, " ", "-"))
	var projectID *uuid.UUID
	if input.Project != nil && *input.Project != "" {
		projectID = s.resolveProjectID(ctx, *input.Project)
	}

	c, err := s.contents.CreateContent(ctx, &content.CreateParams{
		Slug:        slug,
		Title:       *input.Title,
		Body:        body,
		Type:        content.Type(*input.ContentType),
		Status:      content.StatusDraft,
		ReviewLevel: content.ReviewStandard,
		ProjectID:   projectID,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("creating content: %w", err)
	}

	s.logger.Info("manage_content", "action", "create", "id", c.ID)
	return nil, ManageContentOutput{ID: c.ID.String(), Title: c.Title, Status: string(c.Status), Action: "create"}, nil
}

func (s *Server) mcUpdateContent(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == nil || *input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for update")
	}
	id, err := uuid.Parse(*input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	var ct *content.Type
	if input.ContentType != nil && *input.ContentType != "" {
		t := content.Type(*input.ContentType)
		ct = &t
	}

	c, err := s.contents.UpdateContent(ctx, id, &content.UpdateParams{
		Title: input.Title,
		Body:  input.Body,
		Type:  ct,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("updating content: %w", err)
	}

	s.logger.Info("manage_content", "action", "update", "id", c.ID)
	return nil, ManageContentOutput{ID: c.ID.String(), Title: c.Title, Status: string(c.Status), Action: "update"}, nil
}

func (s *Server) mcPublishContent(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == nil || *input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for publish")
	}
	id, err := uuid.Parse(*input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	published := content.StatusPublished
	c, err := s.contents.UpdateContent(ctx, id, &content.UpdateParams{
		Status: &published,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("publishing content: %w", err)
	}

	s.logger.Info("manage_content", "action", "publish", "id", c.ID)
	return nil, ManageContentOutput{ID: c.ID.String(), Title: c.Title, Status: string(c.Status), Action: "publish"}, nil
}
