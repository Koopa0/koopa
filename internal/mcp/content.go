package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

// --- manage_content ---

type ManageContentInput struct {
	Action      string  `json:"action" jsonschema:"required" jsonschema_description:"Action: create, update, publish, list, read, bookmark_rss"`
	ContentID   *string `json:"content_id,omitempty" jsonschema_description:"Content UUID (required for update/publish/read)"`
	Title       *string `json:"title,omitempty" jsonschema_description:"Content title (required for create)"`
	Body        *string `json:"body,omitempty" jsonschema_description:"Content body (markdown)"`
	ContentType *string `json:"content_type,omitempty" jsonschema_description:"Type: article, essay, build-log, til, note, bookmark, digest"`
	Status      *string `json:"status,omitempty" jsonschema_description:"Status filter (for list) or target status (for update): draft, review, published, archived"`
	Project     *string `json:"project,omitempty" jsonschema_description:"Project slug/alias/title"`
	Limit       FlexInt `json:"limit,omitempty" jsonschema_description:"Max results for list (default 20, max 50)"`
	EntryID     *string `json:"entry_id,omitempty" jsonschema_description:"RSS feed entry UUID (required for bookmark_rss)"`
	Comment     *string `json:"comment,omitempty" jsonschema_description:"Personal comment/annotation (for bookmark_rss)"`
}

// ContentSummary is a lightweight content record for list results.
type ContentSummary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

// ContentDetail is a full content record for read/create/update/publish results.
type ContentDetail struct {
	ID        string   `json:"id"`
	Slug      string   `json:"slug"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Excerpt   string   `json:"excerpt"`
	Type      string   `json:"type"`
	Status    string   `json:"status"`
	Tags      []string `json:"tags,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type ManageContentOutput struct {
	Content  *ContentDetail   `json:"content,omitempty"`
	Contents []ContentSummary `json:"contents,omitempty"`
	Action   string           `json:"action"`
}

func (s *Server) manageContent(ctx context.Context, _ *mcp.CallToolRequest, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	switch input.Action {
	case "create":
		return s.mcCreateContent(ctx, input)
	case "update":
		return s.mcUpdateContent(ctx, input)
	case "publish":
		return s.mcPublishContent(ctx, input)
	case "list":
		return s.mcListContent(ctx, input)
	case "read":
		return s.mcReadContent(ctx, input)
	case "bookmark_rss":
		return s.mcBookmarkRSS(ctx, input)
	default:
		return nil, ManageContentOutput{}, fmt.Errorf("invalid action %q (valid: create, update, publish, list, read, bookmark_rss)", input.Action)
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
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "create"}, nil
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

	var st *content.Status
	if input.Status != nil && *input.Status != "" {
		cs := content.Status(*input.Status)
		st = &cs
	}

	c, err := s.contents.UpdateContent(ctx, id, &content.UpdateParams{
		Title:  input.Title,
		Body:   input.Body,
		Type:   ct,
		Status: st,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("updating content: %w", err)
	}

	s.logger.Info("manage_content", "action", "update", "id", c.ID)
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "update"}, nil
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
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "publish"}, nil
}

func (s *Server) mcListContent(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	limit := clamp(int(input.Limit), 1, 50, 20)

	var ct *content.Type
	if input.ContentType != nil && *input.ContentType != "" {
		t := content.Type(*input.ContentType)
		ct = &t
	}

	// Fetch with type filter at SQL level, then apply status filter in Go.
	// Over-fetch to compensate for post-fetch filtering.
	fetchLimit := limit
	if input.Status != nil && *input.Status != "" {
		fetchLimit = min(limit*3, 50)
	}
	contents, _, err := s.contents.AdminContents(ctx, content.AdminFilter{
		Page: 1, PerPage: fetchLimit, Type: ct,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("listing contents: %w", err)
	}

	summaries := make([]ContentSummary, 0, len(contents))
	for i := range contents {
		c := &contents[i]
		if input.Status != nil && *input.Status != "" && string(c.Status) != *input.Status {
			continue
		}
		summaries = append(summaries, ContentSummary{
			ID:        c.ID.String(),
			Title:     c.Title,
			Type:      string(c.Type),
			Status:    string(c.Status),
			UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
		})
		if len(summaries) >= limit {
			break
		}
	}
	return nil, ManageContentOutput{Contents: summaries, Action: "list"}, nil
}

func (s *Server) mcReadContent(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == nil || *input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for read")
	}
	id, err := uuid.Parse(*input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id: %w", err)
	}

	c, err := s.contents.Content(ctx, id)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("reading content: %w", err)
	}

	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "read"}, nil
}

func (s *Server) mcBookmarkRSS(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if s.feedEntries == nil {
		return nil, ManageContentOutput{}, fmt.Errorf("feed entries store not configured")
	}
	if input.EntryID == nil || *input.EntryID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("entry_id is required for bookmark_rss")
	}
	entryID, err := uuid.Parse(*input.EntryID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid entry_id: %w", err)
	}

	item, err := s.feedEntries.Item(ctx, entryID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("fetching entry: %w", err)
	}

	// Build bookmark body: source URL + optional original content + personal comment.
	var body strings.Builder
	fmt.Fprintf(&body, "**Source:** %s\n\n", item.SourceURL)
	if item.OriginalContent != nil && *item.OriginalContent != "" {
		fmt.Fprintf(&body, "**Excerpt:**\n\n%s\n\n", truncate(*item.OriginalContent, 500))
	}
	if input.Comment != nil && *input.Comment != "" {
		fmt.Fprintf(&body, "**Comment:**\n\n%s\n", *input.Comment)
	}

	title := item.Title
	if input.Title != nil && *input.Title != "" {
		title = *input.Title
	}
	slug := strings.ToLower(strings.ReplaceAll(title, " ", "-"))

	src := "external"
	srcType := content.SourceExternal
	c, err := s.contents.CreateContent(ctx, &content.CreateParams{
		Slug:        slug,
		Title:       title,
		Body:        body.String(),
		Type:        content.TypeBookmark,
		Status:      content.StatusDraft,
		ReviewLevel: content.ReviewLight,
		Source:      &src,
		SourceType:  &srcType,
	})
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("creating bookmark: %w", err)
	}

	// Link the RSS entry to the newly created content.
	if err := s.feedEntries.Curate(ctx, entryID, c.ID); err != nil {
		s.logger.Warn("bookmark_rss: failed to curate entry", "entry_id", entryID, "content_id", c.ID, "error", err)
	}

	s.logger.Info("manage_content", "action", "bookmark_rss", "id", c.ID, "entry_id", entryID)
	return nil, ManageContentOutput{Content: toContentDetail(c), Action: "bookmark_rss"}, nil
}

func toContentDetail(c *content.Content) *ContentDetail {
	return &ContentDetail{
		ID:        c.ID.String(),
		Slug:      c.Slug,
		Title:     c.Title,
		Body:      c.Body,
		Excerpt:   c.Excerpt,
		Type:      string(c.Type),
		Status:    string(c.Status),
		Tags:      c.Tags,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
	}
}

func toContentSummaries(contents []content.Content) []ContentSummary {
	summaries := make([]ContentSummary, len(contents))
	for i := range contents {
		c := &contents[i]
		summaries[i] = ContentSummary{
			ID:        c.ID.String(),
			Title:     c.Title,
			Type:      string(c.Type),
			Status:    string(c.Status),
			UpdatedAt: c.UpdatedAt.Format(time.RFC3339),
		}
	}
	return summaries
}
