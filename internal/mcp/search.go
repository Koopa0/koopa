package mcp

import (
	"context"
	"fmt"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

// --- search_knowledge ---

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query       string  `json:"query" jsonschema:"required" jsonschema_description:"Search query text"`
	ContentType *string `json:"content_type,omitempty" jsonschema_description:"Filter by type: article, essay, build-log, til, note, bookmark, digest"`
	Project     *string `json:"project,omitempty" jsonschema_description:"Filter by project slug/alias/title"`
	After       *string `json:"after,omitempty" jsonschema_description:"Filter: created after YYYY-MM-DD (exclusive)"`
	Before      *string `json:"before,omitempty" jsonschema_description:"Filter: created before YYYY-MM-DD (exclusive)"`
	Limit       FlexInt `json:"limit,omitempty" jsonschema_description:"Max results (default 20, max 50)"`
}

// SearchKnowledgeResult is a single search result.
type SearchKnowledgeResult struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Slug        string   `json:"slug"`
	ContentType string   `json:"content_type"`
	Excerpt     string   `json:"excerpt"`
	Tags        []string `json:"tags"`
	Project     string   `json:"project,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

// SearchKnowledgeOutput is the output of the search_knowledge tool.
type SearchKnowledgeOutput struct {
	Results []SearchKnowledgeResult `json:"results"`
	Total   int                     `json:"total"`
	Query   string                  `json:"query"`
}

func (s *Server) searchKnowledge(ctx context.Context, _ *sdkmcp.CallToolRequest, input SearchKnowledgeInput) (*sdkmcp.CallToolResult, SearchKnowledgeOutput, error) {
	if input.Query == "" {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("query is required")
	}

	after, err := parseOptionalDate(input.After)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("invalid after date: %w", err)
	}
	before, err := parseOptionalDate(input.Before)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("invalid before date: %w", err)
	}

	limit := clamp(int(input.Limit), 1, 50, 20)

	var ct *content.Type
	if input.ContentType != nil && *input.ContentType != "" {
		t := content.Type(*input.ContentType)
		ct = &t
	}

	contents, total, err := s.contents.Search(ctx, input.Query, ct, 1, limit)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("searching content: %w", err)
	}

	results := make([]SearchKnowledgeResult, 0, len(contents))
	for i := range contents {
		c := &contents[i]
		if after != nil && c.CreatedAt.Before(*after) {
			continue
		}
		if before != nil && c.CreatedAt.After(*before) {
			continue
		}
		results = append(results, s.contentToResult(ctx, c))
	}

	if after != nil || before != nil {
		total = len(results)
	}

	return nil, SearchKnowledgeOutput{
		Results: results,
		Total:   total,
		Query:   input.Query,
	}, nil
}

func (s *Server) contentToResult(ctx context.Context, c *content.Content) SearchKnowledgeResult {
	var projectTitle string
	if c.ProjectID != nil && s.projects != nil {
		if p, pErr := s.projects.ProjectByID(ctx, *c.ProjectID); pErr == nil {
			projectTitle = p.Title
		}
	}
	return SearchKnowledgeResult{
		ID:          c.ID.String(),
		Title:       c.Title,
		Slug:        c.Slug,
		ContentType: string(c.Type),
		Excerpt:     c.Excerpt,
		Tags:        c.Tags,
		Project:     projectTitle,
		CreatedAt:   c.CreatedAt.Format(time.RFC3339),
	}
}

func parseOptionalDate(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.DateOnly, *s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
