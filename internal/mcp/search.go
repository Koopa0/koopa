package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/obsidian/note"
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

func (s *Server) searchKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input SearchKnowledgeInput) (*mcp.CallToolResult, SearchKnowledgeOutput, error) {
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

	contents, _, err := s.contents.InternalSearch(ctx, input.Query, 1, limit)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("searching content: %w", err)
	}

	results := s.filterContentResults(ctx, contents, input.ContentType, after, before)

	// Also search notes (Obsidian knowledge notes).
	if s.notes != nil {
		noteResults, nErr := s.notes.SearchByText(ctx, input.Query, limit)
		if nErr == nil {
			for i := range noteResults {
				nr := &noteResults[i]
				results = append(results, noteToResult(nr))
			}
		}
	}

	return nil, SearchKnowledgeOutput{
		Results: results,
		Total:   len(results),
		Query:   input.Query,
	}, nil
}

func (s *Server) filterContentResults(ctx context.Context, contents []content.Content, contentType *string, after, before *time.Time) []SearchKnowledgeResult {
	results := make([]SearchKnowledgeResult, 0, len(contents))
	for i := range contents {
		c := &contents[i]
		if contentType != nil && *contentType != "" && string(c.Type) != *contentType {
			continue
		}
		if after != nil && c.CreatedAt.Before(*after) {
			continue
		}
		if before != nil && c.CreatedAt.After(*before) {
			continue
		}
		results = append(results, s.contentToResult(ctx, c))
	}
	return results
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
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

func noteToResult(nr *note.SearchResult) SearchKnowledgeResult {
	title := nr.FilePath
	if nr.Title != nil {
		title = *nr.Title
	}
	excerpt := ""
	if nr.ContentText != nil {
		excerpt = truncate(*nr.ContentText, 200)
	}
	createdStr := ""
	if nr.GitCreatedAt != nil {
		createdStr = nr.GitCreatedAt.Format(time.RFC3339)
	} else if nr.SyncedAt != nil {
		createdStr = nr.SyncedAt.Format(time.RFC3339)
	}
	return SearchKnowledgeResult{
		ID:          fmt.Sprintf("%d", nr.ID),
		Title:       title,
		Slug:        nr.FilePath,
		ContentType: "note",
		Excerpt:     excerpt,
		CreatedAt:   createdStr,
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
