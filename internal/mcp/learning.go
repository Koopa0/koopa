package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	fsrs "github.com/open-spaced-repetition/go-fsrs/v4"

	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/retrieval"
)

// --- B1: get_tag_summary ---

// TagSummaryInput is the input for the get_tag_summary tool.
type TagSummaryInput struct {
	Project   string `json:"project" jsonschema_description:"project slug, alias, or title (required)"`
	TagPrefix string `json:"tag_prefix,omitempty" jsonschema_description:"only return tags starting with this prefix (e.g. weakness: or improvement:)"`
	Days      int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 90, max 365)"`
}

func (s *Server) getTagSummary(ctx context.Context, _ *mcp.CallToolRequest, input TagSummaryInput) (*mcp.CallToolResult, learning.TagSummaryResult, error) {
	if input.Project == "" {
		return nil, learning.TagSummaryResult{}, fmt.Errorf("project is required")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, learning.TagSummaryResult{}, err
	}

	days := clamp(input.Days, 1, 365, 90)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.TagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, learning.TagSummaryResult{}, fmt.Errorf("querying tag entries: %w", err)
	}

	return nil, learning.TagSummary(entries, input.TagPrefix, days), nil
}

// --- B2: get_coverage_matrix ---

// CoverageMatrixInput is the input for the get_coverage_matrix tool.
type CoverageMatrixInput struct {
	Project string `json:"project" jsonschema_description:"project slug, alias, or title (required)"`
	Days    int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 365, max 730)"`
}

func (s *Server) getCoverageMatrix(ctx context.Context, _ *mcp.CallToolRequest, input CoverageMatrixInput) (*mcp.CallToolResult, learning.CoverageMatrixResult, error) {
	if input.Project == "" {
		return nil, learning.CoverageMatrixResult{}, fmt.Errorf("project is required")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, learning.CoverageMatrixResult{}, err
	}

	days := clamp(input.Days, 1, 730, 365)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.TagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, learning.CoverageMatrixResult{}, fmt.Errorf("querying tag entries: %w", err)
	}

	return nil, learning.CoverageMatrix(entries, days), nil
}

// --- B3: get_weakness_trend ---

// WeaknessTrendInput is the input for the get_weakness_trend tool.
type WeaknessTrendInput struct {
	Project string `json:"project" jsonschema_description:"project slug, alias, or title (required)"`
	Tag     string `json:"tag" jsonschema_description:"weakness tag to track (e.g. weakness:constraint-analysis). Required."`
	Days    int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 30, max 180)"`
}

func (s *Server) getWeaknessTrend(ctx context.Context, _ *mcp.CallToolRequest, input WeaknessTrendInput) (*mcp.CallToolResult, learning.WeaknessTrendResult, error) {
	if input.Project == "" {
		return nil, learning.WeaknessTrendResult{}, fmt.Errorf("project is required")
	}
	if input.Tag == "" {
		return nil, learning.WeaknessTrendResult{}, fmt.Errorf("tag is required")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, learning.WeaknessTrendResult{}, err
	}

	days := clamp(input.Days, 1, 180, 30)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.RichTagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, learning.WeaknessTrendResult{}, fmt.Errorf("querying rich tag entries: %w", err)
	}

	return nil, learning.WeaknessTrend(entries, input.Tag, days), nil
}

// --- B4: get_learning_timeline ---

// LearningTimelineInput is the input for the get_learning_timeline tool.
type LearningTimelineInput struct {
	Project string `json:"project,omitempty" jsonschema_description:"project slug, alias, or title (optional — omit for all projects)"`
	Days    int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 14, max 90)"`
}

func (s *Server) getLearningTimeline(ctx context.Context, _ *mcp.CallToolRequest, input LearningTimelineInput) (*mcp.CallToolResult, learning.TimelineResult, error) {
	var projectID *uuid.UUID
	if input.Project != "" {
		proj, err := s.resolveProjectChain(ctx, input.Project)
		if err != nil {
			return nil, learning.TimelineResult{}, err
		}
		projectID = &proj.ID
	}

	days := clamp(input.Days, 1, 90, 14)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.RichTagEntries(ctx, content.TypeTIL, projectID, since)
	if err != nil {
		return nil, learning.TimelineResult{}, fmt.Errorf("querying rich tag entries: %w", err)
	}

	return nil, learning.Timeline(entries, time.Now()), nil
}

// --- B5: log_retrieval_attempt ---

// LogRetrievalAttemptInput is the input for the log_retrieval_attempt tool.
type LogRetrievalAttemptInput struct {
	ContentSlug string  `json:"content_slug" jsonschema:"required" jsonschema_description:"TIL slug to record retrieval for"`
	Rating      int     `json:"rating" jsonschema:"required" jsonschema_description:"recall quality: 1=again(forgot), 2=hard(partial recall), 3=good(remembered), 4=easy"`
	Tag         *string `json:"tag,omitempty" jsonschema_description:"specific weakness/concept tag (omit for whole-content retrieval)"`
}

func (s *Server) logRetrievalAttempt(ctx context.Context, _ *mcp.CallToolRequest, input LogRetrievalAttemptInput) (*mcp.CallToolResult, retrieval.ReviewResult, error) {
	if input.ContentSlug == "" {
		return nil, retrieval.ReviewResult{}, fmt.Errorf("content_slug is required")
	}
	if input.Rating < 1 || input.Rating > 4 {
		return nil, retrieval.ReviewResult{}, fmt.Errorf("invalid rating %d (valid: 1=again, 2=hard, 3=good, 4=easy)", input.Rating)
	}

	c, err := s.contents.ContentBySlug(ctx, input.ContentSlug)
	if err != nil {
		return nil, retrieval.ReviewResult{}, fmt.Errorf("content not found: %s", input.ContentSlug)
	}

	result, err := s.retrieval.ReviewCard(ctx, c.ID, input.Tag, fsrs.Rating(input.Rating), time.Now())
	if err != nil {
		return nil, retrieval.ReviewResult{}, fmt.Errorf("recording review: %w", err)
	}

	return nil, *result, nil
}

// --- B6: get_retrieval_queue ---

// RetrievalQueueInput is the input for the get_retrieval_queue tool.
type RetrievalQueueInput struct {
	Project string `json:"project,omitempty" jsonschema_description:"project slug, alias, or title (optional — omit for all projects)"`
	Limit   int    `json:"limit,omitempty" jsonschema_description:"max items to return (default 10, max 50)"`
}

func (s *Server) getRetrievalQueue(ctx context.Context, _ *mcp.CallToolRequest, input RetrievalQueueInput) (*mcp.CallToolResult, retrieval.QueueResult, error) {
	var projectID *uuid.UUID
	if input.Project != "" {
		proj, err := s.resolveProjectChain(ctx, input.Project)
		if err != nil {
			return nil, retrieval.QueueResult{}, err
		}
		projectID = &proj.ID
	}

	limit := clamp(input.Limit, 1, 50, 10)

	items, err := s.retrieval.Queue(ctx, projectID, time.Now(), limit)
	if err != nil {
		s.logger.Error("get_retrieval_queue failed", "error", err, "project", input.Project, "limit", limit)
		return nil, retrieval.QueueResult{}, fmt.Errorf("querying retrieval queue: %w", err)
	}

	s.logger.Info("get_retrieval_queue ok", "items", len(items), "project", input.Project)
	return nil, retrieval.QueueResult{Items: items}, nil
}

// --- B7: find_similar_content ---

// FindSimilarContentInput is the input for the find_similar_content tool.
type FindSimilarContentInput struct {
	ContentSlug string `json:"content_slug" jsonschema:"required" jsonschema_description:"slug of the TIL to find similar content for"`
	Limit       int    `json:"limit,omitempty" jsonschema_description:"max results (default 5, max 20)"`
}

// FindSimilarContentOutput wraps the slice result as an object (MCP SDK requires object output schema).
type FindSimilarContentOutput struct {
	Items []content.SimilarTIL `json:"items"`
	Total int                  `json:"total"`
}

func (s *Server) findSimilarContent(ctx context.Context, _ *mcp.CallToolRequest, input FindSimilarContentInput) (*mcp.CallToolResult, FindSimilarContentOutput, error) {
	if input.ContentSlug == "" {
		return nil, FindSimilarContentOutput{}, fmt.Errorf("content_slug is required")
	}

	limit := clamp(input.Limit, 1, 20, 5)

	results, err := s.contents.SimilarTILs(ctx, input.ContentSlug, limit)
	if err != nil {
		return nil, FindSimilarContentOutput{}, fmt.Errorf("finding similar content: %w", err)
	}

	return nil, FindSimilarContentOutput{Items: results, Total: len(results)}, nil
}
