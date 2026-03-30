package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

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
	Quality     string  `json:"quality" jsonschema:"required" jsonschema_description:"recall quality: easy, hard, or failed"`
	Tag         *string `json:"tag,omitempty" jsonschema_description:"specific weakness/concept tag (omit for whole-content retrieval)"`
}

func (s *Server) logRetrievalAttempt(ctx context.Context, _ *mcp.CallToolRequest, input LogRetrievalAttemptInput) (*mcp.CallToolResult, retrieval.Attempt, error) {
	if input.ContentSlug == "" {
		return nil, retrieval.Attempt{}, fmt.Errorf("content_slug is required")
	}
	if !retrieval.ValidQuality(input.Quality) {
		return nil, retrieval.Attempt{}, fmt.Errorf("invalid quality %q (valid: easy, hard, failed)", input.Quality)
	}

	c, err := s.contents.ContentBySlug(ctx, input.ContentSlug)
	if err != nil {
		return nil, retrieval.Attempt{}, fmt.Errorf("content not found: %s", input.ContentSlug)
	}

	attempt, err := s.retrieval.LogAttempt(ctx, c.ID, input.Tag, input.Quality, time.Now())
	if err != nil {
		return nil, retrieval.Attempt{}, fmt.Errorf("logging retrieval attempt: %w", err)
	}

	return nil, *attempt, nil
}

// --- B6: get_retrieval_queue ---

// RetrievalQueueInput is the input for the get_retrieval_queue tool.
type RetrievalQueueInput struct {
	Project string `json:"project,omitempty" jsonschema_description:"project slug, alias, or title (optional — omit for all projects)"`
	Limit   int    `json:"limit,omitempty" jsonschema_description:"max items to return (default 10, max 50)"`
}

func (s *Server) getRetrievalQueue(ctx context.Context, _ *mcp.CallToolRequest, input RetrievalQueueInput) (*mcp.CallToolResult, retrieval.QueueResult, error) {
	var projectSlug *string
	if input.Project != "" {
		proj, err := s.resolveProjectChain(ctx, input.Project)
		if err != nil {
			return nil, retrieval.QueueResult{}, err
		}
		projectSlug = &proj.Slug
	}

	limit := clamp(input.Limit, 1, 50, 10)

	items, err := s.retrieval.Queue(ctx, projectSlug, limit)
	if err != nil {
		return nil, retrieval.QueueResult{}, fmt.Errorf("querying retrieval queue: %w", err)
	}

	return nil, retrieval.QueueResult{Items: items}, nil
}
