package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/learning"
)

// --- B1: get_tag_summary ---

// TagSummaryInput is the input for the get_tag_summary tool.
type TagSummaryInput struct {
	Project   string `json:"project" jsonschema_description:"project slug, alias, or title (required)"`
	TagPrefix string `json:"tag_prefix,omitempty" jsonschema_description:"only return tags starting with this prefix (e.g. weakness: or improvement:)"`
	Days      int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 90, max 365)"`
}

// TagSummaryOutput is the output for the get_tag_summary tool.
type TagSummaryOutput struct {
	Tags    []learning.TagCount `json:"tags"`
	Total   int                 `json:"total"`
	Project string              `json:"project"`
	Period  string              `json:"period"`
}

func (s *Server) getTagSummary(ctx context.Context, _ *mcp.CallToolRequest, input TagSummaryInput) (*mcp.CallToolResult, TagSummaryOutput, error) {
	if input.Project == "" {
		return nil, TagSummaryOutput{}, fmt.Errorf("project is required")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, TagSummaryOutput{}, err
	}

	days := clamp(input.Days, 1, 365, 90)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.TagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, TagSummaryOutput{}, fmt.Errorf("querying tag entries: %w", err)
	}

	result := learning.TagSummary(entries, input.TagPrefix, days)

	return nil, TagSummaryOutput{
		Tags:    result.Tags,
		Total:   result.TotalTags,
		Project: proj.Slug,
		Period:  learning.FormatPeriod(days),
	}, nil
}

// --- B2: get_coverage_matrix ---

// CoverageMatrixInput is the input for the get_coverage_matrix tool.
type CoverageMatrixInput struct {
	Project string `json:"project" jsonschema_description:"project slug, alias, or title (required)"`
	Days    int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 365, max 730)"`
}

// CoverageMatrixOutput is the output for the get_coverage_matrix tool.
type CoverageMatrixOutput struct {
	Topics  []learning.TopicCoverage `json:"topics"`
	Total   int                      `json:"total"`
	Project string                   `json:"project"`
	Period  string                   `json:"period"`
}

func (s *Server) getCoverageMatrix(ctx context.Context, _ *mcp.CallToolRequest, input CoverageMatrixInput) (*mcp.CallToolResult, CoverageMatrixOutput, error) {
	if input.Project == "" {
		return nil, CoverageMatrixOutput{}, fmt.Errorf("project is required")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, CoverageMatrixOutput{}, err
	}

	days := clamp(input.Days, 1, 730, 365)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.TagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, CoverageMatrixOutput{}, fmt.Errorf("querying tag entries: %w", err)
	}

	result := learning.CoverageMatrix(entries, days)

	return nil, CoverageMatrixOutput{
		Topics:  result.Topics,
		Total:   result.TotalEntries,
		Project: proj.Slug,
		Period:  learning.FormatPeriod(days),
	}, nil
}

// --- B3: get_weakness_trend ---

// WeaknessTrendInput is the input for the get_weakness_trend tool.
type WeaknessTrendInput struct {
	Project string `json:"project" jsonschema_description:"project slug, alias, or title (required)"`
	Tag     string `json:"tag" jsonschema_description:"weakness tag to track (e.g. weakness:constraint-analysis). Required."`
	Days    int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default 30, max 180)"`
}

// WeaknessTrendOutput is the output for the get_weakness_trend tool.
type WeaknessTrendOutput struct {
	Tag         string                   `json:"tag"`
	Occurrences []learning.WeaknessPoint `json:"occurrences"`
	Total       int                      `json:"total"`
	Trend       string                   `json:"trend"`
	Project     string                   `json:"project"`
	Period      string                   `json:"period"`
}

func (s *Server) getWeaknessTrend(ctx context.Context, _ *mcp.CallToolRequest, input WeaknessTrendInput) (*mcp.CallToolResult, WeaknessTrendOutput, error) {
	if input.Project == "" {
		return nil, WeaknessTrendOutput{}, fmt.Errorf("project is required")
	}
	if input.Tag == "" {
		return nil, WeaknessTrendOutput{}, fmt.Errorf("tag is required")
	}

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, WeaknessTrendOutput{}, err
	}

	days := clamp(input.Days, 1, 180, 30)
	since := time.Now().AddDate(0, 0, -days)

	entries, err := s.contents.TagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, WeaknessTrendOutput{}, fmt.Errorf("querying tag entries: %w", err)
	}

	result := learning.WeaknessTrend(entries, input.Tag, days)

	return nil, WeaknessTrendOutput{
		Tag:         result.Tag,
		Occurrences: result.Occurrences,
		Total:       len(result.Occurrences),
		Trend:       result.Trend,
		Project:     proj.Slug,
		Period:      learning.FormatPeriod(days),
	}, nil
}
