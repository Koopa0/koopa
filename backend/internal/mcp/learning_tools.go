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

	entries, err := s.contents.TagEntries(ctx, content.TypeTIL, &proj.ID, since)
	if err != nil {
		return nil, learning.WeaknessTrendResult{}, fmt.Errorf("querying tag entries: %w", err)
	}

	return nil, learning.WeaknessTrend(entries, input.Tag, days), nil
}
