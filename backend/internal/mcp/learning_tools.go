package mcpserver

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/content"
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
	Tags    []tagCount `json:"tags"`
	Total   int        `json:"total"`
	Project string     `json:"project"`
	Period  string     `json:"period"`
}

type tagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
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

	counts := make(map[string]int)
	for _, e := range entries {
		for _, tag := range e.Tags {
			if input.TagPrefix != "" && !strings.HasPrefix(tag, input.TagPrefix) {
				continue
			}
			counts[tag]++
		}
	}

	tags := make([]tagCount, 0, len(counts))
	for tag, count := range counts {
		tags = append(tags, tagCount{Tag: tag, Count: count})
	}
	slices.SortFunc(tags, func(a, b tagCount) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c // descending by count
		}
		return cmp.Compare(a.Tag, b.Tag) // ascending by name
	})

	return nil, TagSummaryOutput{
		Tags:    tags,
		Total:   len(tags),
		Project: proj.Slug,
		Period:  fmt.Sprintf("%d days", days),
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
	Topics  []topicCoverage `json:"topics"`
	Total   int             `json:"total"`
	Project string          `json:"project"`
	Period  string          `json:"period"`
}

type topicCoverage struct {
	Topic           string         `json:"topic"`
	Count           int            `json:"count"`
	LastDate        string         `json:"last_date"`
	ResultBreakdown map[string]int `json:"result_breakdown"`
}

// topicTags are the tags that represent LeetCode topic patterns (not result/weakness/improvement/difficulty).
var topicTags = buildTopicTags()

func buildTopicTags() map[string]bool {
	topics := []string{
		"array", "string", "hash-table", "two-pointers", "sliding-window",
		"binary-search", "stack", "queue", "monotonic-stack", "linked-list",
		"tree", "binary-tree", "bst", "graph", "bfs", "dfs",
		"heap", "trie", "union-find", "dp", "greedy", "backtracking",
		"bit-manipulation", "math", "matrix", "interval", "topological-sort",
		"sorting", "simulation", "prefix-sum", "divide-and-conquer",
		"segment-tree", "design",
	}
	m := make(map[string]bool, len(topics))
	for _, t := range topics {
		m[t] = true
	}
	return m
}

var resultTags = map[string]bool{
	"ac-independent": true, "ac-with-hints": true, "ac-after-solution": true, "incomplete": true,
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

	type topicData struct {
		count    int
		lastDate time.Time
		results  map[string]int
	}

	data := make(map[string]*topicData)

	for _, e := range entries {
		// Extract result tag from this entry's tags.
		var result string
		for _, tag := range e.Tags {
			if resultTags[tag] {
				result = tag
				break
			}
		}

		// Count each topic tag.
		for _, tag := range e.Tags {
			if !topicTags[tag] {
				continue
			}
			td, ok := data[tag]
			if !ok {
				td = &topicData{results: make(map[string]int)}
				data[tag] = td
			}
			td.count++
			if e.CreatedAt.After(td.lastDate) {
				td.lastDate = e.CreatedAt
			}
			if result != "" {
				td.results[result]++
			}
		}
	}

	topics := make([]topicCoverage, 0, len(data))
	for topic, td := range data {
		topics = append(topics, topicCoverage{
			Topic:           topic,
			Count:           td.count,
			LastDate:        td.lastDate.Format(time.DateOnly),
			ResultBreakdown: td.results,
		})
	}
	slices.SortFunc(topics, func(a, b topicCoverage) int {
		return cmp.Compare(b.Count, a.Count) // descending by count
	})

	return nil, CoverageMatrixOutput{
		Topics:  topics,
		Total:   len(topics),
		Project: proj.Slug,
		Period:  fmt.Sprintf("%d days", days),
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
	Tag         string          `json:"tag"`
	Occurrences []weaknessPoint `json:"occurrences"`
	Total       int             `json:"total"`
	Trend       string          `json:"trend"` // improving, stable, declining
	Project     string          `json:"project"`
	Period      string          `json:"period"`
}

type weaknessPoint struct {
	Date   string `json:"date"`
	Result string `json:"result,omitempty"`
	Title  string `json:"title,omitempty"`
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

	var occurrences []weaknessPoint
	for _, e := range entries {
		hasTag := false
		var result string
		for _, tag := range e.Tags {
			if tag == input.Tag {
				hasTag = true
			}
			if resultTags[tag] {
				result = tag
			}
		}
		if !hasTag {
			continue
		}
		occurrences = append(occurrences, weaknessPoint{
			Date:   e.CreatedAt.Format(time.DateOnly),
			Result: result,
		})
	}

	// Reverse to chronological order (entries are DESC from DB).
	slices.Reverse(occurrences)

	trend := computeWeaknessTrend(occurrences)

	return nil, WeaknessTrendOutput{
		Tag:         input.Tag,
		Occurrences: occurrences,
		Total:       len(occurrences),
		Trend:       trend,
		Project:     proj.Slug,
		Period:      fmt.Sprintf("%d days", days),
	}, nil
}

// computeWeaknessTrend assesses improvement based on the last 5 results.
// "improving" = majority ac-independent; "declining" = majority ac-after-solution/incomplete.
func computeWeaknessTrend(points []weaknessPoint) string {
	if len(points) < 3 {
		return "insufficient-data"
	}

	// Look at last 5 (or all if fewer).
	window := points
	if len(window) > 5 {
		window = window[len(window)-5:]
	}

	good, bad := 0, 0
	for _, p := range window {
		switch p.Result {
		case "ac-independent":
			good++
		case "ac-after-solution", "incomplete":
			bad++
		case "ac-with-hints":
			// neutral
		}
	}

	switch {
	case good > bad+1:
		return "improving"
	case bad > good+1:
		return "declining"
	default:
		return "stable"
	}
}
