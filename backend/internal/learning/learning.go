// Package learning provides learning analytics computation over content tag entries.
package learning

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/koopa0/blog-backend/internal/content"
)

// TopicTags are the canonical LeetCode topic patterns.
var TopicTags = buildTopicTags()

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

// ResultTags are the canonical result outcome tags.
var ResultTags = map[string]bool{
	"ac-independent": true, "ac-with-hints": true, "ac-after-solution": true, "incomplete": true,
}

// CoverageMatrixResult is the topic × result breakdown.
type CoverageMatrixResult struct {
	Topics       []TopicCoverage `json:"topics"`
	TotalEntries int             `json:"total_entries"`
	PeriodDays   int             `json:"period_days"`
}

// TopicCoverage is a single topic's practice stats.
type TopicCoverage struct {
	Topic    string         `json:"topic"`
	Count    int            `json:"count"`
	LastDate string         `json:"last_date"`
	Results  map[string]int `json:"results"`
}

// CoverageMatrix computes topic × result matrix from tag entries.
func CoverageMatrix(entries []content.TagEntry, days int) CoverageMatrixResult {
	data := buildCoverageData(entries)

	topics := make([]TopicCoverage, 0, len(data))
	for topic, td := range data {
		topics = append(topics, TopicCoverage{
			Topic:    topic,
			Count:    td.count,
			LastDate: td.lastDate.Format(time.DateOnly),
			Results:  td.results,
		})
	}
	slices.SortFunc(topics, func(a, b TopicCoverage) int {
		return cmp.Compare(b.Count, a.Count)
	})

	return CoverageMatrixResult{
		Topics:       topics,
		TotalEntries: len(entries),
		PeriodDays:   days,
	}
}

// TagSummaryResult is tag frequency stats.
type TagSummaryResult struct {
	Tags       []TagCount `json:"tags"`
	TotalTags  int        `json:"total_tags"`
	PeriodDays int        `json:"period_days"`
}

// TagCount is a single tag's frequency.
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// TagSummary computes tag frequency from entries, optionally filtered by prefix.
func TagSummary(entries []content.TagEntry, tagPrefix string, days int) TagSummaryResult {
	counts := make(map[string]int)
	for _, e := range entries {
		for _, tag := range e.Tags {
			if tagPrefix != "" && !strings.HasPrefix(tag, tagPrefix) {
				continue
			}
			counts[tag]++
		}
	}

	tags := make([]TagCount, 0, len(counts))
	for tag, count := range counts {
		tags = append(tags, TagCount{Tag: tag, Count: count})
	}
	slices.SortFunc(tags, func(a, b TagCount) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Tag, b.Tag)
	})

	return TagSummaryResult{
		Tags:       tags,
		TotalTags:  len(tags),
		PeriodDays: days,
	}
}

// WeaknessTrendResult is a time-series for a weakness tag.
type WeaknessTrendResult struct {
	Tag         string          `json:"tag"`
	Occurrences []WeaknessPoint `json:"occurrences"`
	Trend       string          `json:"trend"`
	PeriodDays  int             `json:"period_days"`
}

// WeaknessPoint is a single occurrence of a weakness tag.
type WeaknessPoint struct {
	Date   string `json:"date"`
	Result string `json:"result,omitempty"`
	Title  string `json:"title,omitempty"`
}

// WeaknessTrend computes time-series and trend for a specific tag.
func WeaknessTrend(entries []content.TagEntry, tag string, days int) WeaknessTrendResult {
	var occurrences []WeaknessPoint
	for _, e := range entries {
		hasTag := false
		var result string
		for _, t := range e.Tags {
			if t == tag {
				hasTag = true
			}
			if ResultTags[t] {
				result = t
			}
		}
		if !hasTag {
			continue
		}
		occurrences = append(occurrences, WeaknessPoint{
			Date:   e.CreatedAt.Format(time.DateOnly),
			Result: result,
		})
	}

	// Reverse to chronological order (entries are DESC from DB).
	slices.Reverse(occurrences)

	return WeaknessTrendResult{
		Tag:         tag,
		Occurrences: occurrences,
		Trend:       computeTrend(occurrences),
		PeriodDays:  days,
	}
}

// computeTrend assesses improvement based on the last 5 results.
func computeTrend(points []WeaknessPoint) string {
	if len(points) < 3 {
		return "insufficient-data"
	}

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

type coverageData struct {
	count    int
	lastDate time.Time
	results  map[string]int
}

func buildCoverageData(entries []content.TagEntry) map[string]*coverageData {
	data := make(map[string]*coverageData)
	for _, e := range entries {
		result := extractResultTag(e.Tags)
		for _, tag := range e.Tags {
			if !TopicTags[tag] {
				continue
			}
			td, ok := data[tag]
			if !ok {
				td = &coverageData{results: make(map[string]int)}
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
	return data
}

func extractResultTag(tags []string) string {
	for _, tag := range tags {
		if ResultTags[tag] {
			return tag
		}
	}
	return ""
}

// Clamp constrains val to [minVal, maxVal], using defaultVal if val is 0.
func Clamp(val, minVal, maxVal, defaultVal int) int {
	if val == 0 {
		return defaultVal
	}
	return max(minVal, min(val, maxVal))
}

// FormatPeriod returns a human-readable period string.
func FormatPeriod(days int) string {
	return fmt.Sprintf("%d days", days)
}
