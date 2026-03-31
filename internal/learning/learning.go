// Package learning provides learning analytics computation over content tag entries.
package learning

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

// TopicTags maps canonical LeetCode topic names (e.g. "dp", "two-pointers")
// to true. Used to classify tag entries by algorithmic topic.
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

// ResultTags maps canonical LeetCode result outcome tags (e.g. "ac-independent",
// "incomplete") to true. Used to classify problem-solving outcomes.
var ResultTags = map[string]bool{
	"ac-independent": true, "ac-with-hints": true, "ac-after-solution": true, "incomplete": true,
}

// CoverageMatrixResult is the topic × result breakdown.
type CoverageMatrixResult struct {
	Topics          []TopicCoverage `json:"topics"`
	TotalEntries    int             `json:"total_entries"`
	PatternsCovered int             `json:"patterns_covered"`
	PeriodDays      int             `json:"period_days"`
}

// TopicCoverage is a single topic's practice stats.
type TopicCoverage struct {
	Topic             string         `json:"topic"`
	Count             int            `json:"count"`
	LastDate          string         `json:"last_date"`
	Results           map[string]int `json:"results"`
	Difficulty        map[string]int `json:"difficulty,omitempty"`
	AvgConceptMastery *ConceptRatios `json:"avg_concept_mastery,omitempty"`
}

// ConceptRatios is the average concept mastery breakdown for a topic.
type ConceptRatios struct {
	IndependentRate float64 `json:"independent_rate"`
	GuidedRate      float64 `json:"guided_rate"`
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
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Topic, b.Topic) // stable tiebreaker: alphabetical
	})

	return CoverageMatrixResult{
		Topics:          topics,
		TotalEntries:    len(entries),
		PatternsCovered: len(topics),
		PeriodDays:      days,
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
	Date        string `json:"date"`
	Result      string `json:"result,omitempty"`
	Title       string `json:"title,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Observation string `json:"observation,omitempty"`
}

// WeaknessTrend computes time-series and trend for a specific tag
// using RichTagEntry which includes slug, title, and ai_metadata.
func WeaknessTrend(entries []content.RichTagEntry, tag string, days int) WeaknessTrendResult {
	occurrences := []WeaknessPoint{}
	for i := range entries {
		hasTag := false
		var result string
		for _, t := range entries[i].Tags {
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
			Date:        entries[i].CreatedAt.Format(time.DateOnly),
			Result:      result,
			Title:       entries[i].Title,
			Slug:        entries[i].Slug,
			Observation: extractObservation(entries[i].AIMetadata, tag),
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

// extractObservation returns the observation text for a specific weakness tag
// from ai_metadata.weakness_observations. Returns empty string when metadata
// is nil or the tag is not found.
func extractObservation(metadata json.RawMessage, tag string) string {
	if len(metadata) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &m); err != nil {
		return ""
	}
	raw, ok := m["weakness_observations"]
	if !ok {
		return ""
	}
	var observations []WeaknessObservation
	if err := json.Unmarshal(raw, &observations); err != nil {
		return ""
	}
	for _, obs := range observations {
		if obs.Tag == tag {
			return obs.Observation
		}
	}
	return ""
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
	count      int
	lastDate   time.Time
	results    map[string]int
	difficulty map[string]int
	// concept mastery counters (from ai_metadata.concept_breakdown)
	conceptIndependent int
	conceptGuided      int
	conceptTotal       int
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
				td = &coverageData{
					results:    make(map[string]int),
					difficulty: make(map[string]int),
				}
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

// CoverageMatrixRich computes topic × result matrix from rich tag entries,
// including difficulty distribution and concept mastery ratios.
func CoverageMatrixRich(entries []content.RichTagEntry, days int) CoverageMatrixResult {
	data := buildCoverageDataRich(entries)

	topics := make([]TopicCoverage, 0, len(data))
	for topic, td := range data {
		tc := TopicCoverage{
			Topic:      topic,
			Count:      td.count,
			LastDate:   td.lastDate.Format(time.DateOnly),
			Results:    td.results,
			Difficulty: td.difficulty,
		}
		if td.conceptTotal > 0 {
			tc.AvgConceptMastery = &ConceptRatios{
				IndependentRate: float64(td.conceptIndependent) / float64(td.conceptTotal),
				GuidedRate:      float64(td.conceptGuided) / float64(td.conceptTotal),
			}
		}
		topics = append(topics, tc)
	}
	slices.SortFunc(topics, func(a, b TopicCoverage) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Topic, b.Topic)
	})

	return CoverageMatrixResult{
		Topics:          topics,
		TotalEntries:    len(entries),
		PatternsCovered: len(topics),
		PeriodDays:      days,
	}
}

func buildCoverageDataRich(entries []content.RichTagEntry) map[string]*coverageData {
	data := make(map[string]*coverageData)
	for i := range entries {
		e := &entries[i]
		result := extractResultTag(e.Tags)
		concepts := parseConceptBreakdown(e.AIMetadata)
		difficulty := extractDifficultyTag(e.Tags)

		for _, tag := range e.Tags {
			if !TopicTags[tag] {
				continue
			}
			td := getOrCreateCoverage(data, tag)
			td.count++
			if e.CreatedAt.After(td.lastDate) {
				td.lastDate = e.CreatedAt
			}
			if result != "" {
				td.results[result]++
			}
			if difficulty != "" {
				td.difficulty[difficulty]++
			}
			addConceptCounts(td, concepts)
		}
	}
	return data
}

func getOrCreateCoverage(data map[string]*coverageData, key string) *coverageData {
	td, ok := data[key]
	if !ok {
		td = &coverageData{
			results:    make(map[string]int),
			difficulty: make(map[string]int),
		}
		data[key] = td
	}
	return td
}

func addConceptCounts(td *coverageData, concepts []ConceptBreakdownEntry) {
	for _, cb := range concepts {
		td.conceptTotal++
		switch cb.Mastery {
		case "independent", "independent_after_hint":
			td.conceptIndependent++
		case "guided", "told":
			td.conceptGuided++
		}
	}
}

func parseConceptBreakdown(metadata json.RawMessage) []ConceptBreakdownEntry {
	if len(metadata) == 0 {
		return nil
	}
	var m struct {
		ConceptBreakdown []ConceptBreakdownEntry `json:"concept_breakdown"`
	}
	if err := json.Unmarshal(metadata, &m); err != nil {
		return nil
	}
	return m.ConceptBreakdown
}

func extractDifficultyTag(tags []string) string {
	for _, t := range tags {
		if DifficultyTags[t] {
			return t
		}
	}
	return ""
}

func extractResultTag(tags []string) string {
	for _, tag := range tags {
		if ResultTags[tag] {
			return tag
		}
	}
	return ""
}
