package learning

import (
	"fmt"
	"strings"
)

// Controlled vocabulary for LeetCode/HackerRank learning session tags.
// Source of truth -- MCP tool description references this list.
// Only enforced when project is "leetcode" or "hackerrank".

// strictTagProjects are the projects that require strict tag validation.
var strictTagProjects = map[string]bool{
	"leetcode": true, "hackerrank": true,
}

// canonicalTags is the full set of allowed tags for strict-mode projects.
// 55 tags total, organized by category for maintainability.
var canonicalTags = buildCanonicalTags()

func buildCanonicalTags() map[string]bool {
	categories := map[string][]string{
		"topic": {
			"array", "string", "hash-table", "two-pointers", "sliding-window",
			"binary-search", "stack", "queue", "monotonic-stack", "linked-list",
			"tree", "binary-tree", "bst", "graph", "bfs", "dfs",
			"heap", "trie", "union-find", "dp", "greedy", "backtracking",
			"bit-manipulation", "math", "matrix", "interval", "topological-sort",
			"sorting", "simulation", "prefix-sum", "divide-and-conquer",
			"segment-tree", "design",
		},
		"difficulty": {"easy", "medium", "hard"},
		"result":     {"ac-independent", "ac-with-hints", "ac-after-solution", "incomplete"},
		"weakness": {
			"weakness:pattern-recognition", "weakness:approach-selection",
			"weakness:state-transition", "weakness:edge-cases",
			"weakness:complexity-analysis", "weakness:constraint-analysis",
			"weakness:implementation", "weakness:time-management",
			"weakness:loop-condition",
		},
		"improvement": {
			"improvement:pattern-recognition", "improvement:approach-selection",
			"improvement:state-transition", "improvement:edge-cases",
			"improvement:complexity-analysis", "improvement:constraint-analysis",
			"improvement:implementation", "improvement:loop-condition",
		},
		"platform": {"leetcode", "hackerrank"},
	}

	m := make(map[string]bool)
	for _, tags := range categories {
		for _, t := range tags {
			m[t] = true
		}
	}
	return m
}

// NormalizeTag converts a tag to canonical form: lowercase, spaces to hyphens.
func NormalizeTag(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	return strings.ReplaceAll(t, " ", "-")
}

// SessionInput holds the fields needed for learning session validation.
// Decoupled from MCP input types so this package has no MCP dependency.
type SessionInput struct {
	Project    string
	Topic      string
	Title      string
	Body       string
	Source     string
	Difficulty string
	Tags       []string
}

// ValidateInput checks required fields and normalizes optional fields.
// Returns validated tags on success.
func ValidateInput(input *SessionInput) ([]string, error) {
	if input.Project == "" {
		return nil, fmt.Errorf("project is required (use \"none\" for learning not associated with any project)")
	}
	if input.Topic == "" {
		return nil, fmt.Errorf("topic is required")
	}
	if input.Title == "" {
		return nil, fmt.Errorf("title is required")
	}
	if input.Body == "" {
		return nil, fmt.Errorf("body is required")
	}
	if input.Source == "" {
		input.Source = "discussion"
	}
	if input.Difficulty != "" {
		d := NormalizeTag(input.Difficulty)
		if d != "easy" && d != "medium" && d != "hard" {
			return nil, fmt.Errorf("invalid difficulty %q (must be easy, medium, or hard)", input.Difficulty)
		}
	}
	return ValidateTags(input.Tags, input.Source)
}

// ValidateTags normalizes and validates tags for learning sessions.
// When source is a strict-mode platform (leetcode, hackerrank), rejects unknown tags.
// For other sources, tags pass through with normalization only.
func ValidateTags(tags []string, source string) ([]string, error) {
	if len(tags) == 0 {
		return tags, nil
	}

	normalized := make([]string, len(tags))
	for i, raw := range tags {
		normalized[i] = NormalizeTag(raw)
	}

	// Only enforce strict validation for coding practice platforms
	if !strictTagProjects[strings.ToLower(source)] {
		return normalized, nil
	}

	var invalid []string
	for _, t := range normalized {
		if !canonicalTags[t] {
			invalid = append(invalid, t)
		}
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid tags for %s: %s. Use canonical tags only: "+
			"topic (array, dp, graph, ...), difficulty (easy/medium/hard), "+
			"result (ac-independent/ac-with-hints/ac-after-solution/incomplete), "+
			"weakness:xxx, improvement:xxx, platform (leetcode/hackerrank)",
			source, strings.Join(invalid, ", "))
	}

	return normalized, nil
}
