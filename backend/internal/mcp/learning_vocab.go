package mcpserver

import (
	"fmt"
	"strings"
)

// Controlled vocabulary for learning session tags.
// Source of truth for tag validation — MCP tool descriptions reference this list.

// learningTopicTags are the allowed topic tags for learning sessions (LeetCode, etc.).
var learningTopicTags = map[string]bool{
	"array": true, "string": true, "hash-table": true,
	"two-pointers": true, "sliding-window": true, "binary-search": true,
	"stack": true, "queue": true, "monotonic-stack": true, "monotonic-queue": true,
	"linked-list": true, "tree": true, "binary-tree": true, "bst": true,
	"graph": true, "bfs": true, "dfs": true,
	"heap": true, "trie": true, "union-find": true,
	"dp": true, "greedy": true, "backtracking": true,
	"bit-manipulation": true, "math": true, "matrix": true, "interval": true,
	"topological-sort": true, "sorting": true, "design": true, "simulation": true,
	"prefix-sum": true, "divide-and-conquer": true,
	"segment-tree": true, "binary-indexed-tree": true,
}

// learningDifficulties are the allowed difficulty values.
var learningDifficulties = map[string]bool{
	"easy": true, "medium": true, "hard": true,
}

// learningResultTags are the allowed result tags.
var learningResultTags = map[string]bool{
	"ac-independent": true, "ac-with-hints": true,
	"ac-after-solution": true, "incomplete": true,
}

// learningPrefixes are tag prefixes that accept any suffix (e.g. weakness:state-transition).
var learningPrefixes = []string{
	"weakness:", "improvement:",
}

// normalizeTag converts a tag to canonical form: lowercase, spaces to hyphens.
func normalizeTag(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	return strings.ReplaceAll(t, " ", "-")
}

// validateLearningTags normalizes and validates tags against the controlled vocabulary.
// Returns normalized tags and an error listing any invalid tags.
func validateLearningTags(tags []string) ([]string, error) {
	if len(tags) == 0 {
		return tags, nil
	}

	normalized := make([]string, len(tags))
	var invalid []string

	for i, raw := range tags {
		t := normalizeTag(raw)
		normalized[i] = t

		if isValidLearningTag(t) {
			continue
		}
		invalid = append(invalid, t)
	}

	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid tags: %s. Allowed: topic tags (array, dp, graph, ...), "+
			"result (ac-independent, ac-with-hints, ac-after-solution, incomplete), "+
			"weakness:xxx, improvement:xxx", strings.Join(invalid, ", "))
	}

	return normalized, nil
}

// isValidLearningTag checks if a tag is in the controlled vocabulary.
func isValidLearningTag(t string) bool {
	if learningTopicTags[t] || learningDifficulties[t] || learningResultTags[t] {
		return true
	}
	for _, prefix := range learningPrefixes {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}
