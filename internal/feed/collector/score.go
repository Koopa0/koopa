// Copyright 2026 Koopa. All rights reserved.

// score.go owns the relevance-scoring heuristic for collected items.
// `coreKeywords` are high-weight topics for koopa's positioning —
// matches against those receive 2x weight. If the positioning
// shifts (e.g. a new focus area), update coreKeywords here, not in
// feed subscription config.

package collector

import "strings"

// coreKeywords are high-value topics for Koopa's positioning as a Go backend
// consultant specializing in PostgreSQL, high-concurrency systems, and IoT.
// Matches against these keywords receive a 2x weight boost.
var coreKeywords = map[string]bool{
	"go": true, "golang": true, "postgresql": true, "postgres": true,
	"pgx": true, "sqlc": true, "concurrency": true, "goroutine": true,
	"grpc": true, "system design": true, "database": true, "sql": true,
	"iot": true, "mqtt": true, "kubernetes": true, "docker": true,
	"performance": true, "benchmark": true, "observability": true,
	"genkit": true, "mcp": true, "claude": true, "llm": true,
}

// Score computes a relevance score (0-1) for a collected item based on
// keyword matches in title, content, and tags against tracking keywords.
// Core keywords (Go, PostgreSQL, system design, etc.) receive 2x weight,
// reflecting Koopa's positioning as a Go backend consultant. The range
// matches the relevance_score CHECK (BETWEEN 0 AND 1) and the >0.5
// relevance threshold documented on db/models.go.
func Score(title, content string, tags, keywords []string) float32 {
	if len(keywords) == 0 {
		return 0
	}

	// Build the haystack: title (weighted by repetition) + tags + content.
	// Title appears twice to give it higher weight.
	var b strings.Builder
	lower := strings.ToLower(title)
	b.WriteString(lower)
	b.WriteByte(' ')
	b.WriteString(lower) // double title weight
	b.WriteByte(' ')
	for _, t := range tags {
		b.WriteString(strings.ToLower(t))
		b.WriteByte(' ')
	}
	b.WriteString(strings.ToLower(content))
	haystack := b.String()

	var totalWeight, matchedWeight float32
	for _, kw := range keywords {
		weight := float32(1)
		if coreKeywords[kw] {
			weight = 2 // core keywords are worth double
		}
		totalWeight += weight
		if strings.Contains(haystack, kw) {
			matchedWeight += weight
		}
	}

	if totalWeight == 0 {
		return 0
	}
	// matchedWeight <= totalWeight by construction, so the ratio is in [0,1];
	// no upper cap is needed.
	return matchedWeight / totalWeight
}

// NormalizeKeywords deduplicates and lowercases a keyword list.
func NormalizeKeywords(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	result := make([]string, 0, len(raw))
	for _, kw := range raw {
		lower := strings.ToLower(strings.TrimSpace(kw))
		if lower == "" {
			continue
		}
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		result = append(result, lower)
	}
	return result
}
