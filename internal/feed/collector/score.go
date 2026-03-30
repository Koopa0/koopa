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

// Score computes a relevance score (0-100) for a collected item based on
// keyword matches in title, content, and tags against tracking keywords.
// Core keywords (Go, PostgreSQL, system design, etc.) receive 2x weight,
// reflecting Koopa's positioning as a Go backend consultant.
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
	score := matchedWeight / totalWeight * 100
	if score > 100 {
		score = 100
	}
	return score
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
