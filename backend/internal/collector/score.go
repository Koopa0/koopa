package collector

import "strings"

// Score computes a relevance score (0-100) for a collected item based on
// keyword matches in title, content, and tags against tracking keywords.
// Uses case-insensitive substring matching. Returns 0 if keywords is empty.
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

	var matched int
	for _, kw := range keywords {
		if strings.Contains(haystack, kw) {
			matched++
		}
	}

	score := float32(matched) / float32(len(keywords)) * 100
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
