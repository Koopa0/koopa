// Copyright 2026 Koopa. All rights reserved.

package collector

import "strings"

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
