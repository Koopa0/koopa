package learning

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

// benchEntries returns n synthetic TagEntry values with a mix of topic tags.
func benchEntries(n int) []content.TagEntry {
	topics := []string{"dp", "graph", "two-pointers", "binary-search", "greedy"}
	results := []string{"ac-independent", "ac-with-hints", "ac-after-solution", "incomplete"}
	entries := make([]content.TagEntry, n)
	for i := range n {
		entries[i] = content.TagEntry{
			ID:        uuid.New(),
			Tags:      []string{topics[i%len(topics)], results[i%len(results)]},
			CreatedAt: time.Now().AddDate(0, 0, -(i % 365)),
		}
	}
	return entries
}

func BenchmarkCoverageMatrix(b *testing.B) {
	b.ReportAllocs()
	entries := benchEntries(500)
	for b.Loop() {
		CoverageMatrix(entries, 365)
	}
}

func BenchmarkTagSummary(b *testing.B) {
	b.ReportAllocs()
	entries := benchEntries(500)
	for b.Loop() {
		TagSummary(entries, "", 90)
	}
}

func BenchmarkTagSummary_WithPrefix(b *testing.B) {
	b.ReportAllocs()
	entries := benchEntries(500)
	for b.Loop() {
		TagSummary(entries, "weakness:", 90)
	}
}

func BenchmarkNormalizeTag(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		NormalizeTag("  Two Pointers  ")
	}
}

func BenchmarkWeaknessTrend(b *testing.B) {
	b.ReportAllocs()
	entries := benchRichEntries(200)
	for b.Loop() {
		WeaknessTrend(entries, "dp", 90)
	}
}

// benchRichEntries returns n synthetic RichTagEntry values for weakness trend benchmarks.
func benchRichEntries(n int) []content.RichTagEntry {
	topics := []string{"dp", "graph", "two-pointers", "binary-search", "greedy"}
	results := []string{"ac-independent", "ac-with-hints", "ac-after-solution", "incomplete"}
	entries := make([]content.RichTagEntry, n)
	for i := range n {
		entries[i] = content.RichTagEntry{
			ID:        uuid.New(),
			Slug:      "bench-slug",
			Title:     "bench title",
			Tags:      []string{topics[i%len(topics)], results[i%len(results)]},
			CreatedAt: time.Now().AddDate(0, 0, -(i % 365)),
		}
	}
	return entries
}
