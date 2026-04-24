package collector

import (
	"strings"
	"testing"
)

// BenchmarkScore measures the hot path in Score — called for every RSS item.
func BenchmarkScore(b *testing.B) {
	b.ReportAllocs()

	title := "Building High-Performance Systems in Go with PostgreSQL"
	content := strings.Repeat("This covers goroutines, concurrency, and database patterns. ", 50)
	tags := []string{"golang", "postgresql", "performance"}
	keywords := []string{
		"go", "golang", "postgresql", "postgres", "pgx", "concurrency",
		"goroutine", "performance", "benchmark", "database", "sql",
	}

	for b.Loop() {
		Score(title, content, tags, keywords)
	}
}

// BenchmarkScore_ShortContent measures Score with minimal input (common case for TILs).
func BenchmarkScore_ShortContent(b *testing.B) {
	b.ReportAllocs()

	title := "Go tip"
	content := "Use defer."
	tags := []string{"go"}
	keywords := []string{"go", "tip"}

	for b.Loop() {
		Score(title, content, tags, keywords)
	}
}

// BenchmarkScore_NoMatch measures Score when no keywords match (zero-score fast path).
func BenchmarkScore_NoMatch(b *testing.B) {
	b.ReportAllocs()

	title := "Introduction to Rust"
	content := "Rust is a systems programming language."
	tags := []string{"rust"}
	keywords := []string{"go", "golang", "postgresql"}

	for b.Loop() {
		Score(title, content, tags, keywords)
	}
}

// BenchmarkNormalizeKeywords measures dedup + lowercase on a realistic keyword list.
func BenchmarkNormalizeKeywords(b *testing.B) {
	b.ReportAllocs()

	raw := []string{
		"Go", "go", "GO", "Golang", "golang",
		"PostgreSQL", "postgresql", "POSTGRESQL",
		"Kubernetes", "kubernetes",
		"Docker", "docker",
		"Performance", "performance",
		"Concurrency", "concurrency",
	}

	for b.Loop() {
		NormalizeKeywords(raw)
	}
}

// BenchmarkNormalizeURL and BenchmarkHashURL removed — the canonicaliser is
// now internal/url.Canonical / Hash, with benchmarks (if any) owned by that
// package. Collector no longer implements its own URL normalisation.

// BenchmarkDomainFromURL measures domain extraction — called per rate-limit Wait.
func BenchmarkDomainFromURL(b *testing.B) {
	b.ReportAllocs()

	url := "https://example.com/feed/atom.xml?format=rss"

	for b.Loop() {
		domainFromURL(url)
	}
}
