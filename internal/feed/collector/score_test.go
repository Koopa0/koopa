// Copyright 2026 Koopa. All rights reserved.

package collector

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		title    string
		content  string
		tags     []string
		keywords []string
		want     float32
	}{
		{
			name:     "all keywords match",
			title:    "Building a REST API in Go",
			content:  "This article covers HTTP handlers and routing patterns.",
			tags:     []string{"golang", "rest"},
			keywords: []string{"go", "rest", "api"},
			want:     1,
		},
		{
			name:     "no keywords match",
			title:    "Introduction to Python",
			content:  "Python is a programming language.",
			tags:     []string{"python"},
			keywords: []string{"rust", "wasm"},
			want:     0,
		},
		{
			name:     "partial match gives proportional score with core keyword boost",
			title:    "Go concurrency",
			content:  "Goroutines and channels.",
			tags:     nil,
			keywords: []string{"go", "rust", "java", "python"},
			want:     0.4, // go(2x) matched / total weight 5 (go=2+rust=1+java=1+python=1) = 0.4
		},
		{
			name:     "empty keywords returns zero",
			title:    "anything",
			content:  "anything",
			tags:     nil,
			keywords: nil,
			want:     0,
		},
		{
			name:     "empty content still matches title",
			title:    "golang patterns",
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
			want:     1,
		},
		{
			name:     "case insensitive matching",
			title:    "GOLANG Patterns",
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
			want:     1,
		},
		{
			name:     "tag match contributes to score",
			title:    "unrelated title",
			content:  "unrelated content",
			tags:     []string{"kubernetes"},
			keywords: []string{"kubernetes"},
			want:     1,
		},
		{
			name:     "substring matching works",
			title:    "microservices architecture",
			content:  "",
			tags:     nil,
			keywords: []string{"microservice"}, // substring of "microservices"
			want:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Score(tt.title, tt.content, tt.tags, tt.keywords)
			if got != tt.want {
				t.Errorf("Score(%q, ..., %v) = %v, want %v", tt.title, tt.keywords, got, tt.want)
			}
		})
	}
}

// TestScore_RescaledRange pins the [0,1] contract after the 0-100 → 0-1
// rescale: a full single-keyword match is exactly 1.0, and any input with at
// least one match stays <= 1.0 (the relevance_score CHECK is BETWEEN 0 AND 1).
func TestScore_RescaledRange(t *testing.T) {
	t.Parallel()

	if got := Score("golang", "", nil, []string{"golang"}); got != 1 {
		t.Errorf("Score full single-keyword match = %v, want exactly 1.0", got)
	}

	matched := []struct {
		name     string
		title    string
		content  string
		tags     []string
		keywords []string
	}{
		{name: "single core match", title: "go", content: "", tags: nil, keywords: []string{"go"}},
		{name: "core + non-core both match", title: "go rust", content: "", tags: nil, keywords: []string{"go", "rust"}},
		{name: "partial match", title: "go", content: "", tags: nil, keywords: []string{"go", "python", "java"}},
		{name: "tag-only match", title: "x", content: "y", tags: []string{"kubernetes"}, keywords: []string{"kubernetes"}},
	}
	for _, tt := range matched {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Score(tt.title, tt.content, tt.tags, tt.keywords)
			if got <= 0 || got > 1 {
				t.Errorf("Score(%q, ...) = %v, want (0, 1]", tt.title, got)
			}
		})
	}
}

func TestNormalizeKeywords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{
			name: "dedup and lowercase",
			raw:  []string{"Go", "go", "GO"},
			want: []string{"go"},
		},
		{
			name: "trim whitespace",
			raw:  []string{"  golang  ", "rust"},
			want: []string{"golang", "rust"},
		},
		{
			name: "skip empty strings",
			raw:  []string{"", "  ", "valid"},
			want: []string{"valid"},
		},
		{
			name: "nil input",
			raw:  nil,
			want: []string{},
		},
		{
			name: "preserves order of first occurrence",
			raw:  []string{"b", "a", "B"},
			want: []string{"b", "a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeKeywords(tt.raw)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("NormalizeKeywords(%v) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}

func FuzzScore(f *testing.F) {
	f.Add("title", "content", "tag1", "keyword1")
	f.Add("", "", "", "")
	f.Add("UPPER", "lower", "MiXeD", "keyword")

	f.Fuzz(func(t *testing.T, title, content, tag, keyword string) {
		score := Score(title, content, []string{tag}, []string{keyword})
		if score < 0 || score > 1 {
			t.Errorf("Score() = %v, want [0, 1]", score)
		}
	})
}

func FuzzNormalizeKeywords(f *testing.F) {
	f.Add("go", "rust", "python")
	f.Add("", "  ", "valid")

	f.Fuzz(func(t *testing.T, a, b, c string) {
		result := NormalizeKeywords([]string{a, b, c})
		// Must not panic, result must have no duplicates
		seen := make(map[string]struct{})
		for _, kw := range result {
			if kw == "" {
				t.Error("NormalizeKeywords returned empty string")
			}
			if _, ok := seen[kw]; ok {
				t.Errorf("NormalizeKeywords returned duplicate: %q", kw)
			}
			seen[kw] = struct{}{}
		}
	})
}

// Benchmarks for Score / NormalizeKeywords (consolidated from bench_test.go).
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
