package collector

import (
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
			want:     100,
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
			want:     40, // go(2x) matched / total weight 5 (go=2+rust=1+java=1+python=1) = 40%
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
			want:     100,
		},
		{
			name:     "case insensitive matching",
			title:    "GOLANG Patterns",
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
			want:     100,
		},
		{
			name:     "tag match contributes to score",
			title:    "unrelated title",
			content:  "unrelated content",
			tags:     []string{"kubernetes"},
			keywords: []string{"kubernetes"},
			want:     100,
		},
		{
			name:     "substring matching works",
			title:    "microservices architecture",
			content:  "",
			tags:     nil,
			keywords: []string{"microservice"}, // substring of "microservices"
			want:     100,
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
		if score < 0 || score > 100 {
			t.Errorf("Score() = %v, want [0, 100]", score)
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
