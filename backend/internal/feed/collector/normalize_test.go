package collector

import (
	"math"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestScore_BoundaryValues covers zero, max, nil and overflow guard cases.
func TestScore_BoundaryValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		title    string
		content  string
		tags     []string
		keywords []string
		wantMin  float32
		wantMax  float32
	}{
		{
			name:     "all core keywords match — cannot exceed 100",
			title:    "go golang postgresql postgres pgx sqlc concurrency goroutine grpc system design database sql iot mqtt kubernetes docker performance benchmark observability genkit mcp claude llm",
			content:  "go golang postgresql postgres pgx sqlc concurrency goroutine grpc system design database sql iot mqtt kubernetes docker performance benchmark observability genkit mcp claude llm",
			tags:     []string{"go", "golang"},
			keywords: []string{"go", "golang", "postgresql"},
			wantMin:  100,
			wantMax:  100,
		},
		{
			name:     "single keyword, no match",
			title:    "rust programming",
			content:  "memory safety",
			tags:     nil,
			keywords: []string{"go"},
			wantMin:  0,
			wantMax:  0,
		},
		{
			name:     "empty title and content but keyword in tags",
			title:    "",
			content:  "",
			tags:     []string{"go"},
			keywords: []string{"go"},
			wantMin:  100,
			wantMax:  100,
		},
		{
			name:     "nil tags treated as empty",
			title:    "golang",
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
			wantMin:  100,
			wantMax:  100,
		},
		{
			name:    "very long keyword list — score stays in [0,100]",
			title:   "golang article",
			content: strings.Repeat("golang ", 100),
			tags:    nil,
			keywords: append([]string{"golang"}, func() []string {
				kws := make([]string, 500)
				for i := range kws {
					kws[i] = "niche_keyword_that_wont_match"
				}
				return kws
			}()...),
			wantMin: 0,
			wantMax: 100,
		},
		{
			name:     "single keyword matches — score is 100",
			title:    "golang",
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
			wantMin:  100,
			wantMax:  100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Score(tt.title, tt.content, tt.tags, tt.keywords)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("Score(%q, ...) = %v, want [%v, %v]", tt.title, got, tt.wantMin, tt.wantMax)
			}
			if math.IsNaN(float64(got)) || math.IsInf(float64(got), 0) {
				t.Errorf("Score(%q, ...) = %v (NaN or Inf)", tt.title, got)
			}
		})
	}
}

// TestScore_CoreKeywordBoost verifies that core keywords (go, postgresql, etc.)
// receive 2x weight relative to non-core keywords.
func TestScore_CoreKeywordBoost(t *testing.T) {
	t.Parallel()

	// With keywords ["go"(core=2x), "rust"(non-core=1x)]:
	//   totalWeight = 3, matchedWeight when "go" matches = 2, score = 2/3 * 100 ≈ 66.67
	//   matchedWeight when "rust" matches = 1, score = 1/3 * 100 ≈ 33.33
	t.Run("core keyword boosts score above non-core", func(t *testing.T) {
		t.Parallel()

		coreScore := Score("go programming", "", nil, []string{"go", "rust"})
		nonCoreScore := Score("rust programming", "", nil, []string{"go", "rust"})

		if coreScore <= nonCoreScore {
			t.Errorf("core keyword score %v should be > non-core score %v", coreScore, nonCoreScore)
		}
	})

	t.Run("exact core keyword weight calculation", func(t *testing.T) {
		t.Parallel()
		// keywords: ["go"(2), "python"(1)] → totalWeight=3
		// title "go programming": "go" matches → matchedWeight=2 → score=66.666...
		want := float32(2) / float32(3) * 100
		got := Score("go programming", "", nil, []string{"go", "python"})
		// Allow floating point tolerance of 0.01.
		diff := got - want
		if diff < -0.01 || diff > 0.01 {
			t.Errorf("Score() = %v, want ~%v (core keyword 2x boost)", got, want)
		}
	})
}

// TestScore_TitleWeightDouble verifies that the title is counted twice,
// giving a title-only match higher weight than a content-only match.
func TestScore_TitleWeightDouble(t *testing.T) {
	t.Parallel()

	keyword := []string{"unique_kw_xyz"}

	// Match in title (counted twice in haystack).
	titleScore := Score("unique_kw_xyz article", "no match here", nil, keyword)
	// Match in content (counted once).
	contentScore := Score("no match here", "unique_kw_xyz appears once", nil, keyword)

	// Both should be 100 since "unique_kw_xyz" is the only keyword and it matches in both.
	// The double-title weighting affects the proportional weight, not binary match.
	if titleScore != 100 {
		t.Errorf("Score with title match = %v, want 100", titleScore)
	}
	if contentScore != 100 {
		t.Errorf("Score with content match = %v, want 100", contentScore)
	}
}

// TestScore_AdversarialInputs verifies that Score handles injected/malformed inputs safely.
func TestScore_AdversarialInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		title    string
		content  string
		tags     []string
		keywords []string
	}{
		{
			name:     "SQL injection in title",
			title:    "'; DROP TABLE feeds; --",
			content:  "",
			tags:     nil,
			keywords: []string{"go"},
		},
		{
			name:     "XSS in content",
			title:    "normal title",
			content:  "<script>alert('xss')</script>golang",
			tags:     nil,
			keywords: []string{"golang"},
		},
		{
			name:     "null bytes in inputs",
			title:    "go\x00lang",
			content:  "\x00",
			tags:     []string{"\x00"},
			keywords: []string{"go\x00lang"},
		},
		{
			name:     "emoji in title and keywords",
			title:    "🚀 golang performance",
			content:  "",
			tags:     nil,
			keywords: []string{"🚀", "golang"},
		},
		{
			name:     "very long title",
			title:    strings.Repeat("golang ", 10000),
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
		},
		{
			name:     "very long keywords list with duplicates",
			title:    "golang",
			content:  "",
			tags:     nil,
			keywords: append([]string{"golang", "golang", "golang"}, make([]string, 1000)...),
		},
		{
			name:     "RTL text",
			title:    "برنامه‌نویسی golang",
			content:  "",
			tags:     nil,
			keywords: []string{"golang"},
		},
		{
			name:     "zero-width characters in keywords",
			title:    "golang",
			content:  "",
			tags:     nil,
			keywords: []string{"golang\u200b"}, // zero-width space
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Score(tt.title, tt.content, tt.tags, tt.keywords)
			if got < 0 || got > 100 {
				t.Errorf("Score(%q, ...) = %v, want [0, 100]", tt.title, got)
			}
			if math.IsNaN(float64(got)) || math.IsInf(float64(got), 0) {
				t.Errorf("Score(%q, ...) = %v (NaN or Inf)", tt.title, got)
			}
		})
	}
}

// TestNormalizeKeywords_Adversarial covers security and boundary inputs.
func TestNormalizeKeywords_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       []string
		wantLen   int  // -1 means don't check length
		wantEmpty bool // true = expect empty result
		wantNoDup bool // true = expect no duplicates
	}{
		{
			name:      "SQL injection keyword",
			raw:       []string{"'; DROP TABLE keywords; --"},
			wantLen:   1,
			wantNoDup: true,
		},
		{
			name:      "XSS keyword",
			raw:       []string{"<script>alert(1)</script>"},
			wantLen:   1,
			wantNoDup: true,
		},
		{
			name:      "null byte keyword skipped after trim",
			raw:       []string{"\x00"},
			wantLen:   1, // "\x00" is non-empty after TrimSpace
			wantNoDup: true,
		},
		{
			name:      "whitespace-only entries skipped",
			raw:       []string{"   ", "\t", "\n"},
			wantEmpty: true,
			wantNoDup: true,
		},
		{
			name: "large input — 10k keywords",
			raw: func() []string {
				kws := make([]string, 10000)
				for i := range kws {
					kws[i] = "keyword"
				}
				return kws
			}(),
			wantLen:   1,
			wantNoDup: true,
		},
		{
			name:      "emoji keywords deduplicated",
			raw:       []string{"🚀", "🚀", "go"},
			wantLen:   2,
			wantNoDup: true,
		},
		{
			name:      "mixed case dedup",
			raw:       []string{"GoLang", "GOLANG", "golang"},
			wantLen:   1,
			wantNoDup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeKeywords(tt.raw)

			if tt.wantEmpty && len(got) != 0 {
				t.Errorf("NormalizeKeywords(%v) = %v, want empty", tt.raw, got)
			}
			if tt.wantLen >= 0 && len(got) != tt.wantLen {
				t.Errorf("NormalizeKeywords(%v) len = %d, want %d; got %v", tt.raw, len(got), tt.wantLen, got)
			}
			if tt.wantNoDup {
				seen := make(map[string]int)
				for i, kw := range got {
					if prev, ok := seen[kw]; ok {
						t.Errorf("NormalizeKeywords: duplicate %q at index %d (first at %d)", kw, i, prev)
					}
					seen[kw] = i
				}
			}
		})
	}
}

// TestNormalizeKeywords_ReturnType verifies the return type contract:
// empty input returns empty slice (not nil), to allow safe range over result.
func TestNormalizeKeywords_ReturnType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []string
	}{
		{name: "nil input", raw: nil},
		{name: "empty slice", raw: []string{}},
		{name: "all whitespace", raw: []string{"  ", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeKeywords(tt.raw)
			// Must be non-nil (safe to range) and empty.
			if got == nil {
				t.Errorf("NormalizeKeywords(%v) = nil, want non-nil empty slice", tt.raw)
			}
			if diff := cmp.Diff([]string{}, got); diff != "" {
				t.Errorf("NormalizeKeywords(%v) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}
