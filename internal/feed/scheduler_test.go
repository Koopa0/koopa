// Copyright 2026 Koopa. All rights reserved.

package feed

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// ---------------------------------------------------------------------------
// FilterConfig.MatchURL
// ---------------------------------------------------------------------------

func TestFilterConfig_MatchURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config FilterConfig
		rawURL string
		want   bool
	}{
		{
			name:   "empty deny paths never matches",
			config: FilterConfig{},
			rawURL: "https://example.com/articles/foo",
			want:   false,
		},
		{
			name:   "exact prefix match",
			config: FilterConfig{DenyPaths: []string{"/sponsored"}},
			rawURL: "https://example.com/sponsored/article",
			want:   true,
		},
		{
			name:   "prefix match with trailing slash",
			config: FilterConfig{DenyPaths: []string{"/ads/"}},
			rawURL: "https://example.com/ads/banner",
			want:   true,
		},
		{
			name:   "prefix does not match different path",
			config: FilterConfig{DenyPaths: []string{"/sponsored"}},
			rawURL: "https://example.com/articles/go",
			want:   false,
		},
		{
			name:   "multiple deny paths first matches",
			config: FilterConfig{DenyPaths: []string{"/a", "/b"}},
			rawURL: "https://example.com/a/something",
			want:   true,
		},
		{
			name:   "multiple deny paths second matches",
			config: FilterConfig{DenyPaths: []string{"/a", "/b"}},
			rawURL: "https://example.com/b/something",
			want:   true,
		},
		{
			name:   "multiple deny paths none match",
			config: FilterConfig{DenyPaths: []string{"/a", "/b"}},
			rawURL: "https://example.com/c/something",
			want:   false,
		},
		{
			name:   "invalid URL returns false",
			config: FilterConfig{DenyPaths: []string{"/x"}},
			rawURL: "://invalid",
			want:   false,
		},
		{
			name:   "empty URL returns false",
			config: FilterConfig{DenyPaths: []string{"/x"}},
			rawURL: "",
			want:   false,
		},
		{
			name:   "root path matches slash prefix",
			config: FilterConfig{DenyPaths: []string{"/"}},
			rawURL: "https://example.com/anything",
			want:   true,
		},
		{
			name:   "path traversal in URL does not panic",
			config: FilterConfig{DenyPaths: []string{"/safe"}},
			rawURL: "https://example.com/../../etc/passwd",
			want:   false,
		},
		{
			name:   "URL without path",
			config: FilterConfig{DenyPaths: []string{"/articles"}},
			rawURL: "https://example.com",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.MatchURL(tt.rawURL)
			if got != tt.want {
				t.Errorf("FilterConfig.MatchURL(%q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterConfig.MatchTitle
// ---------------------------------------------------------------------------

func TestFilterConfig_MatchTitle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config FilterConfig
		title  string
		want   bool
	}{
		{
			name:   "empty patterns never matches",
			config: FilterConfig{},
			title:  "Sponsored content here",
			want:   false,
		},
		{
			name:   "case-insensitive pattern match",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored"}},
			title:  "SPONSORED: Buy this product",
			want:   true,
		},
		{
			name:   "case-sensitive regex does not match different case",
			config: FilterConfig{DenyTitlePatterns: []string{"sponsored"}},
			title:  "SPONSORED content",
			want:   false,
		},
		{
			// A malformed regexp is skipped, NOT reinterpreted as a substring, so
			// a title containing the literal pattern text is NOT filtered.
			name:   "invalid regex is skipped not substring-matched",
			config: FilterConfig{DenyTitlePatterns: []string{"[invalid regex"}},
			title:  "[Invalid Regex match",
			want:   false,
		},
		{
			// A malformed sibling pattern must not suppress a valid one.
			name:   "valid pattern still matches alongside an invalid sibling",
			config: FilterConfig{DenyTitlePatterns: []string{"[invalid regex", "(?i)sponsored"}},
			title:  "A Sponsored item",
			want:   true,
		},
		{
			name:   "empty title never matches non-empty pattern",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad"}},
			title:  "",
			want:   false,
		},
		{
			name:   "multiple patterns first matches",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad", "(?i)promo"}},
			title:  "Big AD sale",
			want:   true,
		},
		{
			name:   "multiple patterns second matches",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad", "(?i)promo"}},
			title:  "PROMO event",
			want:   true,
		},
		{
			name:   "multiple patterns none match",
			config: FilterConfig{DenyTitlePatterns: []string{"(?i)ad", "(?i)promo"}},
			title:  "Deep dive into Go generics",
			want:   false,
		},
		{
			name:   "regex with anchors",
			config: FilterConfig{DenyTitlePatterns: []string{"^Sponsored"}},
			title:  "Sponsored content",
			want:   true,
		},
		{
			name:   "regex with anchors does not match middle",
			config: FilterConfig{DenyTitlePatterns: []string{"^Sponsored"}},
			title:  "Not Sponsored content",
			want:   false,
		},
		{
			name:   "unicode title matches pattern",
			config: FilterConfig{DenyTitlePatterns: []string{"廣告"}},
			title:  "今日廣告特價",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.MatchTitle(tt.title)
			if got != tt.want {
				t.Errorf("FilterConfig.MatchTitle(%q) = %v, want %v", tt.title, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterConfig.MatchTags
// ---------------------------------------------------------------------------

func TestFilterConfig_MatchTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config FilterConfig
		tags   []string
		want   bool
	}{
		{
			name:   "no allow or deny rules, never matches",
			config: FilterConfig{},
			tags:   []string{"go", "backend"},
			want:   false,
		},
		{
			name:   "allow list with matching tag passes",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   []string{"go", "rust"},
			want:   false, // has allowed tag, should NOT skip
		},
		{
			name:   "allow list without matching tag skips",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   []string{"python", "ruby"},
			want:   true,
		},
		{
			name:   "allow list with empty item tags skips",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   []string{},
			want:   true,
		},
		{
			name:   "allow list with nil item tags skips",
			config: FilterConfig{AllowTags: []string{"go"}},
			tags:   nil,
			want:   true,
		},
		{
			name:   "deny list with matching tag skips",
			config: FilterConfig{DenyTags: []string{"sponsored"}},
			tags:   []string{"sponsored", "go"},
			want:   true,
		},
		{
			name:   "deny list without matching tag passes",
			config: FilterConfig{DenyTags: []string{"sponsored"}},
			tags:   []string{"go", "backend"},
			want:   false,
		},
		{
			name:   "tag matching is case-insensitive",
			config: FilterConfig{AllowTags: []string{"Go"}},
			tags:   []string{"go"},
			want:   false, // case-insensitive match found — should NOT skip
		},
		{
			name:   "deny tag case-insensitive match",
			config: FilterConfig{DenyTags: []string{"SPAM"}},
			tags:   []string{"spam"},
			want:   true,
		},
		{
			name:   "allow and deny: deny wins when both match",
			config: FilterConfig{AllowTags: []string{"go"}, DenyTags: []string{"sponsored"}},
			tags:   []string{"go", "sponsored"},
			want:   true, // deny takes precedence (deny checked after allow)
		},
		{
			name:   "allow and deny: only allow matches",
			config: FilterConfig{AllowTags: []string{"go"}, DenyTags: []string{"sponsored"}},
			tags:   []string{"go"},
			want:   false,
		},
		{
			name:   "empty deny list does not skip",
			config: FilterConfig{DenyTags: []string{}},
			tags:   []string{"anything"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.MatchTags(tt.tags)
			if got != tt.want {
				t.Errorf("FilterConfig.MatchTags(%v) = %v, want %v", tt.tags, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterConfig.Skip (combined)
// ---------------------------------------------------------------------------

func TestFilterConfig_Skip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  FilterConfig
		itemURL string
		title   string
		tags    []string
		want    bool
	}{
		{
			name:    "empty config never skips",
			config:  FilterConfig{},
			itemURL: "https://example.com/article",
			title:   "Great article",
			tags:    []string{"go"},
			want:    false,
		},
		{
			name:    "URL match skips regardless of title and tags",
			config:  FilterConfig{DenyPaths: []string{"/ads"}},
			itemURL: "https://example.com/ads/banner",
			title:   "Normal title",
			tags:    []string{"go"},
			want:    true,
		},
		{
			name:    "title match skips when URL ok",
			config:  FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored"}},
			itemURL: "https://example.com/article",
			title:   "Sponsored article",
			tags:    []string{"go"},
			want:    true,
		},
		{
			name:    "tag match skips when URL and title ok",
			config:  FilterConfig{DenyTags: []string{"spam"}},
			itemURL: "https://example.com/article",
			title:   "Normal article",
			tags:    []string{"spam"},
			want:    true,
		},
		{
			name: "all filters together: only URL triggers",
			config: FilterConfig{
				DenyPaths:         []string{"/deny"},
				DenyTitlePatterns: []string{"(?i)nope"},
				DenyTags:          []string{"bad"},
			},
			itemURL: "https://example.com/deny/path",
			title:   "Normal",
			tags:    []string{"good"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.config.Skip(tt.itemURL, tt.title, tt.tags)
			if got != tt.want {
				t.Errorf("FilterConfig.Skip(%q, %q, %v) = %v, want %v",
					tt.itemURL, tt.title, tt.tags, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseFilterConfig
// ---------------------------------------------------------------------------

func TestParseFilterConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want FilterConfig
	}{
		{
			name: "empty bytes returns zero value",
			raw:  ``,
			want: FilterConfig{},
		},
		{
			name: "empty object returns zero value",
			raw:  `{}`,
			want: FilterConfig{},
		},
		{
			name: "valid deny_paths",
			raw:  `{"deny_paths":["/ads","/sponsored"]}`,
			want: FilterConfig{DenyPaths: []string{"/ads", "/sponsored"}},
		},
		{
			name: "valid deny_title_patterns",
			raw:  `{"deny_title_patterns":["(?i)sponsored"]}`,
			want: FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored"}},
		},
		{
			name: "valid allow_tags and deny_tags",
			raw:  `{"allow_tags":["go","rust"],"deny_tags":["spam"]}`,
			want: FilterConfig{AllowTags: []string{"go", "rust"}, DenyTags: []string{"spam"}},
		},
		{
			name: "invalid JSON returns zero value",
			raw:  `{invalid json`,
			want: FilterConfig{},
		},
		{
			name: "null returns zero value",
			raw:  `null`,
			want: FilterConfig{},
		},
		{
			name: "all fields",
			raw:  `{"deny_paths":["/x"],"deny_title_patterns":["ad"],"allow_tags":["go"],"deny_tags":["spam"]}`,
			want: FilterConfig{
				DenyPaths:         []string{"/x"},
				DenyTitlePatterns: []string{"ad"},
				AllowTags:         []string{"go"},
				DenyTags:          []string{"spam"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseFilterConfig(json.RawMessage(tt.raw))
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseFilterConfig(%q) mismatch (-want +got):\n%s", tt.raw, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidSchedule additional adversarial cases
// ---------------------------------------------------------------------------

func TestValidSchedule_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "leading whitespace", input: " hourly", want: false},
		{name: "trailing whitespace", input: "daily ", want: false},
		{name: "tab in middle", input: "dai\tly", want: false},
		{name: "unicode lookalike", input: "dаily", want: false}, // Cyrillic 'а'
		{name: "null byte", input: "daily\x00", want: false},
		{name: "SQL injection", input: "daily'; DROP TABLE feeds;--", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ValidSchedule(tt.input)
			if got != tt.want {
				t.Errorf("ValidSchedule(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// due — scheduler skip-vs-fetch decision (pure)
// ---------------------------------------------------------------------------

// TestDue exercises the scheduler's per-feed skip-vs-fetch predicate
// (scheduler.go::due, called from fetchSchedule). The decision is a pure
// function of (lastFetched, now, interval): a never-fetched feed is always due;
// a fetched feed is due once its age reaches the interval, with the boundary
// inclusive. Expected values are hand-computed against a fixed `now`.
//
// Mutation it catches: flipping the comparison to `>` (excluding the exact
// boundary) breaks "exactly interval ago" → due; dropping the nil guard panics
// on a never-fetched feed; using `<=` instead of `<` in the original inline
// skip check would make "exactly interval ago" skip — each surfaces here.
func TestDue(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	const interval = time.Hour

	ago := func(d time.Duration) *time.Time {
		ts := now.Add(-d)
		return &ts
	}

	tests := []struct {
		name        string
		lastFetched *time.Time
		want        bool
	}{
		{name: "never fetched is due", lastFetched: nil, want: true},
		{name: "fetched 30m ago, 1h interval — not due", lastFetched: ago(30 * time.Minute), want: false},
		{name: "fetched 59m59s ago — not due (just under interval)", lastFetched: ago(59*time.Minute + 59*time.Second), want: false},
		{name: "fetched exactly 1h ago — due (inclusive boundary)", lastFetched: ago(interval), want: true},
		{name: "fetched 2h ago — due (well past interval)", lastFetched: ago(2 * time.Hour), want: true},
		{name: "future last-fetched — not due (negative age)", lastFetched: ago(-time.Minute), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := due(tt.lastFetched, now, interval)
			if got != tt.want {
				t.Errorf("due(%v, now, %v) = %v, want %v", tt.lastFetched, interval, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fuzz tests
// ---------------------------------------------------------------------------

func FuzzFilterConfig_MatchURL(f *testing.F) {
	f.Add("")
	f.Add("https://example.com/articles/foo")
	f.Add("https://example.com/sponsored/article")
	f.Add("://invalid")
	f.Add("https://example.com/../../etc/passwd")
	f.Add("\x00null\x00byte")
	f.Add("not-a-url")

	fc := FilterConfig{DenyPaths: []string{"/sponsored", "/ads"}}
	f.Fuzz(func(t *testing.T, rawURL string) {
		_ = fc.MatchURL(rawURL) // must not panic
	})
}

func FuzzFilterConfig_MatchTitle(f *testing.F) {
	f.Add("")
	f.Add("Normal article title")
	f.Add("Sponsored content here")
	f.Add("<script>alert(1)</script>")
	f.Add("\x00\x01\x02")
	f.Add("Unicode: 日本語タイトル")

	fc := FilterConfig{DenyTitlePatterns: []string{"(?i)sponsored", "(?i)ad"}}
	f.Fuzz(func(t *testing.T, title string) {
		_ = fc.MatchTitle(title) // must not panic
	})
}

func FuzzFilterConfig_MatchTags(f *testing.F) {
	f.Add("")
	f.Add("go")
	f.Add("Go")
	f.Add("<script>")
	f.Add("\x00")

	fc := FilterConfig{AllowTags: []string{"go", "rust"}, DenyTags: []string{"spam"}}
	f.Fuzz(func(t *testing.T, tag string) {
		_ = fc.MatchTags([]string{tag}) // must not panic
	})
}

func FuzzParseFilterConfig(f *testing.F) {
	f.Add(``)
	f.Add(`{}`)
	f.Add(`{"deny_paths":["/ads"]}`)
	f.Add(`{not valid json`)
	f.Add(`null`)
	f.Add(`{"deny_paths":null}`)
	f.Add(`{"deny_title_patterns":["(?i)sponsored"]}`)

	f.Fuzz(func(t *testing.T, raw string) {
		_ = ParseFilterConfig(json.RawMessage(raw)) // must not panic
	})
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkFilterConfig_Skip(b *testing.B) {
	b.ReportAllocs()

	fc := FilterConfig{
		DenyPaths:         []string{"/ads", "/sponsored", "/promo"},
		DenyTitlePatterns: []string{"(?i)sponsored", "(?i)advertisement"},
		DenyTags:          []string{"spam", "promo"},
	}

	for b.Loop() {
		_ = fc.Skip("https://example.com/articles/go-performance", "Deep dive into Go performance", []string{"go", "performance"})
	}
}

func BenchmarkFilterConfig_MatchURL(b *testing.B) {
	b.ReportAllocs()

	fc := FilterConfig{DenyPaths: []string{"/ads", "/sponsored", "/promo", "/native"}}

	for b.Loop() {
		_ = fc.MatchURL("https://example.com/articles/go-performance")
	}
}

func BenchmarkParseFilterConfig(b *testing.B) {
	b.ReportAllocs()

	raw := json.RawMessage(`{"deny_paths":["/ads","/sponsored"],"deny_title_patterns":["(?i)sponsored"],"deny_tags":["spam"]}`)

	for b.Loop() {
		_ = ParseFilterConfig(raw)
	}
}
