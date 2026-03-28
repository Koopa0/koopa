package mcpserver

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
)

// --- slugify ---

func TestSlugify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple ascii lowercase",
			input: "hello world",
			want:  "hello-world",
		},
		{
			name:  "mixed case",
			input: "Hello World",
			want:  "hello-world",
		},
		{
			name:  "all uppercase",
			input: "GO PROGRAMMING",
			want:  "go-programming",
		},
		{
			name:  "leading and trailing spaces",
			input: "  hello world  ",
			want:  "hello-world",
		},
		{
			name:  "special characters stripped",
			input: "hello! world@ #test",
			want:  "hello-world-test",
		},
		{
			name:  "consecutive spaces become single hyphen",
			input: "hello   world",
			want:  "hello-world",
		},
		{
			name:  "consecutive hyphens collapsed",
			input: "hello--world",
			want:  "hello-world",
		},
		{
			name:  "leading hyphens stripped",
			input: "---hello",
			want:  "hello",
		},
		{
			name:  "trailing hyphens stripped",
			input: "hello---",
			want:  "hello",
		},
		{
			name:  "only hyphens returns empty",
			input: "---",
			want:  "",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "CJK characters stripped (not alphanumeric)",
			input: "你好世界",
			want:  "",
		},
		{
			name:  "mixed CJK and ascii",
			input: "Hello 你好 World",
			want:  "hello-world",
		},
		{
			name:  "numbers preserved",
			input: "Go 1.22 Release Notes",
			want:  "go-122-release-notes",
		},
		{
			name:  "hyphens in source preserved as single",
			input: "build-log entry",
			want:  "build-log-entry",
		},
		{
			name:  "truncates to 80 characters",
			input: strings.Repeat("a", 100),
			want:  strings.Repeat("a", 80),
		},
		{
			name:  "truncated slug has trailing hyphens stripped",
			input: strings.Repeat("a", 79) + "-extra",
			// after slugification: 79 a's + "-extra" = 85 chars
			// truncate to 80: 79 a's + "-" → TrimRight strips trailing hyphen
			want: strings.Repeat("a", 79),
		},
		{
			name:  "single word",
			input: "golang",
			want:  "golang",
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  "",
		},
		{
			name:  "punctuation only",
			input: "!@#$%",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := slugify(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("slugify(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

func TestSlugify_LengthInvariant(t *testing.T) {
	t.Parallel()

	// Any input must produce a slug of at most 80 rune-safe bytes.
	inputs := []string{
		strings.Repeat("ab-", 50),
		strings.Repeat("x", 200),
		"Hello World! This is a very long title that exceeds the 80 character limit for slugs in URLs",
	}
	for _, input := range inputs {
		got := slugify(input)
		if len(got) > 80 {
			t.Errorf("slugify(%q) len=%d, want <= 80", input, len(got))
		}
		if got != "" && (got[0] == '-' || got[len(got)-1] == '-') {
			t.Errorf("slugify(%q) = %q, must not start or end with hyphen", input, got)
		}
	}
}

func FuzzSlugify(f *testing.F) {
	f.Add("Hello World")
	f.Add("")
	f.Add("---")
	f.Add(strings.Repeat("a", 200))
	f.Add("你好世界")
	f.Add("Hello 你好 World")
	f.Add("!@#$%^&*()")
	f.Add("normal-slug-title")

	f.Fuzz(func(t *testing.T, input string) {
		got := slugify(input)
		// Invariant 1: result must not exceed 80 bytes.
		if len(got) > 80 {
			t.Errorf("slugify(%q) len=%d, must be <= 80", input, len(got))
		}
		// Invariant 2: result must not start or end with a hyphen (unless empty).
		if got != "" {
			if got[0] == '-' || got[len(got)-1] == '-' {
				t.Errorf("slugify(%q) = %q, must not start/end with hyphen", input, got)
			}
		}
		// Invariant 3: result must be lowercase (all runes are a-z, 0-9, or hyphen).
		for _, r := range got {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				t.Errorf("slugify(%q) = %q contains invalid rune %q", input, got, r)
			}
		}
		// Invariant 4: no consecutive hyphens.
		if strings.Contains(got, "--") {
			t.Errorf("slugify(%q) = %q contains consecutive hyphens", input, got)
		}
	})
}

func BenchmarkSlugify(b *testing.B) {
	cases := []struct {
		name  string
		input string
	}{
		{"short", "Hello World"},
		{"typical_blog_title", "Building a Knowledge Engine with Go and PostgreSQL"},
		{"long_title", "This Is a Very Long Blog Post Title That Tests the Truncation Behavior of the Slugify Function"},
		{"cjk_mixed", "Building Go Systems 系統設計 with PostgreSQL"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_ = slugify(c.input)
			}
		})
	}
}

// --- estimateWordCount ---

func TestEstimateWordCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty string",
			input: "",
			want:  0,
		},
		{
			name:  "single word",
			input: "hello",
			want:  1,
		},
		{
			name:  "two words",
			input: "hello world",
			want:  2,
		},
		{
			name:  "multiple words",
			input: "one two three four five",
			want:  5,
		},
		{
			name:  "extra whitespace between words",
			input: "hello   world",
			want:  2,
		},
		{
			name:  "leading and trailing whitespace",
			input: "  hello world  ",
			want:  2,
		},
		{
			name:  "newlines count as separators",
			input: "hello\nworld\nfoo",
			want:  3,
		},
		{
			name:  "tabs count as separators",
			input: "hello\tworld",
			want:  2,
		},
		{
			name:  "whitespace only",
			input: "   \t\n  ",
			want:  0,
		},
		{
			name:  "markdown body with headers",
			input: "# Title\n\nThis is a paragraph with several words in it.",
			want:  11, // strings.Fields counts "#" as a separate word
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := estimateWordCount(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("estimateWordCount(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// --- toContentPipelineEntry ---

func TestToContentPipelineEntry(t *testing.T) {
	t.Parallel()

	fixedID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	fixedCreatedAt := time.Date(2025, 3, 15, 10, 0, 0, 0, time.UTC)
	fixedPublishedAt := time.Date(2025, 3, 20, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		input *content.Content
		want  contentPipelineEntry
	}{
		{
			name: "full content record with tags and published_at",
			input: &content.Content{
				ID:          fixedID,
				Slug:        "my-article",
				Title:       "My Article",
				Body:        "one two three four five",
				Type:        content.TypeArticle,
				Status:      content.StatusPublished,
				Tags:        []string{"go", "backend"},
				CreatedAt:   fixedCreatedAt,
				PublishedAt: &fixedPublishedAt,
			},
			want: contentPipelineEntry{
				ID:          fixedID.String(),
				Slug:        "my-article",
				Title:       "My Article",
				Type:        "article",
				Status:      "published",
				Tags:        []string{"go", "backend"},
				CreatedAt:   fixedCreatedAt.Format(time.RFC3339),
				PublishedAt: fixedPublishedAt.Format(time.RFC3339),
				WordCount:   5,
			},
		},
		{
			name: "nil published_at results in empty published_at string",
			input: &content.Content{
				ID:          fixedID,
				Slug:        "draft-post",
				Title:       "Draft Post",
				Body:        "hello world",
				Type:        content.TypeBuildLog,
				Status:      content.StatusDraft,
				Tags:        []string{"project"},
				CreatedAt:   fixedCreatedAt,
				PublishedAt: nil,
			},
			want: contentPipelineEntry{
				ID:          fixedID.String(),
				Slug:        "draft-post",
				Title:       "Draft Post",
				Type:        "build-log",
				Status:      "draft",
				Tags:        []string{"project"},
				CreatedAt:   fixedCreatedAt.Format(time.RFC3339),
				PublishedAt: "",
				WordCount:   2,
			},
		},
		{
			name: "nil tags replaced with empty slice (not nil)",
			input: &content.Content{
				ID:        fixedID,
				Slug:      "no-tags",
				Title:     "No Tags",
				Body:      "content here",
				Type:      content.TypeTIL,
				Status:    content.StatusDraft,
				Tags:      nil,
				CreatedAt: fixedCreatedAt,
			},
			want: contentPipelineEntry{
				ID:        fixedID.String(),
				Slug:      "no-tags",
				Title:     "No Tags",
				Type:      "til",
				Status:    "draft",
				Tags:      []string{},
				CreatedAt: fixedCreatedAt.Format(time.RFC3339),
				WordCount: 2,
			},
		},
		{
			name: "empty body gives zero word count",
			input: &content.Content{
				ID:        fixedID,
				Slug:      "empty-body",
				Title:     "Empty Body",
				Body:      "",
				Type:      content.TypeNote,
				Status:    content.StatusDraft,
				Tags:      []string{},
				CreatedAt: fixedCreatedAt,
			},
			want: contentPipelineEntry{
				ID:        fixedID.String(),
				Slug:      "empty-body",
				Title:     "Empty Body",
				Type:      "note",
				Status:    "draft",
				Tags:      []string{},
				CreatedAt: fixedCreatedAt.Format(time.RFC3339),
				WordCount: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toContentPipelineEntry(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toContentPipelineEntry() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToContentPipelineEntry_TagsNeverNil(t *testing.T) {
	t.Parallel()

	// Tags must always be a non-nil slice so JSON serialises as [] not null.
	c := &content.Content{
		ID:        uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Slug:      "test",
		Title:     "Test",
		Body:      "body",
		Type:      content.TypeArticle,
		Status:    content.StatusDraft,
		Tags:      nil,
		CreatedAt: time.Now(),
	}
	entry := toContentPipelineEntry(c)
	if entry.Tags == nil {
		t.Error("toContentPipelineEntry() Tags = nil, want non-nil empty slice")
	}
	// Verify utf8 validity of slug pass-through.
	if !utf8.ValidString(entry.Slug) {
		t.Errorf("toContentPipelineEntry() Slug %q is not valid UTF-8", entry.Slug)
	}
}
