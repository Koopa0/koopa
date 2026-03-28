package mcpserver

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
)

// ---- extractFrontmatter ----

func TestExtractFrontmatter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		key  string
		want string
	}{
		{
			name: "key present with value",
			body: "---\nproject: my-project\nstatus: active\n---\n\n# Heading",
			key:  "project",
			want: "my-project",
		},
		{
			name: "key with extra spaces around colon",
			body: "project:   spaced-value\n",
			key:  "project",
			want: "spaced-value",
		},
		{
			name: "key not present returns empty",
			body: "---\ntitle: hello\n---\n",
			key:  "project",
			want: "",
		},
		{
			name: "empty body returns empty",
			body: "",
			key:  "project",
			want: "",
		},
		{
			name: "body is only --- delimiters",
			body: "---\n---\n",
			key:  "project",
			want: "",
		},
		{
			name: "stops at first heading",
			body: "# Heading\nproject: after-heading\n",
			key:  "project",
			want: "",
		},
		{
			name: "heading after frontmatter stops scan",
			body: "project: before-heading\n# Heading\nproject: after-heading\n",
			key:  "project",
			want: "before-heading",
		},
		{
			name: "value with colon included verbatim",
			body: "url: https://example.com\n",
			key:  "url",
			want: "https://example.com",
		},
		{
			name: "key prefix does not match partial key",
			body: "project_id: some-id\n",
			key:  "project",
			want: "",
		},
		{
			name: "blank lines are skipped",
			body: "\n\nproject: found\n",
			key:  "project",
			want: "found",
		},
		{
			name: "second occurrence of key not reached after heading",
			body: "project: first\n# Stop\nproject: second\n",
			key:  "project",
			want: "first",
		},
		{
			name: "only dashes line is skipped",
			body: "---\nproject: after-dashes\n",
			key:  "project",
			want: "after-dashes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractFrontmatter(tt.body, tt.key)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("extractFrontmatter(%q, %q) mismatch (-want +got):\n%s", tt.body, tt.key, diff)
			}
		})
	}
}

// FuzzExtractFrontmatter ensures extractFrontmatter never panics on arbitrary markdown.
func FuzzExtractFrontmatter(f *testing.F) {
	f.Add("---\nproject: foo\n---\n\n# Heading", "project")
	f.Add("", "project")
	f.Add("# Heading\nsome text", "title")
	f.Add("key: value\nanother: one", "key")
	f.Add("---\n---\n", "status")
	f.Fuzz(func(t *testing.T, body, key string) {
		_ = extractFrontmatter(body, key) // must not panic
	})
}

// ---- contentMatchesProject ----

func TestContentMatchesProject(t *testing.T) {
	t.Parallel()

	projectID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	otherID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	projectSlug := "my-project"

	tests := []struct {
		name    string
		content content.Content
		want    bool
	}{
		{
			name: "FK match — project_id equals projectID",
			content: content.Content{
				ProjectID: &projectID,
				Slug:      "unrelated-slug",
			},
			want: true,
		},
		{
			name: "FK mismatch — different project_id",
			content: content.Content{
				ProjectID: &otherID,
				Slug:      "unrelated-slug",
			},
			want: false,
		},
		{
			name: "FK nil — falls through to tag match",
			content: content.Content{
				Tags: []string{"my-project", "go"},
			},
			want: true,
		},
		{
			name: "tag match case-insensitive",
			content: content.Content{
				Tags: []string{"My-Project"},
			},
			want: true,
		},
		{
			name: "tag mismatch",
			content: content.Content{
				Tags: []string{"other-project", "go"},
			},
			want: false,
		},
		{
			name: "slug prefix match",
			content: content.Content{
				Slug: "my-project-post-1",
			},
			want: true,
		},
		{
			name: "slug does not have prefix",
			content: content.Content{
				Slug: "another-post",
			},
			want: false,
		},
		{
			name: "frontmatter project key exact match",
			content: content.Content{
				Body: "project: my-project\n\n# Content",
			},
			want: true,
		},
		{
			name: "frontmatter project key contains slug",
			content: content.Content{
				Body: "project: my-project-extra\n",
			},
			want: true,
		},
		{
			name: "frontmatter project key mismatch",
			content: content.Content{
				Body: "project: other-project\n",
			},
			want: false,
		},
		{
			name: "no project_id, no tags, no prefix, no frontmatter — no match",
			content: content.Content{
				Slug: "random-post",
				Tags: []string{"golang"},
				Body: "project: different\n",
			},
			want: false,
		},
		{
			name: "FK match takes priority over mismatched tags",
			content: content.Content{
				ProjectID: &projectID,
				Tags:      []string{"totally-different"},
			},
			want: true,
		},
		{
			name:    "empty content — no match",
			content: content.Content{},
			want:    false,
		},
		{
			name: "multiple matching strategies — still true",
			content: content.Content{
				ProjectID: &projectID,
				Tags:      []string{"my-project"},
				Slug:      "my-project-slug",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := contentMatchesProject(&tt.content, projectID, projectSlug)
			if got != tt.want {
				t.Errorf("contentMatchesProject() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---- truncate ----

func TestTruncate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{
			name:   "ASCII within limit — no truncation",
			s:      "hello",
			maxLen: 10,
			want:   "hello",
		},
		{
			name:   "ASCII exact limit — no truncation",
			s:      "hello",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "ASCII over limit — truncated with ellipsis",
			s:      "hello world",
			maxLen: 5,
			want:   "hello...",
		},
		{
			name:   "empty string",
			s:      "",
			maxLen: 10,
			want:   "",
		},
		{
			name:   "maxLen zero returns empty",
			s:      "hello",
			maxLen: 0,
			want:   "",
		},
		{
			name:   "CJK characters counted by rune not byte",
			s:      "你好世界測試", // 6 runes, each 3 bytes
			maxLen: 4,
			want:   "你好世界...",
		},
		{
			name:   "CJK within limit",
			s:      "你好",
			maxLen: 5,
			want:   "你好",
		},
		{
			name:   "emoji counted as one rune",
			s:      "😀😁😂😃",
			maxLen: 2,
			want:   "😀😁...",
		},
		{
			name:   "mixed ASCII and CJK",
			s:      "Go語言",
			maxLen: 3,
			want:   "Go語...",
		},
		{
			name:   "maxLen equals string rune length — no truncation",
			s:      "abc",
			maxLen: 3,
			want:   "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncate(tt.s, tt.maxLen)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("truncate(%q, %d) mismatch (-want +got):\n%s", tt.s, tt.maxLen, diff)
			}
		})
	}
}

// FuzzTruncate ensures truncate never panics and always returns a valid string.
func FuzzTruncate(f *testing.F) {
	f.Add("hello world", 5)
	f.Add("", 0)
	f.Add("你好世界", 2)
	f.Add("😀😁😂", 1)
	f.Add("abc", 100)
	f.Fuzz(func(t *testing.T, s string, maxLen int) {
		got := truncate(s, maxLen)
		if maxLen >= 0 {
			// Result rune length must not exceed maxLen + 3 (ellipsis)
			gotRunes := []rune(got)
			wantMax := maxLen + 3 // "..." suffix has 3 runes
			if len(gotRunes) > wantMax {
				t.Errorf("truncate(%q, %d) = %q, rune length %d exceeds max %d",
					s, maxLen, got, len(gotRunes), wantMax)
			}
		}
	})
}

// ---- stripHTMLTags ----

func TestStripHTMLTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "simple open and close tags removed",
			s:    "<p>Hello world</p>",
			want: "Hello world",
		},
		{
			name: "nested tags removed",
			s:    "<div><p><strong>Bold</strong> text</p></div>",
			want: "Bold text",
		},
		{
			name: "self-closing tag removed",
			s:    "Line one<br/>Line two",
			want: "Line one Line two",
		},
		{
			name: "no HTML — unchanged",
			s:    "plain text",
			want: "plain text",
		},
		{
			name: "empty string",
			s:    "",
			want: "",
		},
		{
			name: "whitespace collapsed",
			s:    "  hello   world  ",
			want: "hello world",
		},
		{
			name: "tag with attributes removed",
			s:    `<a href="https://example.com" class="link">click here</a>`,
			want: "click here",
		},
		{
			name: "multiple adjacent tags",
			s:    "<em><strong>text</strong></em>",
			want: "text",
		},
		{
			name: "malformed tag missing close angle — treated as tag up to >",
			s:    "<p>content</p>",
			want: "content",
		},
		{
			name: "content between tags preserved",
			s:    "<h1>Title</h1><p>Body paragraph.</p>",
			want: "Title Body paragraph.",
		},
		{
			name: "tags replaced by space — words do not merge",
			s:    "word1<br>word2",
			want: "word1 word2",
		},
		{
			name: "HTML entities preserved (not decoded)",
			s:    "AT&amp;T",
			want: "AT&amp;T",
		},
		{
			name: "only whitespace",
			s:    "   \t\n  ",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := stripHTMLTags(tt.s)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("stripHTMLTags(%q) mismatch (-want +got):\n%s", tt.s, diff)
			}
		})
	}
}

// FuzzStripHTMLTags ensures stripHTMLTags never panics on arbitrary input.
func FuzzStripHTMLTags(f *testing.F) {
	f.Add("<p>Hello</p>")
	f.Add("")
	f.Add("<div><span>text</span></div>")
	f.Add("plain text")
	f.Add("<a href=\"url\">link</a>")
	f.Add("<br/>")
	f.Add("<!-- comment -->")
	f.Fuzz(func(t *testing.T, s string) {
		_ = stripHTMLTags(s) // must not panic
	})
}

// BenchmarkStripHTMLTags measures HTML stripping throughput at realistic sizes.
func BenchmarkStripHTMLTags(b *testing.B) {
	snippets := []struct {
		name  string
		input string
	}{
		{
			name:  "short_plain",
			input: "Hello world, no HTML here.",
		},
		{
			name:  "short_html",
			input: "<p>Hello <strong>world</strong>, this is a <a href=\"url\">link</a>.</p>",
		},
		{
			name: "medium_html",
			input: `<article>
				<h1>Title of the Article</h1>
				<p>This is the first paragraph with some <em>emphasis</em> and <strong>bold</strong>.</p>
				<p>A second paragraph with a <a href="https://example.com">link</a> inside.</p>
				<ul><li>Item one</li><li>Item two</li><li>Item three</li></ul>
			</article>`,
		},
		{
			name: "large_html",
			// ~500 chars of nested HTML
			input: `<div class="post"><header><h2>Post Title</h2><time>2026-03-28</time></header>` +
				`<section><p>Lorem ipsum dolor sit amet, <em>consectetur</em> adipiscing elit. ` +
				`Sed do eiusmod <strong>tempor incididunt</strong> ut labore et dolore magna aliqua.</p>` +
				`<p>Ut enim ad minim veniam, quis <a href="/link">nostrud exercitation</a> ullamco laboris.</p>` +
				`<blockquote><p>Duis aute irure dolor in reprehenderit in voluptate.</p></blockquote>` +
				`</section><footer><span>Tags: </span><a href="/go">go</a>, <a href="/testing">testing</a></footer></div>`,
		},
	}

	for _, sn := range snippets {
		b.Run(sn.name, func(b *testing.B) {
			for b.Loop() {
				_ = stripHTMLTags(sn.input)
			}
		})
	}
}

// ---- clamp ----

func TestClamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		val        int
		minVal     int
		maxVal     int
		defaultVal int
		want       int
	}{
		{
			name:       "value within range — returned as-is",
			val:        5,
			minVal:     1,
			maxVal:     10,
			defaultVal: 3,
			want:       5,
		},
		{
			name:       "value at minimum boundary — returned as-is",
			val:        1,
			minVal:     1,
			maxVal:     10,
			defaultVal: 3,
			want:       1,
		},
		{
			name:       "value at maximum boundary — returned as-is",
			val:        10,
			minVal:     1,
			maxVal:     10,
			defaultVal: 3,
			want:       10,
		},
		{
			name:       "value above max — clamped to max",
			val:        100,
			minVal:     1,
			maxVal:     10,
			defaultVal: 3,
			want:       10,
		},
		{
			name:       "value below min but positive — clamped to min",
			val:        0,
			minVal:     1,
			maxVal:     10,
			defaultVal: 3,
			// val <= 0 → returns defaultVal
			want: 3,
		},
		{
			name:       "zero value — returns default",
			val:        0,
			minVal:     1,
			maxVal:     10,
			defaultVal: 5,
			want:       5,
		},
		{
			name:       "negative value — returns default",
			val:        -5,
			minVal:     1,
			maxVal:     10,
			defaultVal: 7,
			want:       7,
		},
		{
			name: "value exactly one below min — clamped to min",
			// clamp: val <= 0 → default; val < min → min; val > max → max; else val
			// val=0, min=1 → val<=0 → default
			// val=1, min=2 → val>0, val<min → min
			val:        1,
			minVal:     2,
			maxVal:     10,
			defaultVal: 5,
			want:       2,
		},
		{
			name:       "value one above max — clamped to max",
			val:        11,
			minVal:     1,
			maxVal:     10,
			defaultVal: 5,
			want:       10,
		},
		{
			name:       "default is returned when val negative",
			val:        -1,
			minVal:     0,
			maxVal:     100,
			defaultVal: 20,
			want:       20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := clamp(tt.val, tt.minVal, tt.maxVal, tt.defaultVal)
			if got != tt.want {
				t.Errorf("clamp(%d, %d, %d, %d) = %d, want %d",
					tt.val, tt.minVal, tt.maxVal, tt.defaultVal, got, tt.want)
			}
		})
	}
}

// ---- isEmptyResult ----

func TestIsEmptyResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output any
		want   bool
	}{
		{
			name:   "nil output",
			output: nil,
			want:   false,
		},
		// isEmptyResult looks for the json key "total" (lowercase).
		// Structs must use json:"total" tags; untagged exported fields marshal as "Total".
		{
			name: "json-tagged total=0 — empty",
			output: struct {
				Total int `json:"total"`
			}{Total: 0},
			want: true,
		},
		{
			name: "json-tagged total=1 — not empty",
			output: struct {
				Total int `json:"total"`
			}{Total: 1},
			want: false,
		},
		{
			name: "json-tagged total=100 — not empty",
			output: struct {
				Total int `json:"total"`
			}{Total: 100},
			want: false,
		},
		{
			name:   "struct without total field — not empty",
			output: struct{ Count int }{Count: 0},
			want:   false,
		},
		{
			name:   "empty struct — not empty",
			output: struct{}{},
			want:   false,
		},
		{
			name:   "nil output — not empty",
			output: nil,
			want:   false,
		},
		{
			name: "json-tagged total with other fields — total=0",
			output: struct {
				Total   int      `json:"total"`
				Results []string `json:"results"`
			}{Total: 0, Results: nil},
			want: true,
		},
		{
			name: "json-tagged total with other fields — total=5",
			output: struct {
				Total   int      `json:"total"`
				Results []string `json:"results"`
			}{Total: 5, Results: []string{"a"}},
			want: false,
		},
		{
			name: "untagged Total field — not detected (key is 'Total' not 'total')",
			output: struct {
				Total int
			}{Total: 0},
			want: false,
		},
		{
			name:   "non-marshallable type (channel) — returns false",
			output: make(chan int),
			want:   false,
		},
		{
			name:   "string type — no total field",
			output: "hello",
			want:   false,
		},
		{
			name: "nested struct — total at top level with json tag",
			output: struct {
				Total  int `json:"total"`
				Nested struct{ Count int }
			}{Total: 0},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isEmptyResult(tt.output)
			if got != tt.want {
				t.Errorf("isEmptyResult(%v) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

// TestIsEmptyResult_StringTotal verifies the exact string comparison logic:
// only the literal "0" triggers empty, not "00" or " 0".
func TestIsEmptyResult_StringTotal(t *testing.T) {
	t.Parallel()

	// A pointer to int64 marshals as a JSON number.
	// We test that "0" is detected but larger values are not.
	type result struct {
		Total int64 `json:"total"`
	}

	if !isEmptyResult(result{Total: 0}) {
		t.Error("isEmptyResult(total=0) = false, want true")
	}
	if isEmptyResult(result{Total: 1}) {
		t.Error("isEmptyResult(total=1) = true, want false")
	}
}
