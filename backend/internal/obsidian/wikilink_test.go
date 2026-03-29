package obsidian

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseWikilinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    []Link
	}{
		{
			name:    "empty content",
			content: "",
			want:    []Link{},
		},
		{
			name:    "no wikilinks",
			content: "This is plain text with no links.",
			want:    []Link{},
		},
		{
			name:    "single link",
			content: "See [[some-note]] for details.",
			want:    []Link{{Path: "some-note"}},
		},
		{
			name:    "link with alias",
			content: "See [[path/to/note|display text]] here.",
			want:    []Link{{Path: "path/to/note", Display: "display text"}},
		},
		{
			name:    "multiple links on one line",
			content: "Links: [[note-a]] and [[note-b]] end.",
			want:    []Link{{Path: "note-a"}, {Path: "note-b"}},
		},
		{
			name:    "duplicate links deduplicated",
			content: "See [[note-a]] and again [[note-a]].",
			want:    []Link{{Path: "note-a"}},
		},
		{
			name:    "link inside fenced code block ignored",
			content: "Before\n```\n[[inside-code]]\n```\nAfter [[real-link]]",
			want:    []Link{{Path: "real-link"}},
		},
		{
			name:    "empty brackets ignored",
			content: "Empty [[]] should be skipped.",
			want:    []Link{},
		},
		{
			name:    "links across multiple lines",
			content: "Line 1 [[link-1]]\nLine 2 [[link-2]]\nLine 3 [[link-3]]",
			want: []Link{
				{Path: "link-1"},
				{Path: "link-2"},
				{Path: "link-3"},
			},
		},
		{
			name:    "link with spaces trimmed",
			content: "See [[ spaced-note ]] here.",
			want:    []Link{{Path: "spaced-note"}},
		},
		{
			name:    "nested brackets parsed to first closing",
			content: "Text [[note-[with]-bracket]] end.",
			want:    []Link{{Path: "note-[with]-bracket"}},
		},
		// adversarial
		{
			name:    "SQL injection in link path",
			content: "[['; DROP TABLE notes; --]]",
			want:    []Link{{Path: "'; DROP TABLE notes; --"}},
		},
		{
			name:    "XSS in link path",
			content: `[[<script>alert(1)</script>]]`,
			want:    []Link{{Path: "<script>alert(1)</script>"}},
		},
		{
			name:    "null bytes in content",
			content: "text [[note\x00evil]] end",
			want:    []Link{{Path: "note\x00evil"}},
		},
		{
			name:    "very long link path",
			content: "[[" + string(make([]byte, 10000)) + "]]",
			want:    []Link{{Path: string(make([]byte, 10000))}},
		},
		{
			name:    "pipe only (empty path and display)",
			content: "[[|]]",
			want:    []Link{}, // empty path after trim → skipped
		},
		{
			name:    "multiple pipes",
			content: "[[a|b|c]]",
			want:    []Link{{Path: "a", Display: "b|c"}},
		},
		{
			name:    "unclosed bracket",
			content: "text [[unclosed no end",
			want:    []Link{},
		},
		{
			name:    "single open bracket",
			content: "text [not-a-link] end",
			want:    []Link{},
		},
		{
			name:    "inline backticks do not toggle code block",
			content: "some ``` [[still-parsed]] ``` text [[also-parsed]]",
			want:    []Link{{Path: "still-parsed"}, {Path: "also-parsed"}},
		},
		{
			name:    "unicode path preserved",
			content: "[[Go 記憶體管理|記憶體]]",
			want:    []Link{{Path: "Go 記憶體管理", Display: "記憶體"}},
		},
		{
			name:    "emoji in path",
			content: "[[🚀 Launch Notes]]",
			want:    []Link{{Path: "🚀 Launch Notes"}},
		},
		{
			name:    "link at very start of content",
			content: "[[first-link]]",
			want:    []Link{{Path: "first-link"}},
		},
		{
			name:    "link at very end without newline",
			content: "end [[last-link]]",
			want:    []Link{{Path: "last-link"}},
		},
		{
			name:    "adjacent links no space between",
			content: "[[a]][[b]]",
			want:    []Link{{Path: "a"}, {Path: "b"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseWikilinks(tt.content)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseWikilinks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
