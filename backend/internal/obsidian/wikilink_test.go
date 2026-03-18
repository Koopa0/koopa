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
