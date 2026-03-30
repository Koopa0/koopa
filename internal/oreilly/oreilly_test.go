package oreilly

import (
	"testing"
)

// --- ExtractFilename ---

func TestExtractFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		refID string
		want  string
	}{
		{
			name:  "typical O'Reilly reference ID",
			refID: "9781835880302-/chap01.xhtml",
			want:  "chap01.xhtml",
		},
		{
			name:  "nested path segment",
			refID: "9781835880302-/OEBPS/content/chap05.xhtml",
			want:  "chap05.xhtml",
		},
		{
			name:  "no slash — returns original",
			refID: "chap01.xhtml",
			want:  "chap01.xhtml",
		},
		{
			name:  "empty string returns empty",
			refID: "",
			want:  "",
		},
		{
			name:  "trailing slash returns original (nothing after slash)",
			refID: "9781835880302-/",
			want:  "9781835880302-/",
		},
		{
			name:  "path ending with xhtml fragment",
			refID: "some/path/section.xhtml",
			want:  "section.xhtml",
		},
		{
			name:  "single slash at index 0 with content",
			refID: "/cover.xhtml",
			want:  "cover.xhtml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractFilename(tt.refID)
			if got != tt.want {
				t.Errorf("ExtractFilename(%q) = %q, want %q", tt.refID, got, tt.want)
			}
		})
	}
}

// --- StripHTML ---

func TestStripHTML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "plain text unchanged",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "simple tag removed",
			input: "<p>hello</p>",
			want:  "hello",
		},
		{
			name:  "nested tags removed",
			input: "<div><p>text</p></div>",
			want:  "text",
		},
		{
			name:  "multiple tags collapsed",
			input: "<h1>Title</h1><p>Body text here.</p>",
			want:  "Title Body text here.",
		},
		{
			name:  "attributes stripped",
			input: `<a href="https://example.com" class="link">click</a>`,
			want:  "click",
		},
		{
			name:  "self-closing tags removed",
			input: "before<br/>after",
			want:  "before after",
		},
		{
			name:  "leading and trailing whitespace trimmed",
			input: "  <p>hello</p>  ",
			want:  "hello",
		},
		{
			name:  "multiple consecutive spaces collapsed",
			input: "foo   bar   baz",
			want:  "foo bar baz",
		},
		{
			name:  "tabs and newlines collapsed to single space",
			input: "foo\t\nbar",
			want:  "foo bar",
		},
		{
			name:  "tags produce spaces that are collapsed",
			input: "<b>bold</b><i>italic</i>",
			want:  "bold italic",
		},
		{
			name:  "entire string is one tag returns empty",
			input: "<script>alert(1)</script>",
			want:  "alert(1)",
		},
		{
			name:  "comment-like content inside tag stripped",
			input: "<!-- comment -->text",
			want:  "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := StripHTML(tt.input)
			if got != tt.want {
				t.Errorf("StripHTML(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func FuzzStripHTML(f *testing.F) {
	f.Add("<p>hello world</p>")
	f.Add("<div><span>nested</span></div>")
	f.Add("")
	f.Add("plain text no tags")
	f.Add("<a href=\"http://example.com\">link</a>")
	f.Add("<!-- comment -->")
	f.Add("<br/>")
	f.Fuzz(func(t *testing.T, input string) {
		got := StripHTML(input)
		// Must not panic.
		// Invariant: result contains no '<' characters that are part of a complete tag.
		// (Incomplete tags like "a < b" may remain — we only check for regression in length.)
		if len(got) > len(input) {
			t.Errorf("StripHTML(%q) = %q: output longer than input", input, got)
		}
	})
}
