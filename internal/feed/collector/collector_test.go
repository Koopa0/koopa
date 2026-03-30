package collector

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mmcdole/gofeed"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lowercase host",
			input: "https://Example.COM/path",
			want:  "https://example.com/path",
		},
		{
			name:  "strip trailing slash",
			input: "https://example.com/path/",
			want:  "https://example.com/path",
		},
		{
			name:  "strip utm params",
			input: "https://example.com/post?utm_source=rss&utm_medium=feed&id=123",
			want:  "https://example.com/post?id=123",
		},
		{
			name:  "strip fragment",
			input: "https://example.com/post#section",
			want:  "https://example.com/post",
		},
		{
			name:  "already normalized",
			input: "https://example.com/post",
			want:  "https://example.com/post",
		},
		{
			name:  "mixed case utm",
			input: "https://example.com/post?UTM_Campaign=test",
			want:  "https://example.com/post",
		},
		{
			name:  "invalid url returns as-is",
			input: "://not-a-url",
			want:  "://not-a-url",
		},
		{
			name:  "root path no trailing slash",
			input: "https://example.com/",
			want:  "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHashURL(t *testing.T) {
	// Same URL with different trailing slashes should produce the same hash
	h1 := hashURL("https://example.com/post/")
	h2 := hashURL("https://example.com/post")
	if h1 != h2 {
		t.Errorf("hashURL with/without trailing slash differ: %q vs %q", h1, h2)
	}

	// Same URL with different utm params should produce the same hash
	h3 := hashURL("https://example.com/post?utm_source=rss")
	if h1 != h3 {
		t.Errorf("hashURL with/without utm differ: %q vs %q", h1, h3)
	}

	// Different URLs should produce different hashes
	h4 := hashURL("https://example.com/other")
	if h1 == h4 {
		t.Errorf("hashURL for different URLs should differ")
	}

	// Hash should be hex-encoded SHA-256 (64 chars)
	if len(h1) != 64 {
		t.Errorf("hashURL length = %d, want 64", len(h1))
	}
}

func TestItemContent(t *testing.T) {
	tests := []struct {
		name string
		item *gofeed.Item
		want string
	}{
		{
			name: "content preferred over description",
			item: &gofeed.Item{Content: "<p>full content</p>", Description: "short desc"},
			want: "<p>full content</p>",
		},
		{
			name: "fallback to description",
			item: &gofeed.Item{Description: "short desc"},
			want: "short desc",
		},
		{
			name: "both empty",
			item: &gofeed.Item{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := itemContent(tt.item)
			if got != tt.want {
				t.Errorf("itemContent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDomainFromURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "simple", input: "https://example.com/path", want: "example.com"},
		{name: "with port", input: "https://example.com:8080/path", want: "example.com:8080"},
		{name: "uppercase", input: "https://EXAMPLE.COM/path", want: "example.com"},
		{name: "invalid", input: "://bad", want: "://bad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domainFromURL(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("domainFromURL(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}
