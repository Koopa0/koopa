package collector

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mmcdole/gofeed"
)

// URL normalization + hashing tests live in internal/url/url_test.go.
// Single authoritative canonicalisation lives in the koopaurl package;
// the collector delegates via koopaurl.Hash.

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
