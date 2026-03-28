package ai

import (
	"strings"
	"testing"

	"github.com/koopa0/blog-backend/internal/feed/entry"
)

func TestBuildBookmarkUserPrompt(t *testing.T) {
	cd := &entry.Item{
		Title:      "Understanding Go Memory Model",
		SourceName: "Go Blog",
		SourceURL:  "https://go.dev/blog/memory",
	}

	got := buildBookmarkUserPrompt(cd)

	for _, want := range []string{"Understanding Go Memory Model", "Go Blog", "https://go.dev/blog/memory"} {
		if !strings.Contains(got, want) {
			t.Errorf("buildBookmarkUserPrompt() missing %q, got: %s", want, got)
		}
	}
}
