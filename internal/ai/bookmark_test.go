package ai

import (
	"strings"
	"testing"

	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
)

func TestBuildBookmarkUserPrompt(t *testing.T) {
	cd := &entry.Item{
		Title:     "Understanding Go Memory Model",
		FeedName:  "Go Blog",
		SourceURL: "https://go.dev/blog/memory",
	}

	got := buildBookmarkUserPrompt(cd)

	for _, want := range []string{"Understanding Go Memory Model", "Go Blog", "https://go.dev/blog/memory"} {
		if !strings.Contains(got, want) {
			t.Errorf("buildBookmarkUserPrompt() missing %q, got: %s", want, got)
		}
	}
}
