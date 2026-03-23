package flow

import (
	"strings"
	"testing"

	"github.com/koopa0/blog-backend/internal/collected"
)

func TestBuildBookmarkUserPrompt(t *testing.T) {
	cd := &collected.Item{
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
