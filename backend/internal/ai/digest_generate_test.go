package ai

import (
	"strings"
	"testing"

	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/project"
)

func TestBuildDigestUserPrompt(t *testing.T) {
	published := []content.Content{
		{Title: "Go 1.26 Released", Type: content.TypeArticle, Excerpt: "New features overview"},
	}

	collectedItems := []entry.Item{
		{
			Title:      "PG Performance",
			SourceName: "PG Blog",
			SourceURL:  "https://pg.dev/perf",
		},
	}

	projects := []project.Project{
		{Title: "blog-backend", Status: project.StatusInProgress, Description: "Go API server"},
	}

	got := buildDigestUserPrompt(published, collectedItems, projects, "2026-03-03", "2026-03-10")

	for _, want := range []string{
		"2026-03-03",
		"2026-03-10",
		"Go 1.26 Released",
		"PG Performance",
		"blog-backend",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildDigestUserPrompt() missing %q", want)
		}
	}
}

func TestBuildDigestUserPrompt_Empty(t *testing.T) {
	got := buildDigestUserPrompt(nil, nil, nil, "2026-03-03", "2026-03-10")
	if !strings.Contains(got, "2026-03-03") {
		t.Error("buildDigestUserPrompt() should contain date range even with empty data")
	}
	// should not contain section headers when no data
	if strings.Contains(got, "本週發佈的內容") {
		t.Error("buildDigestUserPrompt() should skip published section when empty")
	}
}
