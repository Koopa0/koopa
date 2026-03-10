package flow

import (
	"strings"
	"testing"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/project"
)

func TestScoreValue(t *testing.T) {
	tests := []struct {
		name  string
		input *int16
		want  int16
	}{
		{name: "nil", input: nil, want: 0},
		{name: "75", input: int16Ptr(75), want: 75},
		{name: "0", input: int16Ptr(0), want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreValue(tt.input)
			if got != tt.want {
				t.Errorf("scoreValue() = %d, want %d", got, tt.want)
			}
		})
	}
}

func int16Ptr(v int16) *int16 { return &v }

func TestBuildDigestUserPrompt(t *testing.T) {
	published := []content.Content{
		{Title: "Go 1.26 Released", Type: content.TypeArticle, Excerpt: "New features overview"},
	}

	summary := "PostgreSQL 效能調校技巧"
	titleZH := "PG 效能指南"
	score := int16(85)
	collectedItems := []collected.CollectedData{
		{
			Title:       "PG Performance",
			SourceName:  "PG Blog",
			SourceURL:   "https://pg.dev/perf",
			AISummaryZH: &summary,
			AITitleZH:   &titleZH,
			AIScore:     &score,
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
		"PG 效能指南",
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
