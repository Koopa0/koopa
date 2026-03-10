package flow

import (
	"strings"
	"testing"

	"github.com/koopa0/blog-backend/internal/collected"
)

func TestBuildBookmarkUserPrompt(t *testing.T) {
	titleZH := "深入理解 Go 記憶體模型"
	summaryZH := "本文詳細解析 Go 的記憶體模型..."
	reason := "深度技術分析，有實作範例"

	cd := &collected.CollectedData{
		Title:         "Understanding Go Memory Model",
		SourceName:    "Go Blog",
		SourceURL:     "https://go.dev/blog/memory",
		AITitleZH:     &titleZH,
		AISummaryZH:   &summaryZH,
		AIScoreReason: &reason,
	}

	got := buildBookmarkUserPrompt(cd)

	// Should use zh title instead of original
	if !strings.Contains(got, titleZH) {
		t.Errorf("buildBookmarkUserPrompt() should use AITitleZH, got: %s", got)
	}
	if strings.Contains(got, "Understanding Go Memory Model") {
		t.Error("buildBookmarkUserPrompt() should prefer AITitleZH over original title")
	}

	for _, want := range []string{summaryZH, reason, "Go Blog", "https://go.dev/blog/memory"} {
		if !strings.Contains(got, want) {
			t.Errorf("buildBookmarkUserPrompt() missing %q", want)
		}
	}
}

func TestBuildBookmarkUserPrompt_NilFields(t *testing.T) {
	cd := &collected.CollectedData{
		Title:      "Raw Title",
		SourceName: "Source",
		SourceURL:  "https://example.com",
	}

	got := buildBookmarkUserPrompt(cd)

	// Should fall back to original title
	if !strings.Contains(got, "Raw Title") {
		t.Errorf("buildBookmarkUserPrompt() should use original title when AITitleZH is nil, got: %s", got)
	}
}
