package flow

import (
	"testing"

	"github.com/koopa0/blog-backend/internal/collected"
)

func TestWeightedScore(t *testing.T) {
	tests := []struct {
		name   string
		result ScoreResult
		want   int16
	}{
		{
			name:   "all tens",
			result: ScoreResult{Relevance: 10, Depth: 10, Freshness: 10, Quality: 10},
			want:   100,
		},
		{
			name:   "all ones",
			result: ScoreResult{Relevance: 1, Depth: 1, Freshness: 1, Quality: 1},
			want:   10,
		},
		{
			name:   "mixed scores",
			result: ScoreResult{Relevance: 8, Depth: 7, Freshness: 6, Quality: 9},
			// 8*0.35 + 7*0.30 + 6*0.15 + 9*0.20 = 2.8 + 2.1 + 0.9 + 1.8 = 7.6
			// 7.6 * 10 = 76
			want: 76,
		},
		{
			name:   "all fives",
			result: ScoreResult{Relevance: 5, Depth: 5, Freshness: 5, Quality: 5},
			want:   50,
		},
		{
			name:   "all zeros",
			result: ScoreResult{Relevance: 0, Depth: 0, Freshness: 0, Quality: 0},
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.WeightedScore()
			if got != tt.want {
				t.Errorf("WeightedScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestStatusFromScore(t *testing.T) {
	tests := []struct {
		name  string
		score int16
		want  collected.Status
	}{
		{name: "100 -> curated", score: 100, want: collected.StatusCurated},
		{name: "70 -> curated", score: 70, want: collected.StatusCurated},
		{name: "69 -> read", score: 69, want: collected.StatusRead},
		{name: "50 -> read", score: 50, want: collected.StatusRead},
		{name: "49 -> ignored", score: 49, want: collected.StatusIgnored},
		{name: "0 -> ignored", score: 0, want: collected.StatusIgnored},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StatusFromScore(tt.score)
			if got != tt.want {
				t.Errorf("StatusFromScore(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestBuildScoreUserPrompt(t *testing.T) {
	content := "article body here"
	cd := &collected.CollectedData{
		Title:           "Test Article",
		SourceName:      "Go Blog",
		SourceURL:       "https://go.dev/blog/test",
		OriginalContent: &content,
	}

	got := buildScoreUserPrompt(cd)

	if got == "" {
		t.Fatal("buildScoreUserPrompt() returned empty string")
	}
	// verify key fields are present
	for _, want := range []string{"Test Article", "Go Blog", "https://go.dev/blog/test", "article body here"} {
		if !contains(got, want) {
			t.Errorf("buildScoreUserPrompt() missing %q", want)
		}
	}
}

func TestBuildScoreUserPrompt_NilContent(t *testing.T) {
	cd := &collected.CollectedData{
		Title:      "No Content",
		SourceName: "Source",
		SourceURL:  "https://example.com",
	}

	got := buildScoreUserPrompt(cd)
	if got == "" {
		t.Fatal("buildScoreUserPrompt() returned empty string for nil content")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
