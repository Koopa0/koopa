//go:build !integration

package exec

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/koopa0/blog-backend/internal/ai"
)

// TestRunner_MockFlowOutputUnmarshal verifies that the output produced by
// mock flows can be cleanly unmarshalled back into their respective output types.
func TestRunner_MockFlowOutputUnmarshal(t *testing.T) {
	t.Parallel()

	t.Run("content-review", func(t *testing.T) {
		t.Parallel()

		mockContentReview := ai.NewMockContentReview()
		output, err := mockContentReview.Run(t.Context(), json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("NewMockContentReview().Run() error: %v", err)
		}

		var got ai.ContentReviewOutput
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatalf("unmarshal ContentReviewOutput: %v", err)
		}

		want := ai.ContentReviewOutput{
			Proofread: &ai.ReviewResult{
				Level:       "auto",
				Notes:       "mock mode",
				Corrections: []string{},
			},
			Excerpt:     "Mock excerpt for testing.",
			Tags:        []string{},
			ReadingTime: 1,
		}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("ContentReviewOutput mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("content-polish", func(t *testing.T) {
		t.Parallel()

		mockPolish := ai.NewMockContentPolish()
		output, err := mockPolish.Run(t.Context(), json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("NewMockContentPolish().Run() error: %v", err)
		}

		var got ai.PolishOutput
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatalf("unmarshal ContentPolishOutput: %v", err)
		}

		want := ai.PolishOutput{
			OriginalBody: "Mock original body.",
			PolishedBody: "Mock polished body.",
		}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("ContentPolishOutput mismatch (-want +got):\n%s", diff)
		}
	})
}
