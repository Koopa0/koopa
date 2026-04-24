package collector

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mmcdole/gofeed"
)

// URL canonicalisation + hashing tests live in internal/url/url_test.go.
// Canonicalisation is owned by the koopaurl package; collector-side
// adversarial / security cases would be redundant with url_test.go.

// TestItemContent_Extended covers boundary and adversarial inputs.
func TestItemContent_Extended(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		item *gofeed.Item
		want string
	}{
		{
			name: "content with null bytes",
			item: &gofeed.Item{Content: "hello\x00world"},
			want: "hello\x00world",
		},
		{
			name: "very large content",
			item: &gofeed.Item{Content: strings.Repeat("x", 100_000)},
			want: strings.Repeat("x", 100_000),
		},
		{
			name: "content is whitespace only",
			item: &gofeed.Item{Content: "   ", Description: "desc"},
			want: "   ", // content is non-empty so it wins
		},
		{
			name: "unicode content",
			item: &gofeed.Item{Content: "Go 語言的並發模型"},
			want: "Go 語言的並發模型",
		},
		{
			name: "html entities in description fallback",
			item: &gofeed.Item{Description: "&lt;script&gt;alert(1)&lt;/script&gt;"},
			want: "&lt;script&gt;alert(1)&lt;/script&gt;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := itemContent(tt.item)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("itemContent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// FuzzNormalizeURL removed — idempotency fuzz test lives in
// internal/url/url_test.go as FuzzCanonical, covering the same invariant
// against the authoritative canonicaliser.

// TestRegression_MaxFeedResponseSize documents the bug where external RSS
// responses were unbounded (fixed by io.LimitReader). This test verifies
// the constant is set to a safe value.
func TestRegression_MaxFeedResponseSize(t *testing.T) {
	t.Parallel()

	// maxFeedResponseSize must be between 1 MB and 50 MB.
	const minSafe = 1 << 20  // 1 MB
	const maxSafe = 50 << 20 // 50 MB

	if maxFeedResponseSize < minSafe {
		t.Errorf("maxFeedResponseSize = %d, want >= %d (too small; legitimate feeds may be rejected)", maxFeedResponseSize, minSafe)
	}
	if maxFeedResponseSize > maxSafe {
		t.Errorf("maxFeedResponseSize = %d, want <= %d (too large; memory exhaustion risk)", maxFeedResponseSize, maxSafe)
	}
}

// TestRegression_MaxContentLen documents the truncation behaviour for scoring.
func TestRegression_MaxContentLen(t *testing.T) {
	t.Parallel()

	// maxContentLen must be reasonable: enough for scoring but not unbounded.
	const minLen = 500
	const maxLen = 50_000

	if maxContentLen < minLen {
		t.Errorf("maxContentLen = %d, want >= %d", maxContentLen, minLen)
	}
	if maxContentLen > maxLen {
		t.Errorf("maxContentLen = %d, want <= %d (scoring window too large)", maxContentLen, maxLen)
	}
}

// TestRegression_MaxRedirects documents the redirect cap.
func TestRegression_MaxRedirects(t *testing.T) {
	t.Parallel()

	if maxRedirects <= 0 {
		t.Errorf("maxRedirects = %d, want > 0", maxRedirects)
	}
	if maxRedirects > 10 {
		t.Errorf("maxRedirects = %d, want <= 10 (SSRF redirect chain risk)", maxRedirects)
	}
}
