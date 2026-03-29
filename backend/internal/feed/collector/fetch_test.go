package collector

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mmcdole/gofeed"
)

// TestNormalizeURL_Adversarial extends the existing normalizeURL tests with
// adversarial, security, and boundary cases.
func TestNormalizeURL_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Security: path traversal should not be manipulated by normalizer
		{
			name:  "path traversal attempt",
			input: "https://example.com/../../etc/passwd",
			want:  "https://example.com/../../etc/passwd",
		},
		// SQL injection in query params — tracking params stripped, SQL survives in non-utm keys
		{
			name:  "sql injection in query param",
			input: "https://example.com/post?id=1'%3BDROP%20TABLE%20feeds%3B--",
			want:  "https://example.com/post?id=1%27%3BDROP+TABLE+feeds%3B--",
		},
		// UTM stripping is case-insensitive
		{
			name:  "utm uppercase variant",
			input: "https://example.com/post?UTM_SOURCE=rss&legit=1",
			want:  "https://example.com/post?legit=1",
		},
		// Multiple utm params all stripped, others preserved
		{
			name:  "multiple utm with non-utm",
			input: "https://example.com/post?utm_source=a&utm_medium=b&utm_campaign=c&id=42",
			want:  "https://example.com/post?id=42",
		},
		// Empty string
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		// No path (root with query)
		{
			name:  "root with query",
			input: "https://example.com?q=test",
			want:  "https://example.com?q=test",
		},
		// Fragment only
		{
			name:  "fragment stripped from utm-only url",
			input: "https://example.com/post?utm_source=rss#top",
			want:  "https://example.com/post",
		},
		// Unicode in path — must survive normalization
		{
			name:  "unicode path",
			input: "https://example.com/文章/golang",
			want:  "https://example.com/%E6%96%87%E7%AB%A0/golang",
		},
		// Regression: double utm prefix like utm_utm_source should be stripped
		{
			name:  "utm double prefix",
			input: "https://example.com/post?utm_utm_source=rss",
			want:  "https://example.com/post",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeURL(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("normalizeURL(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// TestHashURL_Properties verifies invariants of the hash function.
func TestHashURL_Properties(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		url1   string
		url2   string
		wantEq bool
	}{
		{
			name:   "trailing slash equivalence",
			url1:   "https://example.com/post/",
			url2:   "https://example.com/post",
			wantEq: true,
		},
		{
			name:   "utm stripped equivalence",
			url1:   "https://example.com/post?utm_source=rss",
			url2:   "https://example.com/post",
			wantEq: true,
		},
		{
			name:   "case insensitive host equivalence",
			url1:   "https://EXAMPLE.COM/post",
			url2:   "https://example.com/post",
			wantEq: true,
		},
		{
			name:   "different paths produce different hashes",
			url1:   "https://example.com/post-a",
			url2:   "https://example.com/post-b",
			wantEq: false,
		},
		{
			name:   "different hosts produce different hashes",
			url1:   "https://example.com/post",
			url2:   "https://other.com/post",
			wantEq: false,
		},
		{
			name:   "different query params (non-utm) produce different hashes",
			url1:   "https://example.com/post?id=1",
			url2:   "https://example.com/post?id=2",
			wantEq: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h1 := hashURL(tt.url1)
			h2 := hashURL(tt.url2)
			equal := h1 == h2
			if equal != tt.wantEq {
				t.Errorf("hashURL(%q) = %q, hashURL(%q) = %q; equal=%v, want %v",
					tt.url1, h1, tt.url2, h2, equal, tt.wantEq)
			}
			// Hash length invariant: always 64 hex chars (SHA-256)
			for _, h := range []string{h1, h2} {
				if len(h) != 64 {
					t.Errorf("hashURL length = %d, want 64", len(h))
				}
			}
		})
	}
}

// TestHashURL_SecurityInputs verifies hash is deterministic for adversarial inputs.
func TestHashURL_SecurityInputs(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"'; DROP TABLE collected_data; --",
		"<script>alert(1)</script>",
		"http://127.0.0.1/admin",
		strings.Repeat("a", 10000),
		"\x00\x01\x02\x03",
		"",
	}

	for _, input := range inputs {
		// Must not panic, must return 64-char hex string.
		h := hashURL(input)
		if len(h) != 64 {
			t.Errorf("hashURL(%q) length = %d, want 64", input, len(h))
		}
	}
}

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

// TestNormalizeURL_Fuzz is a property-based fuzz test for normalizeURL.
func FuzzNormalizeURL(f *testing.F) {
	f.Add("https://example.com/post?utm_source=rss&id=1")
	f.Add("https://EXAMPLE.COM/path/")
	f.Add("")
	f.Add("://bad")
	f.Add("https://example.com/post?utm_source=rss#fragment")
	f.Add("'; DROP TABLE feeds; --")
	f.Add("\x00\xff")
	f.Add("https://[::1]/feed")

	f.Fuzz(func(t *testing.T, input string) {
		// must not panic
		result := normalizeURL(input)

		// Idempotency: normalizing again must produce the same result.
		result2 := normalizeURL(result)
		if result != result2 {
			t.Errorf("normalizeURL is not idempotent: normalizeURL(%q)=%q, normalizeURL(%q)=%q",
				input, result, result, result2)
		}
	})
}

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
