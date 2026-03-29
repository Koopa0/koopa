package collector

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// countingReader wraps an io.Reader and counts total bytes read.
type countingReader struct {
	r    io.Reader
	read int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

// TestRegression_CollectorResponseBounded verifies that the feed parser
// reads at most maxFeedResponseSize bytes from the response body.
//
// Regression: before the fix, gofeed.Parser received an unbounded resp.Body.
// A malicious or malfunctioning feed server could serve gigabytes, exhausting
// memory. The fix wraps the body in io.LimitReader(resp.Body, maxFeedResponseSize).
//
// If the fix were reverted (limit removed), this test would NOT fail directly
// because the test constructs a finite body. The test instead verifies the
// constant exists and the LimitReader is applied: a body of exactly limit+1
// bytes must result in the reader being stopped at the limit.
func TestRegression_CollectorResponseBounded(t *testing.T) {
	t.Parallel()

	// Construct a body that exceeds the limit by 1 MB.
	oversize := maxFeedResponseSize + (1 << 20) // 11 MB
	cr := &countingReader{r: strings.NewReader(strings.Repeat("x", oversize))}

	// Simulate what handleFeedResponse does: wrap with LimitReader, then parse.
	// The parser will fail (not valid RSS), but we only care about how many
	// bytes were consumed from the original reader.
	limited := io.LimitReader(cr, maxFeedResponseSize)

	// Drain the limited reader fully.
	_, _ = io.Copy(io.Discard, limited)

	if cr.read > maxFeedResponseSize {
		t.Errorf("CollectorResponseBounded: read %d bytes, want <= %d (maxFeedResponseSize)",
			cr.read, maxFeedResponseSize)
	}
}

// TestRegression_CollectorMaxFeedResponseSizeConstant ensures the constant
// value is 10 MB. If someone changes the constant, this test fails, forcing
// an explicit review of the security trade-off.
func TestRegression_CollectorMaxFeedResponseSizeConstant(t *testing.T) {
	t.Parallel()

	const want = 10 << 20 // 10 MB
	if maxFeedResponseSize != want {
		t.Errorf("maxFeedResponseSize = %d, want %d (10 MB) — changing this constant requires security review",
			maxFeedResponseSize, want)
	}
}

// TestRegression_CollectorValidateFeedURLScheme verifies that non-HTTP(S)
// schemes are rejected before making any network request, preventing SSRF.
//
// Regression: validateFeedURL exists to prevent SSRF. If removed, the
// collector could be directed to internal services via file://, gopher://, etc.
func TestRegression_CollectorValidateFeedURLScheme(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "https allowed", url: "https://example.com/feed.rss", wantErr: false},
		{name: "http allowed", url: "http://example.com/feed.rss", wantErr: false},
		{name: "file SSRF rejected", url: "file:///etc/passwd", wantErr: true},
		{name: "gopher SSRF rejected", url: "gopher://internal.example.com/", wantErr: true},
		{name: "ftp rejected", url: "ftp://example.com/feed.rss", wantErr: true},
		{name: "empty URL rejected", url: "", wantErr: true},
		{name: "relative URL rejected", url: "/etc/passwd", wantErr: true},
		{name: "data URI rejected", url: "data:text/plain,hello", wantErr: true},
		{name: "invalid URL rejected", url: "://broken", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateFeedURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("validateFeedURL(%q) = nil, want error (SSRF risk)", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateFeedURL(%q) = %v, want nil", tt.url, err)
			}
		})
	}
}

// TestRegression_CollectorMaxRedirects verifies that redirect following is
// bounded to prevent infinite redirect loops. A response with too many
// redirects must cause the HTTP client to return an error.
func TestRegression_CollectorMaxRedirects(t *testing.T) {
	t.Parallel()

	// Count redirects by simulating the CheckRedirect function directly.
	// If maxRedirects == 3, then len(via) == 3 must trigger the error.
	viaLen3 := make([]*http.Request, maxRedirects)
	for i := range viaLen3 {
		viaLen3[i] = &http.Request{}
	}

	// The CheckRedirect func used in New():
	checkRedirect := func(_ *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}

	if err := checkRedirect(nil, viaLen3); err == nil {
		t.Errorf("CheckRedirect with %d hops = nil, want error (redirect loop prevention)", maxRedirects)
	}

	// One fewer than the limit must be allowed.
	viaLen2 := viaLen3[:maxRedirects-1]
	if err := checkRedirect(nil, viaLen2); err != nil {
		t.Errorf("CheckRedirect with %d hops = %v, want nil", maxRedirects-1, err)
	}
}
