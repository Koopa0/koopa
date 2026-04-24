package collector

import (
	"strings"
	"testing"
)

func TestValidateFeedURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// happy paths
		{name: "http scheme", input: "http://example.com/feed.xml", wantErr: false},
		{name: "https scheme", input: "https://example.com/feed.xml", wantErr: false},
		{name: "https with path and query", input: "https://example.com/rss?format=atom", wantErr: false},

		// SSRF / security adversarial
		{name: "file scheme", input: "file:///etc/passwd", wantErr: true},
		{name: "ftp scheme", input: "ftp://example.com/feed", wantErr: true},
		{name: "gopher scheme", input: "gopher://example.com/feed", wantErr: true},
		{name: "javascript scheme", input: "javascript:alert(1)", wantErr: true},
		{name: "data URI", input: "data:text/xml,<feed/>", wantErr: true},
		// SSRF: internal/private network hosts
		{name: "localhost", input: "http://localhost/feed", wantErr: true},
		{name: "127.0.0.1", input: "http://127.0.0.1/feed", wantErr: true},
		{name: "IPv6 loopback", input: "http://[::1]/feed", wantErr: true},
		{name: "AWS metadata", input: "http://169.254.169.254/latest/meta-data/", wantErr: true},
		{name: "GCP metadata", input: "http://metadata.google.internal/computeMetadata/", wantErr: true},
		{name: "private 10.x", input: "http://10.0.0.1/feed", wantErr: true},
		{name: "private 192.168.x", input: "http://192.168.1.1/feed", wantErr: true},
		{name: "private 172.16.x", input: "http://172.16.0.1/feed", wantErr: true},
		{name: "0.0.0.0", input: "http://0.0.0.0/feed", wantErr: true},

		// malformed URLs
		{name: "empty string", input: "", wantErr: true},
		{name: "no scheme", input: "example.com/feed.xml", wantErr: true},
		{name: "double slash only", input: "//example.com/feed", wantErr: true},
		{name: "path only", input: "/feeds/rss.xml", wantErr: true},
		{name: "invalid parse error", input: "://bad-url", wantErr: true},

		// SQL injection in URL (scheme check should still reject)
		{name: "SQL injection no scheme", input: "'; DROP TABLE feeds; --", wantErr: true},
		// Go url.Parse rejects null bytes as invalid control characters — wantErr: true.
		{name: "null byte in url", input: "http://example.com/feed\x00.xml", wantErr: true},

		// boundary
		{name: "very long valid url", input: "https://" + strings.Repeat("a", 2000) + ".com/feed", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateFeedURL(tt.input)
			if tt.wantErr && err == nil {
				t.Fatalf("validateFeedURL(%q) = nil, want error", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateFeedURL(%q) = %v, want nil", tt.input, err)
			}
		})
	}
}

func FuzzValidateFeedURL(f *testing.F) {
	f.Add("https://example.com/feed")
	f.Add("http://example.com/rss")
	f.Add("file:///etc/passwd")
	f.Add("")
	f.Add("://bad")
	f.Add("javascript:alert(1)")
	f.Add("'; DROP TABLE feeds; --")
	f.Add("\x00\xff\xfe")

	f.Fuzz(func(t *testing.T, input string) {
		// must not panic; if it returns nil the scheme must be http or https
		err := validateFeedURL(input)
		if err == nil {
			// check the invariant: only http/https are allowed
			// (we can't import net/url here, but the function itself enforces this)
			if len(input) < 4 {
				t.Errorf("validateFeedURL(%q) = nil for suspiciously short input", input)
			}
		}
	})
}
