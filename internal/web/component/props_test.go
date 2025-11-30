package component

import (
	"strings"
	"testing"
)

func TestIsValidAvatarURL(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		valid bool
	}{
		// Valid URLs
		{"empty URL", "", true},
		{"relative URL", "/api/avatar/123", true},
		{"https URL", "https://example.com/avatar.jpg", true},
		{"http URL", "http://example.com/avatar.jpg", true},

		// XSS vectors - must be blocked
		{"javascript scheme", "javascript:alert(1)", false},
		{"javascript template literal", "javascript:alert`1`", false},
		{"data scheme", "data:text/html,<script>alert(1)</script>", false},
		{"data SVG", "data:image/svg+xml,<svg onload=alert(1)>", false},
		{"file scheme", "file:///etc/passwd", false},
		{"ftp scheme", "ftp://evil.com/malware", false},
		{"gopher scheme", "gopher://evil.com/", false},

		// SSRF vectors - localhost variants
		{"localhost", "http://localhost/admin", false},
		{"127.0.0.1", "http://127.0.0.1/admin", false},
		{"IPv6 localhost", "http://[::1]/admin", false},
		{"0.0.0.0", "http://0.0.0.0/admin", false},

		// SSRF vectors - cloud metadata
		{"AWS metadata", "http://169.254.169.254/metadata", false},
		{"AWS metadata full path", "http://169.254.169.254/latest/meta-data/", false},

		// SSRF vectors - private networks
		{"private 10.x", "http://10.0.0.1/", false},
		{"private 172.16.x", "http://172.16.0.1/", false},
		{"private 192.168.x", "http://192.168.1.1/", false},

		// Path traversal - basic
		{"path traversal", "../../../etc/passwd", false},
		{"path traversal in relative", "/images/../../../etc/passwd", false},

		// Path traversal - URL encoding bypass attempts
		{"url encoded path traversal", "/%2e%2e/%2e%2e/etc/passwd", false},
		{"url encoded dots single", "/%2e%2e/etc/passwd", false},
		{"mixed encoded traversal", "/images/%2e%2e/secret", false},
		// Double encoding: %252e%252e decodes to %2e%2e (literal string, not ..)
		// This is safe because we only decode once
		{"double encoded safe", "/%252e%252e/etc/passwd", true},
		// Note: On Unix, backslash is NOT a path separator - it's a literal character
		// So "/images\..\" is a directory named "images\..\" not traversal
		{"backslash in filename", "/images\\..\\etc\\passwd", true},

		// Path traversal - legitimate filenames with dots (should pass)
		{"filename with dots", "/images/my..image.jpg", true},
		{"version number", "/api/v1.0.0/avatar", true},
		{"ellipsis in path", "/docs/readme...txt", true},

		// DoS protection
		{"very long URL", "https://example.com/" + strings.Repeat("a", 3000), false},

		// Edge cases
		{"whitespace only", "   ", false}, // Not valid URL format
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidAvatarURL(tt.url)
			if got != tt.valid {
				t.Errorf("isValidAvatarURL(%q) = %v, want %v", tt.url, got, tt.valid)
			}
		})
	}
}

func TestGetInitials(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"", "?"},
		{"   ", "?"},         // Whitespace only
		{"Alice", "A"},       // Single name
		{"John Doe", "JD"},   // Two names
		{"John M Doe", "JD"}, // Three names (first + last)
		{"alice", "A"},       // Lowercase
		{"john doe", "JD"},   // Lowercase
		{"世界", "世"},          // Unicode single name
		{"你好 世界", "你世"},      // Unicode two names
		{"😀 Alice", "😀A"},    // Emoji + name
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getInitials(tt.name)
			if got != tt.want {
				t.Errorf("getInitials(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestButtonType_String(t *testing.T) {
	tests := []struct {
		name string
		t    ButtonType
		want string
	}{
		{"button type", ButtonTypeButton, "button"},
		{"submit type", ButtonTypeSubmit, "submit"},
		{"reset type", ButtonTypeReset, "reset"},
		{"empty default", "", "button"},
		// Invalid values - should return safe default
		{"invalid value", ButtonType("invalid"), "button"},
		{"xss attempt", ButtonType("<script>"), "button"},
		{"sql injection", ButtonType("'; DROP TABLE--"), "button"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.t.String(); got != tt.want {
				t.Errorf("ButtonType(%q).String() = %q, want %q", tt.t, got, tt.want)
			}
		})
	}
}

func TestBadgeVariant_String(t *testing.T) {
	tests := []struct {
		name string
		v    BadgeVariant
		want string
	}{
		{"default variant", BadgeVariantDefault, "default"},
		{"success variant", BadgeVariantSuccess, "success"},
		{"error variant", BadgeVariantError, "error"},
		{"warning variant", BadgeVariantWarning, "warning"},
		{"empty default", "", "default"},
		// Invalid values - should return safe default
		{"invalid value", BadgeVariant("invalid"), "default"},
		{"xss attempt", BadgeVariant("<script>"), "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.String(); got != tt.want {
				t.Errorf("BadgeVariant(%q).String() = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

func TestBadgeSize_String(t *testing.T) {
	tests := []struct {
		name string
		s    BadgeSize
		want string
	}{
		{"small size", BadgeSizeSmall, "sm"},
		{"medium size", BadgeSizeMedium, "md"},
		{"empty default", "", "sm"},
		// Invalid values - should return safe default
		{"invalid value", BadgeSize("invalid"), "sm"},
		{"large not defined", BadgeSize("lg"), "sm"},
		{"xss attempt", BadgeSize("<script>"), "sm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("BadgeSize(%q).String() = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}
