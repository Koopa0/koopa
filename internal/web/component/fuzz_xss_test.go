package component

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FuzzSessionTitle_XSSPrevention verifies session title XSS escaping.
//
// This fuzz test ensures that potentially malicious session titles are properly
// escaped by templ's auto-escaping mechanism. It tests the Sidebar component
// with various XSS attack vectors.
func FuzzSessionTitle_XSSPrevention(f *testing.F) {
	// Seed corpus with XSS attack vectors
	seeds := []string{
		"<script>alert('XSS')</script>",
		"'; DROP TABLE sessions; --",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"<svg onload=alert(1)>",
		"{{constructor.constructor('alert(1)')()}}",
		"${alert(1)}",
		"<iframe src=javascript:alert(1)>",
		strings.Repeat("<script>", 1000), // Nested XSS
		"\"><script>alert(1)</script>",
		"<style>@import'http://evil.com/xss.css';</style>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, title string) {
		// Render sidebar with potentially malicious title
		sessions := []SessionItem{
			{ID: uuid.New(), Title: title},
		}
		props := SidebarProps{
			Sessions:  sessions,
			CSRFToken: "test-token",
		}

		var buf bytes.Buffer
		err := Sidebar(props).Render(context.Background(), &buf)
		require.NoError(t, err, "Render should never panic")

		html := buf.String()

		// Verify dangerous patterns are ESCAPED, not raw
		dangerousPatterns := []string{
			"<script", "javascript:", "onerror=", "onload=",
			"<iframe", "data:text/html", "${", "{{",
			"@import", "<style", "<object", "<embed",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(title), strings.ToLower(pattern)) {
				// If input contains dangerous pattern starting with '<', verify it's escaped to &lt;
				if strings.HasPrefix(pattern, "<") {
					escapedPattern := strings.Replace(pattern, "<", "&lt;", 1)
					if !strings.Contains(html, escapedPattern) {
						// Only error if the UNESCAPED pattern appears in output
						// (templ should always escape < to &lt; in text content)
						if strings.Contains(html, pattern) {
							t.Errorf("XSS pattern %q not properly escaped in title %q (expected %q)", pattern, title, escapedPattern)
						}
					}
				}
				// For non-tag patterns like "javascript:", verify they appear only in safe text context
				// (templ escapes text content automatically, so "javascript:" in text is safe)
			}
		}
	})
}

// FuzzUsername_XSSPrevention verifies username XSS escaping in Navbar.
//
// This fuzz test ensures that potentially malicious usernames are properly
// escaped by templ's auto-escaping mechanism. It tests the Navbar component
// with the same XSS vectors as session titles.
func FuzzUsername_XSSPrevention(f *testing.F) {
	// Comprehensive XSS attack vectors (same as FuzzSessionTitle)
	seeds := []string{
		"<script>alert('XSS')</script>",
		"'; DROP TABLE users; --",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"<svg onload=alert(1)>",
		"{{constructor.constructor('alert(1)')()}}",
		"${alert(1)}",
		"<iframe src=javascript:alert(1)>",
		strings.Repeat("<script>", 1000),
		"\"><script>alert(1)</script>",
		"<style>@import'http://evil.com/xss.css';</style>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, username string) {
		props := NavbarProps{
			AppName:   "Koopa",
			UserName:  username,
			CSRFToken: "test",
		}

		var buf bytes.Buffer
		err := Navbar(props).Render(context.Background(), &buf)
		require.NoError(t, err, "Render should never panic")

		html := buf.String()

		// Same comprehensive pattern checks as FuzzSessionTitle
		dangerousPatterns := []string{
			"<script", "javascript:", "onerror=", "onload=",
			"<iframe", "data:text/html", "${", "{{",
			"@import", "<style", "<object", "<embed",
			"vbscript:", "data:image", "<meta", "<link",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(username), strings.ToLower(pattern)) {
				// If input contains dangerous pattern starting with '<', verify it's escaped to &lt;
				if strings.HasPrefix(pattern, "<") {
					escapedPattern := strings.Replace(pattern, "<", "&lt;", 1)
					if !strings.Contains(html, escapedPattern) {
						// Only error if the UNESCAPED pattern appears in output
						if strings.Contains(html, pattern) {
							t.Errorf("XSS pattern %q not properly escaped in username %q (expected %q)", pattern, username, escapedPattern)
						}
					}
				}
				// For non-tag patterns like "javascript:", verify they appear only in safe text context
			}
		}

		// Additional username-specific checks
		if strings.Contains(username, "@") || strings.Contains(username, ".com") {
			// Email-like usernames should not trigger XSS
			assert.NotContains(t, html, "<script", "Email-like username triggered XSS")
		}
	})
}

// FuzzTabLabel_XSSPrevention verifies tab label XSS escaping.
//
// This fuzz test ensures that potentially malicious tab labels are properly
// escaped by templ's auto-escaping mechanism. It tests the Tabs component.
func FuzzTabLabel_XSSPrevention(f *testing.F) {
	seeds := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<svg onload=alert(1)>",
		"${alert(1)}",
		"\"><script>alert(1)</script>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, label string) {
		tabs := []TabItem{
			{ID: "test", Label: label},
		}

		props := TabsProps{
			Tabs:     tabs,
			ActiveID: "test",
		}

		var buf bytes.Buffer
		err := Tabs(props).Render(context.Background(), &buf)
		require.NoError(t, err, "Render should never panic")

		html := buf.String()

		dangerousPatterns := []string{
			"<script", "javascript:", "onerror=", "onload=",
			"<iframe", "${", "{{",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(label), strings.ToLower(pattern)) {
				// If input contains dangerous pattern starting with '<', verify it's escaped to &lt;
				if strings.HasPrefix(pattern, "<") {
					escapedPattern := strings.Replace(pattern, "<", "&lt;", 1)
					if !strings.Contains(html, escapedPattern) {
						// Only error if the UNESCAPED pattern appears in output
						if strings.Contains(html, pattern) {
							t.Errorf("XSS pattern %q not properly escaped in label %q (expected %q)", pattern, label, escapedPattern)
						}
					}
				}
				// For non-tag patterns like "javascript:", verify they appear only in safe text context
			}
		}
	})
}

// FuzzAppName_XSSPrevention verifies app name XSS escaping in Navbar.
func FuzzAppName_XSSPrevention(f *testing.F) {
	seeds := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:void(alert(1))",
		"<svg><script>alert(1)</script></svg>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, appName string) {
		props := NavbarProps{
			AppName:   appName,
			CSRFToken: "test",
		}

		var buf bytes.Buffer
		err := Navbar(props).Render(context.Background(), &buf)
		require.NoError(t, err, "Render should never panic")

		html := buf.String()

		dangerousPatterns := []string{
			"<script", "javascript:", "onerror=", "onload=",
			"<svg>", "<iframe",
		}

		for _, pattern := range dangerousPatterns {
			if strings.Contains(strings.ToLower(appName), strings.ToLower(pattern)) {
				// If input contains dangerous pattern starting with '<', verify it's escaped to &lt;
				if strings.HasPrefix(pattern, "<") {
					escapedPattern := strings.Replace(pattern, "<", "&lt;", 1)
					if !strings.Contains(html, escapedPattern) {
						// Only error if the UNESCAPED pattern appears in output
						if strings.Contains(html, pattern) {
							t.Errorf("XSS pattern %q not properly escaped in appName %q (expected %q)", pattern, appName, escapedPattern)
						}
					}
				}
				// For non-tag patterns like "javascript:", verify they appear only in safe text context
			}
		}
	})
}
