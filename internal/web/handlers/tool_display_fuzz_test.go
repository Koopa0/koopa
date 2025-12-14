package handlers

import (
	"html"
	"strings"
	"testing"
)

// FuzzHTMLEscape tests that html.EscapeString correctly escapes XSS vectors.
// Per qa-master: Comprehensive seed corpus with 25+ attack vectors.
func FuzzHTMLEscape(f *testing.F) {
	// Basic XSS vectors
	f.Add("<script>alert('xss')</script>")
	f.Add("<img src=x onerror=alert(1)>")
	f.Add("<svg onload=alert(1)>")
	f.Add("<body onload=alert(1)>")

	// Attribute injection
	f.Add(`tool"><script>alert(1)</script>`)
	f.Add(`tool" onclick="alert(1)"`)
	f.Add(`tool' onclick='alert(1)'`)
	f.Add(`"><img src=x onerror=alert(1)>`)

	// Event handlers
	f.Add(`<div onmouseover="alert(1)">`)
	f.Add(`<input onfocus=alert(1) autofocus>`)
	f.Add(`<marquee onstart=alert(1)>`)

	// Protocol handlers
	f.Add(`javascript:alert(1)`)
	f.Add(`data:text/html,<script>alert(1)</script>`)
	f.Add(`vbscript:alert(1)`)

	// Unicode exploits - overlong encoding
	f.Add("\xc0\xbc") // Overlong < in UTF-8
	f.Add("\xc0\xbe") // Overlong > in UTF-8

	// Fullwidth characters (U+FF1C, U+FF1E)
	f.Add("\uff1c") // Fullwidth <
	f.Add("\uff1e") // Fullwidth >

	// SSE injection attempts
	f.Add("tool\ndata: injected\n\n")
	f.Add("tool\r\ndata: evil\r\n\r\n")

	// Null bytes and special chars
	f.Add("\x00null\x00byte")
	f.Add("test\x00<script>")
	f.Add("path/../../../etc/passwd")

	// HTML entities
	f.Add("&lt;script&gt;")
	f.Add("&#60;script&#62;")
	f.Add("&#x3C;script&#x3E;")

	// Mixed vectors
	f.Add(`<script>alert(String.fromCharCode(88,83,83))</script>`)
	f.Add(`<img src="x" onerror="eval(atob('YWxlcnQoMSk='))">`)

	f.Fuzz(func(t *testing.T, input string) {
		result := html.EscapeString(input)

		// Per qa-master v4: Check for raw HTML brackets in output
		// After escaping, < and > should NOT appear (replaced with &lt; &gt;)
		if strings.ContainsAny(result, "<>") {
			t.Errorf("raw HTML brackets in escaped output: input=%q result=%q", input, result)
		}

		// Check for unescaped quotes that could break attributes
		// Note: html.EscapeString escapes " but not ', so we only check "
		if strings.Contains(result, `"`) && !strings.Contains(result, `&#34;`) && !strings.Contains(result, `&quot;`) {
			// html.EscapeString uses &#34; for double quotes
			// Only fail if we have raw " without proper escaping
			if strings.Count(input, `"`) != strings.Count(result, `&#34;`) {
				t.Errorf("unescaped double quote in output: input=%q result=%q", input, result)
			}
		}

		// Check for unescaped ampersand (should be &amp;)
		// Only if original had & that isn't already an entity
		if strings.Contains(input, "&") && !strings.HasPrefix(input, "&") {
			if strings.Contains(result, "&") && !strings.Contains(result, "&amp;") &&
				!strings.Contains(result, "&lt;") && !strings.Contains(result, "&gt;") &&
				!strings.Contains(result, "&#") {
				t.Errorf("potentially unescaped ampersand: input=%q result=%q", input, result)
			}
		}
	})
}

// FuzzToolDisplayLookup tests that tool display lookup handles any input safely.
func FuzzToolDisplayLookup(f *testing.F) {
	// Known tool names
	f.Add("web_search")
	f.Add("web_fetch")
	f.Add("read_file")
	f.Add("write_file")
	f.Add("execute_command")

	// XSS in tool names
	f.Add("<script>alert(1)</script>")
	f.Add("tool\"><script>")

	// Empty and whitespace
	f.Add("")
	f.Add("   ")
	f.Add("\t\n")

	// Long strings
	f.Add(strings.Repeat("a", 1000))

	// Unicode
	f.Add("\u0000")
	f.Add("\uffff")
	f.Add("tool_\u200b_hidden") // Zero-width space

	f.Fuzz(func(t *testing.T, input string) {
		// getToolDisplay should never panic
		display := getToolDisplay(input)

		// Should always return valid display info (default if unknown)
		if display.StartMsg == "" {
			t.Errorf("empty StartMsg for input: %q", input)
		}
		if display.CompleteMsg == "" {
			t.Errorf("empty CompleteMsg for input: %q", input)
		}
		if display.ErrorMsg == "" {
			t.Errorf("empty ErrorMsg for input: %q", input)
		}

		// Messages should not contain raw HTML (they're escaped at usage site)
		// But the stored messages themselves should be safe static strings
		for _, msg := range []string{display.StartMsg, display.CompleteMsg, display.ErrorMsg} {
			if strings.ContainsAny(msg, "<>") {
				t.Errorf("display message contains HTML brackets: %q", msg)
			}
		}
	})
}

// TestHTMLEscapeKnownVectors tests specific XSS vectors are escaped correctly.
func TestHTMLEscapeKnownVectors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		mustNot  string // result must not contain this
		mustHave string // result must contain this (escaped form)
	}{
		{
			name:     "script tag",
			input:    "<script>alert(1)</script>",
			mustNot:  "<script>",
			mustHave: "&lt;script&gt;",
		},
		{
			name:     "img onerror",
			input:    `<img src=x onerror=alert(1)>`,
			mustNot:  "<img",
			mustHave: "&lt;img",
		},
		{
			name:    "attribute breakout",
			input:   `"><script>alert(1)</script>`,
			mustNot: `"><script>`,
		},
		{
			name:    "messageID injection",
			input:   `msg-123"><script>alert(1)</script>`,
			mustNot: `"><script>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := html.EscapeString(tt.input)

			if tt.mustNot != "" && strings.Contains(result, tt.mustNot) {
				t.Errorf("result contains forbidden string %q: %s", tt.mustNot, result)
			}

			if tt.mustHave != "" && !strings.Contains(result, tt.mustHave) {
				t.Errorf("result missing expected string %q: %s", tt.mustHave, result)
			}
		})
	}
}
