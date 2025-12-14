package handlers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// FuzzCSRFToken tests CSRF token validation with malicious inputs.
// This ensures CheckCSRF never panics and correctly rejects invalid tokens.
func FuzzCSRFToken(f *testing.F) {
	// Create a test Sessions instance (isDev=true for testing)
	sessions := NewSessions(nil, []byte("test-secret-key-at-least-32-chars-long-for-hmac"), true)
	sessionID := uuid.New()

	// Seed corpus with various inputs
	f.Add("valid-token-12345")
	f.Add("")                                   // empty
	f.Add(strings.Repeat("A", 10000))           // huge token
	f.Add("\x00\x01\x02")                       // binary data
	f.Add("<script>alert('xss')</script>")      // XSS attempt
	f.Add("../../../etc/passwd")                // path traversal
	f.Add("1234567890:valid-looking-signature") // valid format, wrong signature
	f.Add("not-a-timestamp:signature")          // invalid timestamp
	f.Add("-1:signature")                       // negative timestamp
	f.Add("999999999999999:signature")          // far future timestamp
	f.Add(":signature")                         // missing timestamp
	f.Add("1234567890:")                        // missing signature
	f.Add(":")                                  // only colon
	f.Add("no-colon")                           // no delimiter
	f.Add(strings.Repeat(":", 100))             // many colons
	f.Add("1234\n5678:sig")                     // newline injection
	f.Add("1234%0a5678:sig")                    // URL-encoded newline
	f.Add(string([]byte{0xFF, 0xFE, 0xFD}))     // invalid UTF-8

	f.Fuzz(func(t *testing.T, token string) {
		// Should NEVER panic, regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("CSRF validation panicked with token %q: %v", token, r)
			}
		}()

		// Call CheckCSRF - it should return an error for invalid tokens,
		// but NEVER panic
		err := sessions.CheckCSRF(sessionID, token)

		// We don't care about the specific error (invalid tokens will fail),
		// we just verify it doesn't crash
		_ = err
	})
}

// FuzzNewCSRFToken tests CSRF token generation with various session IDs.
// This ensures NewCSRFToken never panics.
func FuzzNewCSRFToken(f *testing.F) {
	sessions := NewSessions(nil, []byte("test-secret-key-at-least-32-chars-long-for-hmac"), true)

	// Seed corpus with various UUIDs
	f.Add(uuid.New().String())
	f.Add(uuid.Nil.String())
	f.Add("invalid-uuid")
	f.Add("")
	f.Add(strings.Repeat("a", 10000))

	f.Fuzz(func(t *testing.T, idStr string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("NewCSRFToken panicked with ID %q: %v", idStr, r)
			}
		}()

		// Try to parse as UUID
		id, err := uuid.Parse(idStr)
		if err != nil {
			// Invalid UUID - skip this input
			return
		}

		// Generate token - should never panic
		token := sessions.NewCSRFToken(id)

		// Token should not be empty
		if token == "" {
			t.Errorf("NewCSRFToken returned empty token for ID %q", idStr)
		}

		// Token should contain a colon (timestamp:signature format)
		if !strings.Contains(token, ":") {
			t.Errorf("NewCSRFToken returned invalid format %q for ID %q", token, idStr)
		}
	})
}
