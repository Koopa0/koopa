// Copyright 2026 Koopa. All rights reserved.

package collector

import (
	"testing"
	"unicode/utf8"
)

// FuzzTruncateUTF8 asserts the invariants that make the feed-content cut safe:
// the result never exceeds the byte cap, never turns valid UTF-8 input into
// invalid UTF-8, is always a prefix of the input, and never panics.
func FuzzTruncateUTF8(f *testing.F) {
	f.Add("", 0)
	f.Add("hello", 3)
	f.Add("héllo", 2) // cut inside the 2-byte é
	f.Add("世界", 1)    // cut inside the 3-byte 世
	f.Add("a世b", 2)
	f.Add("tail 😀 here", 6)
	f.Add("plain ascii content", 5000)
	f.Add("anything", -1)

	f.Fuzz(func(t *testing.T, s string, maxBytes int) {
		got := truncateUTF8(s, maxBytes)

		if maxBytes <= 0 {
			if got != "" {
				t.Fatalf("truncateUTF8(%q, %d) = %q, want empty for non-positive max", s, maxBytes, got)
			}
			return
		}
		if len(got) > maxBytes {
			t.Fatalf("truncateUTF8(%q, %d) len = %d, want <= %d", s, maxBytes, len(got), maxBytes)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("truncateUTF8(%q, %d) = %q is invalid UTF-8 from a valid input", s, maxBytes, got)
		}
		if s[:len(got)] != got {
			t.Fatalf("truncateUTF8(%q, %d) = %q is not a prefix of the input", s, maxBytes, got)
		}
	})
}
