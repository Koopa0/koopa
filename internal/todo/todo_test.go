// Copyright 2026 Koopa. All rights reserved.

package todo

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestEscapeILIKE pins the per-character escape contract of escapeILIKE
// against a small set of representative inputs. escapeILIKE is used to
// build PostgreSQL ILIKE patterns from user-controlled input at three
// call sites (todo.go, views.go, history.go); a wrong escape would let
// the caller smuggle ILIKE wildcards into the pattern, broadening the
// match silently.
//
// The contract: in the output, the only escape sequences reachable by
// an ILIKE engine with default ESCAPE '\' are \\ (literal \), \%
// (literal %), \_ (literal _). Every other byte passes through as-is.
// FuzzEscapeILIKE asserts the formal round-trip version of this
// contract; this test pins explicit expected outputs for representative
// inputs.
func TestEscapeILIKE(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "plain ascii", input: "hello", want: "hello"},
		{name: "ascii with space", input: "hello world", want: "hello world"},
		{name: "single percent", input: "%", want: `\%`},
		{name: "single underscore", input: "_", want: `\_`},
		{name: "single backslash", input: `\`, want: `\\`},
		{name: "three percents", input: "%%%", want: `\%\%\%`},
		{name: "three underscores", input: "___", want: `\_\_\_`},
		{name: "two backslashes", input: `\\`, want: `\\\\`},
		{name: "percent then underscore", input: "%_", want: `\%\_`},
		{name: "all three specials", input: `%_\`, want: `\%\_\\`},
		{name: "percent inside text", input: "50% off", want: `50\% off`},
		{name: "underscore inside text", input: "snake_case", want: `snake\_case`},
		{name: "backslash inside text", input: `a\b`, want: `a\\b`},
		{name: "unicode passthrough", input: "你好世界", want: "你好世界"},
		{name: "unicode with percent", input: "你好%", want: `你好\%`},
		{name: "nul byte unchanged", input: "ab\x00cd", want: "ab\x00cd"},
		{name: "already-escaped percent (caller mistake)", input: `\%`, want: `\\\%`},
		{name: "sql injection attempt is just text", input: `'; DROP TABLE--`, want: `'; DROP TABLE--`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := escapeILIKE(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("escapeILIKE(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// TestValidState pins the todo_state enum membership check that guards
// the list handler's state filter: every enum value passes, everything
// else (including near-misses and casing) fails so the handler returns
// 400 instead of letting PostgreSQL reject the cast as a 500.
func TestValidState(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "inbox", input: "inbox", want: true},
		{name: "todo", input: "todo", want: true},
		{name: "in_progress", input: "in_progress", want: true},
		{name: "done", input: "done", want: true},
		{name: "someday", input: "someday", want: true},
		{name: "empty", input: "", want: false},
		{name: "unknown", input: "bogus", want: false},
		{name: "hyphenated near-miss", input: "in-progress", want: false},
		{name: "uppercase", input: "DONE", want: false},
		{name: "whitespace padded", input: " todo", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validState(tt.input); got != tt.want {
				t.Errorf("validState(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// decodeILIKE is the inverse of escapeILIKE: it consumes a
// backslash-escaped ILIKE pattern (default ESCAPE '\') and returns the
// literal string an ILIKE engine would match against. Used only by
// FuzzEscapeILIKE to assert round-trip: decode(escape(s)) == s for any
// byte string s.
//
// This is intentionally NOT a re-implementation of escapeILIKE. It
// walks the OUTPUT and decodes the three valid escape pairs (\\, \%,
// \_); any other byte (including a lone trailing backslash, which
// escapeILIKE must never emit) passes through unchanged. If
// escapeILIKE ever emits a malformed sequence, decodeILIKE will
// produce different output than the original input — which the fuzz
// invariant catches.
func decodeILIKE(escaped string) string {
	var b strings.Builder
	b.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '\\' && i+1 < len(escaped) {
			switch escaped[i+1] {
			case '\\', '%', '_':
				b.WriteByte(escaped[i+1])
				i++
				continue
			}
		}
		b.WriteByte(escaped[i])
	}
	return b.String()
}

// FuzzEscapeILIKE asserts the safety properties of escapeILIKE on
// arbitrary byte inputs:
//
//  1. No panic on any input (implicit — Go fuzz fails the corpus entry
//     on panic).
//  2. Round-trip: decodeILIKE(escapeILIKE(s)) == s. This is the formal
//     version of "the escape is reversible by an ILIKE engine with
//     default ESCAPE '\\'".
//  3. No orphan backslash and no unescaped wildcard. Every '\\' byte in
//     the output is followed by exactly one of '\\', '%', or '_'.
//     Equivalently, no '%' or '_' byte appears un-preceded by a '\\'.
//     This is the security-relevant invariant — an orphan '%' or '_'
//     would let user input introduce an ILIKE wildcard.
//
// The fuzz target does NOT re-implement escapeILIKE: the round-trip
// uses the inverse mapping (decodeILIKE), and the orphan check is a
// scan invariant, not an alternate encoder.
func FuzzEscapeILIKE(f *testing.F) {
	// Seed corpus mirrors the table-driven cases so the fuzz lane
	// exercises representative inputs before drifting into random bytes.
	seeds := []string{
		"", "hello", "hello world",
		"%", "_", `\`,
		"%%%", "___", `\\`, "%_", `%_\`,
		"50% off", "snake_case", `a\b`,
		"你好世界", "你好%", "ab\x00cd", `\%`,
		`'; DROP TABLE--`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := escapeILIKE(s)

		// Property 2: round-trip via the inverse decoder.
		if back := decodeILIKE(got); back != s {
			t.Errorf("decodeILIKE(escapeILIKE(%q)) = %q, want %q", s, back, s)
		}

		// Property 3: no orphan backslash, no unescaped wildcard.
		// Walk the output once; a '\' MUST be followed by one of
		// '\', '%', '_'. A bare '%' or '_' (not preceded by '\') is
		// the wildcard-injection failure mode.
		for i := 0; i < len(got); i++ {
			c := got[i]
			switch c {
			case '\\':
				if i+1 >= len(got) {
					t.Errorf("orphan trailing backslash in escapeILIKE(%q) = %q", s, got)
					return
				}
				next := got[i+1]
				if next != '\\' && next != '%' && next != '_' {
					t.Errorf("invalid escape sequence %q at byte %d in escapeILIKE(%q) = %q",
						`\`+string(next), i, s, got)
					return
				}
				i++ // skip the escaped char so we don't re-evaluate it
			case '%', '_':
				t.Errorf("unescaped %q at byte %d in escapeILIKE(%q) = %q", string(c), i, s, got)
				return
			}
		}
	})
}
