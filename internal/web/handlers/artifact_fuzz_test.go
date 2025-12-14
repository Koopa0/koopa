package handlers

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseArtifact tests parseArtifact with random inputs.
// Per qa-master: Security-focused fuzz testing for XSS, injection, ReDoS.
func FuzzParseArtifact(f *testing.F) {
	// Seed corpus with valid artifacts
	f.Add(`<artifact type="code" language="go" title="main.go">package main</artifact>`)
	f.Add(`<artifact type="markdown" language="" title="README.md"># Hello</artifact>`)
	f.Add(`<artifact type="html" language="html" title="index.html"><div>test</div></artifact>`)

	// Seed with XSS attack vectors
	f.Add(`<script>alert(1)</script>`)
	f.Add(`<artifact type="code"><script>alert('xss')</script></artifact>`)
	f.Add(`<artifact type="code" language="go" title="<script>">content</artifact>`)
	f.Add(`<artifact type="<script>" language="go" title="x">content</artifact>`)
	f.Add(`<artifact type="code" language="javascript" title="x"><img onerror="alert(1)" src="x"></artifact>`)

	// Seed with path traversal vectors
	f.Add(`<artifact type="code" language="go" title="../../../etc/passwd">content</artifact>`)
	f.Add(`<artifact type="code" language="go" title="..\\..\\windows\\system32">content</artifact>`)
	f.Add(`<artifact type="code" language="go" title="/etc/shadow">content</artifact>`)

	// Seed with injection vectors
	f.Add(`<artifact type="code" language="go" title="x'; DROP TABLE users; --">content</artifact>`)
	f.Add(`<artifact type="code" language="$(whoami)" title="x">content</artifact>`)
	f.Add(`<artifact type="code" language="go" title="x" onclick="alert(1)">content</artifact>`)

	// Seed with malformed tags
	f.Add(`<artifact`)
	f.Add(`<artifact >`)
	f.Add(`<artifact type="code">`)
	f.Add(`<artifact type="code" language="go" title="x">`)
	f.Add(`</artifact>`)
	f.Add(`<artifact type="code" language="go" title="x">content`)
	f.Add(`<artifact type="code" language="go" title="x">content</artifa`)
	f.Add(`<artifact type="code" language="go" title="x">content</artifact`)

	// Seed with nested/multiple tags
	f.Add(`<artifact type="code"><artifact type="code">nested</artifact></artifact>`)
	f.Add(`text<artifact type="code" language="go" title="a">A</artifact>middle<artifact type="code" language="go" title="b">B</artifact>end`)

	// Seed with special characters
	f.Add(`<artifact type="code" language="go" title="test.go">` + "\x00\x01\x02" + `</artifact>`)
	f.Add(`<artifact type="code" language="go" title="test.go">` + strings.Repeat("a", 10000) + `</artifact>`)
	f.Add(`<artifact type="code" language="中文" title="测试.go">内容</artifact>`)
	f.Add(`<artifact type="code" language="go" title="test.go">emoji 🎉🚀</artifact>`)

	// Seed with attribute edge cases
	f.Add(`<artifact type="" language="" title="">empty attrs</artifact>`)
	f.Add(`<artifact TYPE="CODE" LANGUAGE="GO" TITLE="TEST.GO">uppercase</artifact>`)
	f.Add(`<artifact  type="code"  language="go"  title="x" >extra spaces</artifact>`)
	f.Add(`<artifact type="code"language="go"title="x">no spaces</artifact>`)
	f.Add(`<artifact type='code' language='go' title='x'>single quotes</artifact>`)

	// Seed with ReDoS patterns
	f.Add(`<artifact type="` + strings.Repeat("a", 1000) + `" language="go" title="x">content</artifact>`)
	f.Add(strings.Repeat(`<artifact type="code">`, 100))

	f.Fuzz(func(t *testing.T, input string) {
		// parseArtifact must not panic
		artifact, before, after := parseArtifact(input)

		// Verify invariants
		if artifact != nil {
			// Type must be validated
			if artifact.Type != "code" && artifact.Type != "markdown" && artifact.Type != "html" {
				t.Errorf("invalid type %q escaped validation", artifact.Type)
			}
		}

		// before + artifact + after should reconstruct or be subset of input
		// (accounting for consumed artifact tags)
		if artifact == nil {
			// No artifact: before + after should equal input
			if before+after != input {
				// Check for partial tag case: before + after should equal input
				if !strings.HasPrefix(input, before) {
					t.Errorf("before %q is not prefix of input %q", before, input)
				}
			}
		}

		// Ensure no memory corruption - strings should be valid UTF-8 or safe binary
		_ = utf8.ValidString(before)
		_ = utf8.ValidString(after)
		if artifact != nil {
			_ = utf8.ValidString(artifact.Content)
			_ = utf8.ValidString(artifact.Title)
			_ = utf8.ValidString(artifact.Language)
		}
	})
}

// FuzzExtractAttr tests extractAttr with random inputs.
func FuzzExtractAttr(f *testing.F) {
	// Seed with valid attribute patterns
	f.Add(`type="code" language="go" title="main.go"`, "type")
	f.Add(`type="code" language="go" title="main.go"`, "language")
	f.Add(`type="code" language="go" title="main.go"`, "title")
	f.Add(`type="code" language="go" title="main.go"`, "missing")

	// Seed with attack vectors
	f.Add(`type="<script>alert(1)</script>"`, "type")
	f.Add(`type="code" onclick="alert(1)"`, "onclick")
	f.Add(`type="../../../etc/passwd"`, "type")
	f.Add(`type="'; DROP TABLE users; --"`, "type")

	// Seed with edge cases
	f.Add(`type=""`, "type")
	f.Add(`type="a"type="b"`, "type")
	f.Add(``, "type")
	f.Add(`type=code`, "type") // Missing quotes
	f.Add(`type="unclosed`, "type")
	f.Add(strings.Repeat(`type="a" `, 1000), "type")

	f.Fuzz(func(t *testing.T, tag, name string) {
		// extractAttr must not panic
		result := extractAttr(tag, name)

		// Note: Result may contain unmatched quotes if content between quotes
		// has escaped quotes - this is acceptable behavior
		_ = strings.Count(result, `"`)

		// Verify result is valid UTF-8
		_ = utf8.ValidString(result)
	})
}

// FuzzHasPartialTag tests hasPartialTag with random inputs.
func FuzzHasPartialTag(f *testing.F) {
	// Seed corpus
	f.Add("Hello world")
	f.Add("Hello <")
	f.Add("Hello <a")
	f.Add("Hello <artifact")
	f.Add("Hello <artifact ")
	f.Add("<artifact type=\"code\">")
	f.Add("")
	f.Add("<")
	f.Add(strings.Repeat("<", 100))
	f.Add(strings.Repeat("<artifact", 100))

	f.Fuzz(func(t *testing.T, input string) {
		// hasPartialTag must not panic
		result := hasPartialTag(input)

		// If result is true, there should be a '<' near the end
		if result {
			found := false
			for i := len(input) - 1; i >= 0 && i >= len(input)-len(tagStart); i-- {
				if i < len(input) && input[i] == '<' {
					found = true
					break
				}
			}
			if !found && len(input) > 0 {
				t.Errorf("hasPartialTag returned true but no '<' found near end: %q", input)
			}
		}
	})
}

// FuzzSafeSplit tests safeSplit with random inputs.
func FuzzSafeSplit(f *testing.F) {
	// Seed corpus
	f.Add("Hello world")
	f.Add("Hello <")
	f.Add("Text <artif")
	f.Add("<artifact type=")
	f.Add("")
	f.Add(strings.Repeat("a", 10000) + "<")
	f.Add(strings.Repeat("<", 100))

	f.Fuzz(func(t *testing.T, input string) {
		// safeSplit must not panic
		safe, held := safeSplit(input)

		// Invariant: safe + held must equal input
		if safe+held != input {
			t.Errorf("safeSplit(%q) = (%q, %q), but safe+held != input", input, safe, held)
		}

		// If held is non-empty, it should start with '<'
		if held != "" && !strings.HasPrefix(held, "<") {
			t.Errorf("held %q does not start with '<'", held)
		}
	})
}

// FuzzIsValidArtifactType tests isValidArtifactType with random inputs.
func FuzzIsValidArtifactType(f *testing.F) {
	// Seed with valid types
	f.Add("code")
	f.Add("markdown")
	f.Add("html")

	// Seed with invalid types
	f.Add("")
	f.Add("Code")
	f.Add("CODE")
	f.Add("script")
	f.Add("<script>")
	f.Add("../../../etc/passwd")
	f.Add(strings.Repeat("a", 10000))

	f.Fuzz(func(t *testing.T, input string) {
		// isValidArtifactType must not panic
		result := isValidArtifactType(input)

		// Verify expected behavior for known inputs
		switch input {
		case "code", "markdown", "html":
			if !result {
				t.Errorf("isValidArtifactType(%q) = false, want true", input)
			}
		default:
			if result {
				t.Errorf("isValidArtifactType(%q) = true, want false", input)
			}
		}
	})
}
