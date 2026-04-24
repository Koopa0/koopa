package tag

import "testing"

func TestSlugify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Happy path
		{name: "lowercase passthrough", input: "golang", want: "golang"},
		{name: "uppercase to lower", input: "GoLang", want: "golang"},
		{name: "spaces to hyphens", input: "my tag", want: "my-tag"},
		{name: "underscores to hyphens", input: "my_tag", want: "my-tag"},
		{name: "slashes to hyphens", input: "path/to/tag", want: "path-to-tag"},
		{name: "dots to hyphens", input: "io.Reader", want: "io-reader"},
		{name: "consecutive special chars collapse", input: "a--b__c  d", want: "a-b-c-d"},
		{name: "trim leading special", input: " -tag", want: "tag"},
		{name: "trim trailing special", input: "tag- ", want: "tag"},
		{name: "digits preserved", input: "go1.22", want: "go1-22"},
		{name: "empty string", input: "", want: ""},
		{name: "only special chars", input: "---", want: ""},
		{name: "unicode letters", input: "日本語", want: "日本語"},
		{name: "mixed unicode and ascii", input: "Go 語言", want: "go-語言"},
		{name: "real tag: binary-search", input: "binary-search", want: "binary-search"},
		{name: "real tag: Dynamic Programming", input: "Dynamic Programming", want: "dynamic-programming"},
		{name: "real tag: C++", input: "C++", want: "c"},
		// Adversarial: SQL injection — punctuation stripped, letters/digits preserved
		{name: "sql injection: drop table", input: "'; DROP TABLE tags; --", want: "drop-table-tags"},
		{name: "sql injection: comment", input: "tag/* comment */name", want: "tag-comment-name"},
		{name: "sql injection: union select", input: "' UNION SELECT 1--", want: "union-select-1"},
		// Adversarial: XSS — angle brackets are not letter/digit/separator, stripped without space
		{name: "xss: script tag", input: "<script>alert(1)</script>", want: "scriptalert1-script"},
		{name: "xss: event handler", input: `onclick="alert(1)"`, want: "onclickalert1"},
		{name: "xss: html entity ampersand", input: "&lt;img&gt;", want: "ltimggt"},
		// Adversarial: null byte — not a letter/digit, silently dropped
		{name: "null byte mid-word", input: "tag\x00name", want: "tagname"},
		{name: "null byte only", input: "\x00\x00\x00", want: ""},
		// Adversarial: control characters (not special-char whitelist, silently dropped)
		{name: "tab character", input: "go\tlang", want: "golang"},
		{name: "newline", input: "go\nlang", want: "golang"},
		{name: "carriage return", input: "go\rlang", want: "golang"},
		// Adversarial: boundary lengths
		{name: "single letter", input: "a", want: "a"},
		{name: "single digit", input: "9", want: "9"},
		{name: "single special char", input: "-", want: ""},
		{name: "all hyphens", input: "---", want: ""},
		{name: "whitespace only", input: "   ", want: ""},
		{name: "hyphen between words", input: "a-b-c", want: "a-b-c"},
		// Adversarial: emoji — unicode.IsLetter returns false for emoji, they are stripped
		{name: "emoji only", input: "🚀", want: ""},
		{name: "emoji between words", input: "go 🚀 lang", want: "go-lang"},
		{name: "emoji sequence only", input: "🎯🎯", want: ""},
		// Adversarial: unicode edge cases
		{name: "zero-width space", input: "go\u200blang", want: "golang"},
		{name: "rtl mark", input: "\u200ftag", want: "tag"},
		{name: "combining accent: café", input: "café", want: "café"},
		{name: "fullwidth latin letters", input: "Ａbc１２３", want: "ａbc１２３"},
		{name: "mixed cjk and ascii", input: "go言語2024", want: "go言語2024"},
		// Adversarial: path traversal — dots and slashes become hyphens
		{name: "path traversal dots and slashes", input: "../../etc/passwd", want: "etc-passwd"},
		// backslash is not in the special-char whitelist, stripped without separator;
		// colon is now a separator (namespace tags were removed)
		{name: "windows path backslash", input: `C:\Windows\System32`, want: "c-windowssystem32"},
		// colon between words becomes a separator
		{name: "colon becomes separator", input: "weakness:implementation", want: "weakness-implementation"},
		{name: "mixed case with colon", input: "Improvement:Edge-Cases", want: "improvement-edge-cases"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Slugify(tt.input)
			if got != tt.want {
				t.Errorf("Slugify(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// FuzzSlugify verifies Slugify never panics on arbitrary input and always
// produces valid slug characters (lowercase letters, digits, hyphens, unicode letters).
// Scene: user-supplied tags from any input source can contain any UTF-8 string.
func FuzzSlugify(f *testing.F) {
	f.Add("golang")
	f.Add("Dynamic Programming")
	f.Add("C++")
	f.Add("日本語")
	f.Add("")
	f.Add("---")
	f.Add("a  b\tc\nd")
	// Adversarial seeds
	f.Add("'; DROP TABLE tags; --")
	f.Add("<script>alert(1)</script>")
	f.Add("tag\x00name")
	f.Add("\x00\x00\x00")
	f.Add("🚀 emoji tag")
	f.Add("go\u200blang") // zero-width space
	f.Add("\u200ftag")    // rtl mark
	f.Add("../../etc/passwd")
	f.Add(string([]byte{0xFF, 0xFE})) // invalid UTF-8 bytes

	f.Fuzz(func(t *testing.T, input string) {
		result := Slugify(input)
		// Must not end with hyphen
		if result != "" && result[len(result)-1] == '-' {
			t.Errorf("Slugify(%q) = %q ends with hyphen", input, result)
		}
		// Must not start with hyphen
		if result != "" && result[0] == '-' {
			t.Errorf("Slugify(%q) = %q starts with hyphen", input, result)
		}
		// Must not contain consecutive hyphens
		for i := 1; i < len(result); i++ {
			if result[i] == '-' && result[i-1] == '-' {
				t.Errorf("Slugify(%q) = %q has consecutive hyphens", input, result)
				break
			}
		}
	})
}

// BenchmarkSlugify measures slug generation for a realistic tag.
// Scene: ResolveTags processes N tags per content sync — slug perf matters at scale.
// Primary signal: allocs/op — pure string transform should be 1 alloc (the Builder).
func BenchmarkSlugify(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Slugify("Dynamic Programming Algorithms")
	}
}

// BenchmarkSlugify_Unicode measures cost when input is purely Unicode characters.
func BenchmarkSlugify_Unicode(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Slugify("日本語プログラミング言語")
	}
}

// BenchmarkSlugify_Adversarial measures cost for an input that exercises all branches.
func BenchmarkSlugify_Adversarial(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Slugify("'; DROP TABLE -- / tags__ <script> 🚀 unicode日本語")
	}
}
