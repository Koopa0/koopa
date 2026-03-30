package obsidian

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fuzz — all parsing functions must not panic on any input
// ---------------------------------------------------------------------------

func FuzzParse(f *testing.F) {
	f.Add([]byte("---\ntitle: Test\ntags: [golang]\npublished: true\n---\nBody content"))
	f.Add([]byte("---\n---\n"))
	f.Add([]byte("no frontmatter"))
	f.Add([]byte(""))
	f.Add([]byte("---\ntitle: '\n---\n"))     // invalid YAML
	f.Add([]byte("---\n\x00\x00\x00\n---\n")) // null bytes
	f.Add([]byte("---\ntitle: \"'; DROP TABLE --\"\ntags: [\"<script>alert(1)</script>\"]\n---\nBody"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// must not panic
		_, _, _ = Parse(raw)
	})
}

func FuzzParseKnowledge(f *testing.F) {
	f.Add([]byte("---\ntitle: Note\ntype: til\ntags: [go]\n---\nContent"))
	f.Add([]byte("---\ntype: leetcode\nleetcode_id: 42\ndifficulty: hard\n---\n"))
	f.Add([]byte("---\n---\n"))
	f.Add([]byte(""))
	f.Add([]byte("---\nleetcode_id: 999999999999\n---\n"))
	f.Add([]byte("---\ncreated: not-a-date\n---\n"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// must not panic
		_, _, _ = ParseKnowledge(raw)
	})
}

func FuzzParseWikilinks(f *testing.F) {
	f.Add("Hello [[World]] and [[Path|Display]]")
	f.Add("```code\n[[not a link]]\n```")
	f.Add("[[]]")
	f.Add("")
	f.Add("[[nested [[inner]]]]")
	f.Add(strings.Repeat("[[", 1000))
	f.Add("[[path with\nnewline]]")
	f.Add("[['; DROP TABLE --]]")

	f.Fuzz(func(t *testing.T, content string) {
		// must not panic
		_ = ParseWikilinks(content)
	})
}

func FuzzSplitCamelCase(f *testing.F) {
	f.Add("HTTPSRedirect")
	f.Add("OAuth2Client")
	f.Add("io.Reader")
	f.Add("DDIA_Ch8")
	f.Add("[]string")
	f.Add("map[string]interface{}")
	f.Add("[[wikilink]]")
	f.Add("")
	f.Add(strings.Repeat("A", 10000))
	f.Add("中文CamelCase混合")

	f.Fuzz(func(t *testing.T, s string) {
		// must not panic
		_ = SplitCamelCase(s)
	})
}

func FuzzClassifyTags(f *testing.F) {
	f.Add("type/article")
	f.Add("status/draft")
	f.Add("golang/memory")
	f.Add("docker")
	f.Add("")
	f.Add("type/'; DROP TABLE")
	f.Add("///")

	f.Fuzz(func(t *testing.T, tag string) {
		// must not panic
		_, _, _ = classifyTags([]string{tag})
	})
}

// ---------------------------------------------------------------------------
// Benchmarks — hot-path parsing functions
// ---------------------------------------------------------------------------

func BenchmarkParse(b *testing.B) {
	raw := []byte("---\ntitle: Go Memory Management\ntags: [golang/memory, type/article, status/published]\npublished: true\ncreated: 2025-01-15\n---\n# Go Memory Management\n\nThis is a comprehensive guide to memory management in Go.\n")
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = Parse(raw)
	}
}

func BenchmarkParseKnowledge(b *testing.B) {
	raw := []byte("---\ntitle: Two Sum\ntype: leetcode\nleetcode_id: 1\ndifficulty: easy\ntags: [array, hash-table]\ncreated: 2025-01-15\n---\n# Two Sum\n\nSolution using hash map.\n")
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = ParseKnowledge(raw)
	}
}

func BenchmarkParseWikilinks(b *testing.B) {
	content := "This note references [[Go Concurrency]], [[Channels|Go Channels]], and [[sync.Mutex]].\nAlso see [[HTTP Server]] for examples.\n```go\n// not a link: [[ignored]]\n```\n"
	b.ReportAllocs()
	for b.Loop() {
		_ = ParseWikilinks(content)
	}
}

func BenchmarkSplitCamelCase(b *testing.B) {
	input := "HTTPSRedirectHandler.OAuth2Client_DDIA_Ch8 [[wikilink|display]] map[string]interface{}"
	b.ReportAllocs()
	for b.Loop() {
		_ = SplitCamelCase(input)
	}
}

func BenchmarkClassifyTags(b *testing.B) {
	tags := []string{"type/article", "status/published", "golang/memory", "golang/gc", "docker", "kubernetes"}
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = classifyTags(tags)
	}
}
