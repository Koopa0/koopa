package pipeline

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Benchmarks — hot-path pure functions
// ---------------------------------------------------------------------------

func BenchmarkIsSHA(b *testing.B) {
	valid := strings.Repeat("a", 40)
	b.ReportAllocs()
	for b.Loop() {
		isSHA(valid)
	}
}

func BenchmarkIsSHA_Invalid(b *testing.B) {
	invalid := "not-a-sha"
	b.ReportAllocs()
	for b.Loop() {
		isSHA(invalid)
	}
}

func BenchmarkFilterPublicMarkdown(b *testing.B) {
	files := []string{
		"10-Public-Content/post-1.md",
		"10-Public-Content/post-2.md",
		"01-Concepts/note.md",
		"README.md",
		"10-Public-Content/image.png",
		"99-System/template.md",
		"10-Public-Content/post-3.md",
	}
	b.ReportAllocs()
	for b.Loop() {
		filterPublicMarkdown(files)
	}
}

func BenchmarkFilterKnowledgeMarkdown(b *testing.B) {
	files := []string{
		"01-Concepts/go-slices.md",
		"02-Projects/blog.md",
		"10-Public-Content/post.md",
		"99-System/template.md",
		".obsidian/config.md",
		"README.md",
		"01-Concepts/channels.md",
	}
	b.ReportAllocs()
	for b.Loop() {
		filterKnowledgeMarkdown(files)
	}
}

func BenchmarkSlugFromPath(b *testing.B) {
	path := "10-Public-Content/my-great-post-about-go.md"
	b.ReportAllocs()
	for b.Loop() {
		slugFromPath(path)
	}
}

func BenchmarkChangedFiles(b *testing.B) {
	event := PushEvent{
		Commits: []PushCommit{
			{Added: []string{"a.md", "b.md"}, Modified: []string{"c.md"}},
			{Added: []string{"d.md"}, Modified: []string{"a.md", "e.md"}},
			{Added: []string{"f.md"}, Modified: []string{"b.md"}},
		},
	}
	b.ReportAllocs()
	for b.Loop() {
		event.ChangedFiles()
	}
}

func BenchmarkSha256Hex(b *testing.B) {
	input := strings.Repeat("hello world content body ", 100)
	b.ReportAllocs()
	for b.Loop() {
		sha256Hex(input)
	}
}

func BenchmarkNotionURLPattern(b *testing.B) {
	body := `Fixes https://notion.so/Task-aaaa1111bbbb2222cccc3333dddd4444
and also https://notion.so/workspace/Another-11112222333344445555666677778888
some text in between
closes https://www.notion.so/Third-aabbccdd11223344aabbccdd11223344`
	b.ReportAllocs()
	for b.Loop() {
		notionURLPattern.FindAllStringSubmatch(body, -1)
	}
}

// ---------------------------------------------------------------------------
// Fuzz — parsing functions must not panic on any input
// ---------------------------------------------------------------------------

func FuzzIsSHA(f *testing.F) {
	f.Add(strings.Repeat("a", 40))
	f.Add(strings.Repeat("0", 40))
	f.Add("")
	f.Add("not-a-sha")
	f.Add(strings.Repeat("g", 40))
	f.Add(strings.Repeat("A", 40))
	f.Add("\x00\x00\x00")
	f.Add("'; DROP TABLE --")

	f.Fuzz(func(t *testing.T, input string) {
		// must not panic; result is intentionally discarded
		_ = isSHA(input)
	})
}

func FuzzSlugFromPath(f *testing.F) {
	f.Add("10-Public-Content/my-post.md")
	f.Add("")
	f.Add("/")
	f.Add("..")
	f.Add("../../../etc/passwd.md")
	f.Add("dir/.md")
	f.Add("dir/post.md.md")
	f.Add("🚀/rocket.md")

	f.Fuzz(func(t *testing.T, path string) {
		// must not panic
		slugFromPath(path)
	})
}

func FuzzFilterKnowledgeMarkdown(f *testing.F) {
	f.Add("01-Concepts/go.md")
	f.Add("10-Public-Content/post.md")
	f.Add("99-System/template.md")
	f.Add("../../../etc/passwd.md")
	f.Add("")
	f.Add("README.md")
	f.Add(".obsidian/config.md")

	f.Fuzz(func(t *testing.T, file string) {
		// must not panic, single-element slice
		filterKnowledgeMarkdown([]string{file})
	})
}
