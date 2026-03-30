package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// ---------------------------------------------------------------------------
// isSHA — unit + adversarial + boundary
// ---------------------------------------------------------------------------

func TestIsSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// happy path
		{name: "valid lowercase SHA", input: "a" + strings.Repeat("0", 39), want: true},
		{name: "all zeros", input: strings.Repeat("0", 40), want: true},
		{name: "all f", input: strings.Repeat("f", 40), want: true},
		{name: "mixed hex", input: "abc123def456789012345678901234567890abcd", want: true},

		// boundary: length
		{name: "39 chars", input: strings.Repeat("a", 39), want: false},
		{name: "41 chars", input: strings.Repeat("a", 41), want: false},
		{name: "empty string", input: "", want: false},
		{name: "single char", input: "a", want: false},

		// adversarial: non-hex chars
		{name: "uppercase hex", input: strings.Repeat("A", 40), want: false},
		{name: "mixed case", input: "A" + strings.Repeat("0", 39), want: false},
		{name: "contains g", input: "g" + strings.Repeat("0", 39), want: false},
		{name: "contains space", input: " " + strings.Repeat("0", 39), want: false},
		{name: "contains newline", input: strings.Repeat("0", 39) + "\n", want: false},
		{name: "contains null byte", input: strings.Repeat("0", 39) + "\x00", want: false},
		{name: "unicode disguise", input: strings.Repeat("0", 39) + "а", want: false}, // Cyrillic 'а'
		{name: "SQL injection", input: "'; DROP TABLE contents; --          ", want: false},
		{name: "emoji 40 bytes", input: strings.Repeat("😀", 10), want: false},

		// real-world
		{name: "zeroSHA constant", input: zeroSHA, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isSHA(tt.input)
			if got != tt.want {
				t.Errorf("isSHA(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// filterKnowledgeMarkdown — unit + adversarial (path traversal) + boundary
// ---------------------------------------------------------------------------

func TestFilterKnowledgeMarkdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		// happy path
		{
			name:  "normal knowledge files",
			files: []string{"01-Concepts/go-slices.md", "02-Projects/blog.md"},
			want:  []string{"01-Concepts/go-slices.md", "02-Projects/blog.md"},
		},
		{
			name:  "deeply nested",
			files: []string{"01-Concepts/golang/concurrency/channels.md"},
			want:  []string{"01-Concepts/golang/concurrency/channels.md"},
		},

		// excluded directories
		{
			name:  "excludes 10-Public-Content",
			files: []string{"10-Public-Content/post.md", "01-Concepts/note.md"},
			want:  []string{"01-Concepts/note.md"},
		},
		{
			name:  "excludes 99-System",
			files: []string{"99-System/template.md"},
			want:  nil,
		},
		{
			name:  "excludes .claude",
			files: []string{".claude/skills.md"},
			want:  nil,
		},
		{
			name:  "excludes .obsidian",
			files: []string{".obsidian/config.md"},
			want:  nil,
		},
		{
			name:  "excludes root-level markdown",
			files: []string{"README.md", "CLAUDE.md"},
			want:  nil,
		},

		// non-markdown files
		{
			name:  "excludes non-markdown",
			files: []string{"01-Concepts/image.png", "01-Concepts/note.md"},
			want:  []string{"01-Concepts/note.md"},
		},

		// path traversal attacks
		{
			name:  "traversal into excluded dir",
			files: []string{"01-Concepts/../99-System/evil.md"},
			want:  nil,
		},
		{
			name:  "URL-encoded traversal %2e%2e",
			files: []string{"01-Concepts/%2e%2e/99-System/evil.md"},
			want:  nil,
		},
		{
			name:  "double-encoded traversal %252e%252e",
			files: []string{"01-Concepts/%252e%252e/99-System/evil.md"},
			want:  nil, // %252e decodes to %2e which decodes to .
		},
		{
			name:  "mixed case encoded traversal %2E%2E",
			files: []string{"01-Concepts/%2E%2E/99-System/evil.md"},
			want:  nil,
		},
		{
			name:  "traversal into public content",
			files: []string{"foo/../10-Public-Content/stolen.md"},
			want:  nil,
		},
		{
			name:  "traversal into .obsidian",
			files: []string{"01-Concepts/../../.obsidian/hack.md"},
			want:  nil,
		},
		{
			name:  "double traversal",
			files: []string{"a/b/../../99-System/x.md"},
			want:  nil,
		},
		{
			name:  "traversal to root level",
			files: []string{"foo/../README.md"},
			want:  nil, // path.Clean produces "README.md" which has no "/"
		},

		// boundary
		{
			name:  "empty input",
			files: nil,
			want:  nil,
		},
		{
			name:  "empty strings in input",
			files: []string{""},
			want:  nil,
		},
		{
			name:  "just a slash",
			files: []string{"/"},
			want:  nil,
		},
		{
			name:  "chinese directory names",
			files: []string{"學習筆記/go-concurrency.md"},
			want:  []string{"學習筆記/go-concurrency.md"},
		},
		{
			name:  "file with spaces",
			files: []string{"My Notes/some file.md"},
			want:  []string{"My Notes/some file.md"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := filterKnowledgeMarkdown(tt.files)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("filterKnowledgeMarkdown() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// notionURLPattern — regex contract + adversarial
// ---------------------------------------------------------------------------

func TestNotionURLPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantIDs []string // extracted 32-char hex IDs
	}{
		// happy path
		{
			name:    "standard notion URL",
			input:   "https://www.notion.so/workspace/My-Page-abc123def456789012345678901234ab",
			wantIDs: []string{"abc123def456789012345678901234ab"},
		},
		{
			name:    "notion URL without www",
			input:   "https://notion.so/My-Page-abc123def456789012345678901234ab",
			wantIDs: []string{"abc123def456789012345678901234ab"},
		},
		{
			name:    "http scheme",
			input:   "http://notion.so/Page-abc123def456789012345678901234ab",
			wantIDs: []string{"abc123def456789012345678901234ab"},
		},
		{
			name:    "multiple URLs in PR body",
			input:   "Fixes https://notion.so/Task-aaaa1111bbbb2222cccc3333dddd4444 and https://notion.so/Task-11112222333344445555666677778888",
			wantIDs: []string{"aaaa1111bbbb2222cccc3333dddd4444", "11112222333344445555666677778888"},
		},
		{
			name:    "URL with query params after ID",
			input:   "https://notion.so/Page-abc123def456789012345678901234ab?pvs=4",
			wantIDs: []string{"abc123def456789012345678901234ab"},
		},

		// adversarial: no match
		{
			name:    "not a notion URL",
			input:   "https://example.com/abc123def456789012345678901234ab",
			wantIDs: nil,
		},
		{
			name:    "31-char hex (too short)",
			input:   "https://notion.so/Page-abc123def456789012345678901234a",
			wantIDs: nil,
		},
		{
			name:    "uppercase hex in URL",
			input:   "https://notion.so/Page-ABC123DEF456789012345678901234AB",
			wantIDs: nil, // pattern only matches lowercase hex
		},
		{
			name:    "empty string",
			input:   "",
			wantIDs: nil,
		},
		{
			name:    "SQL injection with space breaks URL match",
			input:   "https://notion.so/'; DROP TABLE--abc123def456789012345678901234ab",
			wantIDs: nil, // space in "DROP TABLE" breaks \S*? match
		},
		{
			name:    "SQL injection without space still matches",
			input:   "https://notion.so/';DROP--abc123def456789012345678901234ab",
			wantIDs: []string{"abc123def456789012345678901234ab"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matches := notionURLPattern.FindAllStringSubmatch(tt.input, -1)
			var gotIDs []string
			for _, m := range matches {
				gotIDs = append(gotIDs, m[1])
			}
			if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
				t.Errorf("notionURLPattern.FindAllStringSubmatch(%q) IDs mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sha256Hex — unit + boundary
// ---------------------------------------------------------------------------

func TestSha256Hex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "hello", input: "hello"},
		{name: "unicode", input: "你好世界"},
		{name: "null bytes", input: "\x00\x00"},
		{name: "large input", input: strings.Repeat("x", 1<<16)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sha256Hex(tt.input)

			// verify against stdlib
			h := sha256.Sum256([]byte(tt.input))
			want := hex.EncodeToString(h[:])

			if got != want {
				t.Errorf("sha256Hex(%q) = %q, want %q", tt.input, got, want)
			}

			// verify format: 64 lowercase hex chars
			if len(got) != 64 {
				t.Errorf("sha256Hex(%q) length = %d, want 64", tt.input, len(got))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// slugFromPath — adversarial extensions
// ---------------------------------------------------------------------------

func TestSlugFromPath_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "no .md extension", path: "dir/file.txt", want: "file.txt"},
		{name: "double .md extension", path: "dir/post.md.md", want: "post.md"},
		{name: "just .md", path: "dir/.md", want: ""},
		{name: "empty path", path: "", want: "."}, // filepath.Base("") returns "."
		{name: "root path", path: "/", want: "/"}, // filepath.Base("/") returns "/"
		{name: "dot dot", path: "..", want: ".."}, // filepath.Base("..") returns ".."
		{name: "path traversal", path: "../../../etc/passwd.md", want: "passwd"},
		{name: "emoji in slug", path: "dir/🚀-rocket.md", want: "🚀-rocket"},
		{name: "spaces in slug", path: "dir/my great post.md", want: "my great post"},
		{name: "SQL injection in filename", path: "dir/'; DROP TABLE --.md", want: "'; DROP TABLE --"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := slugFromPath(tt.path)
			if got != tt.want {
				t.Errorf("slugFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ChangedFiles / RemovedFiles — adversarial extensions
// ---------------------------------------------------------------------------

func TestPushEventChangedFiles_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event PushEvent
		want  []string
	}{
		{
			name:  "no commits",
			event: PushEvent{},
			want:  nil,
		},
		{
			name: "empty commit",
			event: PushEvent{
				Commits: []PushCommit{{}},
			},
			want: nil,
		},
		{
			name: "many commits with heavy overlap",
			event: PushEvent{
				Commits: func() []PushCommit {
					commits := make([]PushCommit, 100)
					for i := range commits {
						commits[i] = PushCommit{
							Added:    []string{"same-file.md"},
							Modified: []string{"other.md"},
						}
					}
					return commits
				}(),
			},
			want: []string{"same-file.md", "other.md"},
		},
		{
			name: "file in both added and modified",
			event: PushEvent{
				Commits: []PushCommit{
					{Added: []string{"a.md"}, Modified: []string{"a.md"}},
				},
			},
			want: []string{"a.md"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.event.ChangedFiles()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ChangedFiles() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPushEventChangedFiles(t *testing.T) {
	tests := []struct {
		name  string
		event PushEvent
		want  []string
	}{
		{
			name: "single commit",
			event: PushEvent{
				Commits: []PushCommit{
					{Added: []string{"a.md"}, Modified: []string{"b.md"}},
				},
			},
			want: []string{"a.md", "b.md"},
		},
		{
			name: "dedup across commits",
			event: PushEvent{
				Commits: []PushCommit{
					{Added: []string{"a.md"}},
					{Modified: []string{"a.md", "b.md"}},
				},
			},
			want: []string{"a.md", "b.md"},
		},
		{
			name: "no added or modified files",
			event: PushEvent{
				Commits: []PushCommit{
					{Removed: []string{"deleted.md"}},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.ChangedFiles()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ChangedFiles() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPushEventRemovedFiles(t *testing.T) {
	tests := []struct {
		name  string
		event PushEvent
		want  []string
	}{
		{
			name: "single removed file",
			event: PushEvent{
				Commits: []PushCommit{
					{Removed: []string{"deleted.md"}},
				},
			},
			want: []string{"deleted.md"},
		},
		{
			name: "dedup removed across commits",
			event: PushEvent{
				Commits: []PushCommit{
					{Removed: []string{"a.md"}},
					{Removed: []string{"a.md", "b.md"}},
				},
			},
			want: []string{"a.md", "b.md"},
		},
		{
			name: "no removed files",
			event: PushEvent{
				Commits: []PushCommit{
					{Added: []string{"new.md"}},
				},
			},
			want: nil,
		},
		{
			name: "rename is removed + added",
			event: PushEvent{
				Commits: []PushCommit{
					{
						Removed: []string{"old-name.md"},
						Added:   []string{"new-name.md"},
					},
				},
			},
			want: []string{"old-name.md"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.RemovedFiles()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RemovedFiles() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFilterPublicMarkdown(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{
			name:  "only public markdown",
			files: []string{"10-Public-Content/post.md", "01-Concepts/note.md", "README.md"},
			want:  []string{"10-Public-Content/post.md"},
		},
		{
			name:  "non-markdown in public",
			files: []string{"10-Public-Content/image.png", "10-Public-Content/post.md"},
			want:  []string{"10-Public-Content/post.md"},
		},
		{
			name:  "nested in public",
			files: []string{"10-Public-Content/sub/deep.md"},
			want:  []string{"10-Public-Content/sub/deep.md"},
		},
		{
			name:  "no matches",
			files: []string{"README.md", "docs/guide.md"},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterPublicMarkdown(tt.files)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("filterPublicMarkdown() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSlugFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple path",
			path: "10-Public-Content/my-post.md",
			want: "my-post",
		},
		{
			name: "nested path",
			path: "10-Public-Content/golang/escape-analysis.md",
			want: "escape-analysis",
		},
		{
			name: "chinese filename",
			path: "10-Public-Content/go-記憶體管理.md",
			want: "go-記憶體管理",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slugFromPath(tt.path)
			if got != tt.want {
				t.Errorf("slugFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
