package pipeline

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

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
			name: "no files",
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
