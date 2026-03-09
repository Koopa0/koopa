package pipeline

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVerifySignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"ref":"refs/heads/main"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name    string
		payload []byte
		sig     string
		secret  string
		wantErr bool
	}{
		{
			name:    "valid signature",
			payload: payload,
			sig:     validSig,
			secret:  secret,
		},
		{
			name:    "wrong secret",
			payload: payload,
			sig:     validSig,
			secret:  "wrong-secret",
			wantErr: true,
		},
		{
			name:    "missing sha256 prefix",
			payload: payload,
			sig:     "abc123",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "invalid hex",
			payload: payload,
			sig:     "sha256=not-hex",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "empty signature",
			payload: payload,
			sig:     "",
			secret:  secret,
			wantErr: true,
		},
		{
			name:    "tampered payload",
			payload: []byte(`{"ref":"refs/heads/evil"}`),
			sig:     validSig,
			secret:  secret,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySignature(tt.payload, tt.sig, tt.secret)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifySignature() unexpected error: %v", err)
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
