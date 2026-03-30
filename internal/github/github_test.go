package github

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// shortSHA — unit + boundary
// ---------------------------------------------------------------------------

func TestShortSHA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "40 char SHA", input: strings.Repeat("a", 40), want: "aaaaaaa"},
		{name: "exactly 7", input: "1234567", want: "1234567"},
		{name: "less than 7", input: "abc", want: "abc"},
		{name: "empty", input: "", want: ""},
		{name: "8 chars", input: "12345678", want: "1234567"},
		{name: "1 char", input: "x", want: "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := shortSHA(tt.input)
			if got != tt.want {
				t.Errorf("shortSHA(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Compare — repo format validation
// ---------------------------------------------------------------------------

func TestCompare_InvalidRepo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		repo string
	}{
		{name: "no slash", repo: "noslash"},
		{name: "empty owner", repo: "/repo"},
		{name: "empty repo", repo: "owner/"},
		{name: "empty string", repo: ""},
		// "a/b/c" is valid — SplitN(s, "/", 2) gives ["a", "b/c"]
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := NewClient("token", "owner/repo")
			_, err := c.Compare(t.Context(), tt.repo, "abc", "def")
			if err == nil {
				t.Errorf("Compare(%q) expected error for invalid repo", tt.repo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// NewClient — verify timeout is set
// ---------------------------------------------------------------------------

func TestNewClient_HasTimeout(t *testing.T) {
	t.Parallel()
	c := NewClient("token", "owner/repo")
	if c.client.Timeout == 0 {
		t.Error("NewClient() http.Client has zero timeout")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkShortSHA(b *testing.B) {
	sha := strings.Repeat("a", 40)
	b.ReportAllocs()
	for b.Loop() {
		shortSHA(sha)
	}
}
