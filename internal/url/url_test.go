package url

import (
	"errors"
	"testing"
)

func TestCanonical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "simple https preserved",
			in:   "https://go.dev/blog/loopvar",
			want: "https://go.dev/blog/loopvar",
		},
		{
			name: "trims whitespace",
			in:   "  https://go.dev/blog/loopvar  ",
			want: "https://go.dev/blog/loopvar",
		},
		{
			name: "lowercases scheme and host",
			in:   "HTTPS://GO.DEV/blog/loopvar",
			want: "https://go.dev/blog/loopvar",
		},
		{
			name: "strips trailing slash on non-root path",
			in:   "https://go.dev/blog/loopvar/",
			want: "https://go.dev/blog/loopvar",
		},
		{
			name: "keeps root slash",
			in:   "https://go.dev/",
			want: "https://go.dev/",
		},
		{
			name: "drops fragment",
			in:   "https://go.dev/blog/loopvar#examples",
			want: "https://go.dev/blog/loopvar",
		},
		{
			name: "strips default http port",
			in:   "http://example.com:80/x",
			want: "http://example.com/x",
		},
		{
			name: "strips default https port",
			in:   "https://example.com:443/x",
			want: "https://example.com/x",
		},
		{
			name: "keeps non-default port",
			in:   "https://example.com:8443/x",
			want: "https://example.com:8443/x",
		},
		{
			name: "strips single tracking param",
			in:   "https://go.dev/blog/loopvar?utm_source=twitter",
			want: "https://go.dev/blog/loopvar",
		},
		{
			name: "strips many tracking params preserving others",
			in:   "https://go.dev/p?utm_source=x&utm_medium=y&fbclid=z&id=42",
			want: "https://go.dev/p?id=42",
		},
		{
			name: "sorts remaining query params alphabetically",
			in:   "https://go.dev/search?q=goroutines&lang=en&page=2",
			want: "https://go.dev/search?lang=en&page=2&q=goroutines",
		},
		{
			name: "uppercases percent-encoding hex",
			in:   "https://go.dev/search?q=hello%3aworld",
			want: "https://go.dev/search?q=hello%3Aworld",
		},
		{
			name: "combination — lowercase host + tracking + fragment + sort",
			in:   "HTTPS://Go.Dev/blog/?utm_source=rss&lang=en#section-2",
			want: "https://go.dev/blog?lang=en",
		},
		{
			name:    "empty string",
			in:      "",
			wantErr: true,
		},
		{
			name:    "relative URL has no host",
			in:      "/path/only",
			wantErr: true,
		},
		{
			name:    "bare hostname with no scheme has no host (url.Parse treats it as path)",
			in:      "example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Canonical(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Canonical(%q) returned %q, want error", tt.in, got)
				}
				if !errors.Is(err, ErrInvalidURL) {
					t.Fatalf("Canonical(%q) err = %v, want ErrInvalidURL", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonical(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Canonical(%q):\n got  %q\n want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHash_DeterministicAndCanonical(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{
			// Same canonical form, different surface forms — must produce same hash.
			"https://go.dev/blog/loopvar",
			"  HTTPS://GO.DEV/blog/loopvar/?utm_source=x&fbclid=y#anchor  ",
			"https://go.dev:443/blog/loopvar",
		},
		{
			"https://example.com/a?b=1&a=2",
			"https://example.com/a?a=2&b=1",
		},
	}

	for i, group := range cases {
		var ref string
		for j, raw := range group {
			h, err := Hash(raw)
			if err != nil {
				t.Fatalf("group %d item %d: Hash(%q) error: %v", i, j, raw, err)
			}
			if j == 0 {
				ref = h
				continue
			}
			if h != ref {
				t.Fatalf("group %d item %d:\n %q -> %s\n %q -> %s\nhashes should match", i, j, group[0], ref, raw, h)
			}
		}
	}
}

func TestHash_DifferentResourcesDiffer(t *testing.T) {
	t.Parallel()

	a, err := Hash("https://go.dev/blog/loopvar")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("https://go.dev/blog/generics")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("distinct paths collided: %s", a)
	}
}

func TestHash_InvalidReturnsError(t *testing.T) {
	t.Parallel()
	if _, err := Hash(""); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("empty input, err = %v, want ErrInvalidURL", err)
	}
}

// FuzzCanonical — Canonical must either return an error or a string that is
// idempotent (canonicalising twice produces the same output).
func FuzzCanonical(f *testing.F) {
	seeds := []string{
		"https://go.dev/blog/loopvar",
		"HTTPS://Go.Dev/blog/?utm_source=rss#x",
		"http://example.com:80/x/",
		"https://example.com/path?b=1&a=2",
		"",
		"/relative",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		first, err := Canonical(s)
		if err != nil {
			return
		}
		second, err := Canonical(first)
		if err != nil {
			t.Fatalf("canonicalising output of first pass failed: first=%q err=%v", first, err)
		}
		if first != second {
			t.Fatalf("non-idempotent: input=%q first=%q second=%q", s, first, second)
		}
	})
}
