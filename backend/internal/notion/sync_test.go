package notion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// validPageIDForTest is a well-formed UUID suitable for use as a Notion page ID.
const validPageIDForTest = "12345678-1234-1234-1234-123456789abc"

// --------------------------------------------------------------------------
// buildSourceID
// --------------------------------------------------------------------------

func TestBuildSourceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		pageID string
		status string
		want   string
	}{
		{
			name:   "basic",
			pageID: "abc",
			status: "done",
			want:   "abc:done",
		},
		{
			name:   "same page different status",
			pageID: "abc",
			status: "in-progress",
			want:   "abc:in-progress",
		},
		{
			name:   "uuid page id",
			pageID: validPageIDForTest,
			status: "planned",
			want:   validPageIDForTest + ":planned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildSourceID(tt.pageID, tt.status)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildSourceID(%q, %q) mismatch (-want +got):\n%s", tt.pageID, tt.status, diff)
			}
		})
	}
}

// --------------------------------------------------------------------------
// validPageID
// --------------------------------------------------------------------------

func TestValidPageID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid uuid lowercase",
			input: "12345678-abcd-abcd-abcd-123456789abc",
			want:  true,
		},
		{
			name:  "valid uuid uppercase",
			input: "12345678-ABCD-ABCD-ABCD-123456789ABC",
			want:  true,
		},
		{
			name:  "valid uuid mixed case",
			input: "12345678-1234-1234-1234-123456789abc",
			want:  true,
		},
		{
			name:  "too short",
			input: "12345678-1234-1234-1234-12345678abc",
			want:  false,
		},
		{
			name:  "too long",
			input: "12345678-1234-1234-1234-123456789abcd",
			want:  false,
		},
		{
			name:  "missing dashes",
			input: "123456781234123412341234567890ab",
			want:  false,
		},
		{
			name:  "path traversal",
			input: "../etc/pa-sswd-0000-0000-000000000000",
			want:  false,
		},
		{
			name:  "query string injection",
			input: "12345678-1234-1234-1234-12345678?abc",
			want:  false,
		},
		{
			name:  "null bytes",
			input: "12345678-1234-1234-1234-12345678\x00bc",
			want:  false,
		},
		{
			name:  "dash at wrong position",
			input: "1234567-81234-1234-1234-123456789abc",
			want:  false,
		},
		{
			name:  "invalid hex char",
			input: "12345678-1234-1234-1234-12345678gggg",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := validPageID(tt.input)
			if got != tt.want {
				t.Errorf("validPageID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
