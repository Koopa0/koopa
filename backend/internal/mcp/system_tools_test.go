package mcpserver

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/feed"
)

// --- ensureTag ---

func TestEnsureTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tags   []string
		target string
		want   []string
	}{
		{
			name:   "adds new tag to non-empty slice",
			tags:   []string{"go", "backend"},
			target: "bookmark",
			want:   []string{"go", "backend", "bookmark"},
		},
		{
			name:   "returns unchanged when tag already present",
			tags:   []string{"go", "bookmark"},
			target: "bookmark",
			want:   []string{"go", "bookmark"},
		},
		{
			name:   "adds tag to empty slice",
			tags:   []string{},
			target: "bookmark",
			want:   []string{"bookmark"},
		},
		{
			name:   "nil slice treated as empty — adds tag",
			tags:   nil,
			target: "bookmark",
			want:   []string{"bookmark"},
		},
		{
			name:   "idempotent: single element already present",
			tags:   []string{"bookmark"},
			target: "bookmark",
			want:   []string{"bookmark"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ensureTag(tt.tags, tt.target)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ensureTag(%v, %q) mismatch (-want +got):\n%s", tt.tags, tt.target, diff)
			}
		})
	}
}

// --- toFeedBrief ---

func TestToFeedBrief(t *testing.T) {
	t.Parallel()

	fixedID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	fetchedAt := time.Date(2025, 3, 15, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		feed *feed.Feed
		want feedBrief
	}{
		{
			name: "full feed with last_fetched_at",
			feed: &feed.Feed{
				ID:            fixedID,
				Name:          "Go Blog",
				URL:           "https://go.dev/blog/feed.atom",
				Enabled:       true,
				Schedule:      feed.ScheduleDaily,
				Topics:        []string{"go", "programming"},
				LastFetchedAt: &fetchedAt,
			},
			want: feedBrief{
				ID:            fixedID.String(),
				Name:          "Go Blog",
				URL:           "https://go.dev/blog/feed.atom",
				Enabled:       true,
				Schedule:      feed.ScheduleDaily,
				Topics:        []string{"go", "programming"},
				LastFetchedAt: "2025-03-15T10:00:00Z",
			},
		},
		{
			name: "minimal feed without last_fetched_at",
			feed: &feed.Feed{
				ID:       fixedID,
				Name:     "Minimal",
				URL:      "https://example.com/feed",
				Enabled:  false,
				Schedule: feed.ScheduleWeekly,
				Topics:   nil,
			},
			want: feedBrief{
				ID:            fixedID.String(),
				Name:          "Minimal",
				URL:           "https://example.com/feed",
				Enabled:       false,
				Schedule:      feed.ScheduleWeekly,
				Topics:        nil,
				LastFetchedAt: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toFeedBrief(tt.feed)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("toFeedBrief() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- parseFeedID ---

func TestParseFeedID(t *testing.T) {
	t.Parallel()

	validUUID := "11111111-1111-1111-1111-111111111111"

	tests := []struct {
		name    string
		input   string
		want    uuid.UUID
		wantErr bool
	}{
		{
			name:  "valid UUID",
			input: validUUID,
			want:  uuid.MustParse(validUUID),
		},
		{
			name:    "invalid UUID string",
			input:   "not-a-uuid",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			// uuid.Parse accepts 32-hex-char strings (no hyphens) as valid UUIDs.
			name:  "UUID without hyphens is valid",
			input: "11111111111111111111111111111111",
			want:  uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		},
		{
			name:    "partial UUID",
			input:   "11111111-1111",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseFeedID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFeedID(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFeedID(%q) unexpected error: %v", tt.input, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("parseFeedID(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}
