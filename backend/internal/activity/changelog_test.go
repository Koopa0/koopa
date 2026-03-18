package activity

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGroupChangelog(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)
	project := func(s string) *string { return &s }

	tests := []struct {
		name   string
		events []Event
		want   []ChangelogDay
	}{
		{
			name:   "empty events",
			events: nil,
			want:   []ChangelogDay{},
		},
		{
			name: "single event single day",
			events: []Event{
				{Timestamp: base, Source: "github", EventType: "push", Project: project("blog")},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{Source: "github", EventType: "push", Project: project("blog"), Timestamp: base},
					},
				},
			},
		},
		{
			name: "multiple events same day",
			events: []Event{
				{Timestamp: base.Add(2 * time.Hour), Source: "github", EventType: "push"},
				{Timestamp: base, Source: "obsidian", EventType: "note_updated"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 2,
					Events: []ChangelogEvent{
						{Source: "github", EventType: "push", Timestamp: base.Add(2 * time.Hour)},
						{Source: "obsidian", EventType: "note_updated", Timestamp: base},
					},
				},
			},
		},
		{
			name: "events across multiple days ordered newest first",
			events: []Event{
				{Timestamp: base, Source: "github", EventType: "push"},
				{Timestamp: base.Add(-24 * time.Hour), Source: "obsidian", EventType: "note_created"},
				{Timestamp: base.Add(-48 * time.Hour), Source: "github", EventType: "pull_request"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{Source: "github", EventType: "push", Timestamp: base},
					},
				},
				{
					Date:       "2026-03-16",
					EventCount: 1,
					Events: []ChangelogEvent{
						{Source: "obsidian", EventType: "note_created", Timestamp: base.Add(-24 * time.Hour)},
					},
				},
				{
					Date:       "2026-03-15",
					EventCount: 1,
					Events: []ChangelogEvent{
						{Source: "github", EventType: "pull_request", Timestamp: base.Add(-48 * time.Hour)},
					},
				},
			},
		},
		{
			name: "nil project omitted from changelog event",
			events: []Event{
				{Timestamp: base, Source: "github", EventType: "push", Project: nil},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{Source: "github", EventType: "push", Project: nil, Timestamp: base},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GroupChangelog(tt.events)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GroupChangelog mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
