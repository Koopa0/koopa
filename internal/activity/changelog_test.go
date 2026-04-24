package activity

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

//nolint:gocognit // table-driven test; loop body asserts shape across many cases
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
				{Timestamp: base, EntityType: "github", ChangeKind: "push", Project: project("blog")},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Project: project("blog"), Timestamp: base},
					},
				},
			},
		},
		{
			name: "multiple events same day",
			events: []Event{
				{Timestamp: base.Add(2 * time.Hour), EntityType: "github", ChangeKind: "push"},
				{Timestamp: base, EntityType: "content", ChangeKind: "note_updated"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 2,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Timestamp: base.Add(2 * time.Hour)},
						{EntityType: "content", ChangeKind: "note_updated", Timestamp: base},
					},
				},
			},
		},
		{
			name: "events across multiple days ordered newest first",
			events: []Event{
				{Timestamp: base, EntityType: "github", ChangeKind: "push"},
				{Timestamp: base.Add(-24 * time.Hour), EntityType: "content", ChangeKind: "note_created"},
				{Timestamp: base.Add(-48 * time.Hour), EntityType: "github", ChangeKind: "pull_request"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Timestamp: base},
					},
				},
				{
					Date:       "2026-03-16",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "content", ChangeKind: "note_created", Timestamp: base.Add(-24 * time.Hour)},
					},
				},
				{
					Date:       "2026-03-15",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "pull_request", Timestamp: base.Add(-48 * time.Hour)},
					},
				},
			},
		},
		{
			name: "nil project omitted from changelog event",
			events: []Event{
				{Timestamp: base, EntityType: "github", ChangeKind: "push", Project: nil},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Project: nil, Timestamp: base},
					},
				},
			},
		},
		// adversarial: events have empty string entity_type and change_kind
		{
			name: "empty string entity_type and change_kind are preserved",
			events: []Event{
				{Timestamp: base, EntityType: "", ChangeKind: ""},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "", ChangeKind: "", Timestamp: base},
					},
				},
			},
		},
		// adversarial: unicode characters in entity_type and title
		{
			name: "unicode entity_type and title are preserved verbatim",
			events: []Event{
				{
					Timestamp:  base,
					EntityType: "content-繁體中文",
					ChangeKind: "note_updated",
					Title:      strPtr("📝 Go 學習筆記"),
				},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "content-繁體中文", ChangeKind: "note_updated", Title: strPtr("📝 Go 學習筆記"), Timestamp: base},
					},
				},
			},
		},
		// boundary: event exactly at midnight
		{
			name: "event at midnight belongs to its calendar day",
			events: []Event{
				{Timestamp: time.Date(2026, 3, 17, 0, 0, 0, 0, time.UTC), EntityType: "github", ChangeKind: "push"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Timestamp: time.Date(2026, 3, 17, 0, 0, 0, 0, time.UTC)},
					},
				},
			},
		},
		// boundary: events spanning a month boundary
		{
			name: "events across month boundary group correctly",
			events: []Event{
				{Timestamp: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), EntityType: "github", ChangeKind: "push"},
				{Timestamp: time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC), EntityType: "github", ChangeKind: "push"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-04-01",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Timestamp: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)},
					},
				},
				{
					Date:       "2026-03-31",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "github", ChangeKind: "push", Timestamp: time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC)},
					},
				},
			},
		},
		// boundary: many events on the same day — EventCount tracks all of them
		{
			name: "10 events same day — event_count is 10",
			events: func() []Event {
				evs := make([]Event, 10)
				for i := range evs {
					evs[i] = Event{
						Timestamp:  base.Add(time.Duration(i) * time.Minute),
						EntityType: "github",
						ChangeKind: "push",
					}
				}
				// newest first (DESC order as caller would pass)
				for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
					evs[i], evs[j] = evs[j], evs[i]
				}
				return evs
			}(),
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 10,
					Events:     nil, // checked by wantLen only via cmpopts
				},
			},
		},
		// adversarial: SQL injection payload in entity_type — must be stored verbatim
		{
			name: "SQL injection payload in entity_type stored verbatim",
			events: []Event{
				{Timestamp: base, EntityType: "'; DROP TABLE activity_events; --", ChangeKind: "push"},
			},
			want: []ChangelogDay{
				{
					Date:       "2026-03-17",
					EventCount: 1,
					Events: []ChangelogEvent{
						{EntityType: "'; DROP TABLE activity_events; --", ChangeKind: "push", Timestamp: base},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GroupChangelog(tt.events)
			if tt.name == "10 events same day — event_count is 10" {
				// Only validate day count and event_count; ignore Events slice ordering.
				if len(got) != 1 {
					t.Fatalf("GroupChangelog() len = %d, want 1", len(got))
				}
				if got[0].EventCount != 10 {
					t.Errorf("GroupChangelog() day.EventCount = %d, want 10", got[0].EventCount)
				}
				if len(got[0].Events) != 10 {
					t.Errorf("GroupChangelog() day.Events len = %d, want 10", len(got[0].Events))
				}
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GroupChangelog() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// strPtr is a test helper that returns a pointer to the given string.
func strPtr(s string) *string { return &s }

// FuzzGroupChangelog verifies GroupChangelog never panics on arbitrary event slices.
func FuzzGroupChangelog(f *testing.F) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	f.Add("github", "push", int64(0))
	f.Add("", "", int64(0))
	f.Add("'; DROP TABLE --", "push", int64(3600))
	f.Add("content", "note_updated", int64(-86400))
	f.Add("unicode-繁體中文", "event", int64(1<<32))

	f.Fuzz(func(t *testing.T, entityType, changeKind string, offsetSec int64) {
		events := []Event{
			{
				Timestamp:  base.Add(time.Duration(offsetSec) * time.Second),
				EntityType: entityType,
				ChangeKind: changeKind,
			},
		}
		// must not panic
		got := GroupChangelog(events)
		// invariant: non-empty input always produces at least one day
		if len(got) == 0 {
			t.Error("GroupChangelog(non-empty) returned empty result")
		}
		// invariant: EventCount equals len(Events) for every day
		for _, day := range got {
			if day.EventCount != len(day.Events) {
				t.Errorf("day %q: EventCount=%d != len(Events)=%d", day.Date, day.EventCount, len(day.Events))
			}
		}
	})
}

// BenchmarkGroupChangelog measures grouping performance on a realistic dataset.
func BenchmarkGroupChangelog(b *testing.B) {
	b.ReportAllocs()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 200 events spread across 30 days, newest-first (DESC)
	events := make([]Event, 200)
	for i := range events {
		events[i] = Event{
			Timestamp:  base.Add(-time.Duration(i) * 3 * time.Hour),
			EntityType: "github",
			ChangeKind: "push",
		}
	}
	for b.Loop() {
		_ = GroupChangelog(events)
	}
}
