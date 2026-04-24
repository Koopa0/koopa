package activity

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestGroupSessions(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 17, 9, 0, 0, 0, time.UTC)
	project := func(s string) *string { return &s }

	tests := []struct {
		name     string
		events   []Event
		wantLen  int
		wantFunc func(t *testing.T, sessions []Session)
	}{
		{
			name:    "empty events",
			events:  nil,
			wantLen: 0,
		},
		{
			name: "single event",
			events: []Event{
				{Timestamp: base, EntityType: "github", Project: project("blog")},
			},
			wantLen: 1,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				assertEventCount(t, sessions, 0, 1)
			},
		},
		{
			name: "two events within gap",
			events: []Event{
				{Timestamp: base.Add(20 * time.Minute), EntityType: "github", Project: project("blog")},
				{Timestamp: base, EntityType: "rss", Project: project("blog")},
			},
			wantLen: 1,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				assertEventCount(t, sessions, 0, 2)
				if !slices.Contains(sessions[0].Sources, "github") || !slices.Contains(sessions[0].Sources, "rss") {
					t.Errorf("sources = %v, want github+rss", sessions[0].Sources)
				}
			},
		},
		{
			name: "gap splits into two sessions",
			events: []Event{
				{Timestamp: base.Add(2 * time.Hour), EntityType: "github"},
				{Timestamp: base.Add(10 * time.Minute), EntityType: "rss"},
				{Timestamp: base, EntityType: "rss"},
			},
			wantLen: 2,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				assertEventCount(t, sessions, 0, 1)
				assertEventCount(t, sessions, 1, 2)
			},
		},
		{
			name: "exact 30min gap is new session",
			events: []Event{
				{Timestamp: base.Add(30 * time.Minute), EntityType: "github"},
				{Timestamp: base, EntityType: "github"},
			},
			wantLen: 2,
		},
		{
			name: "29min gap stays in same session",
			events: []Event{
				{Timestamp: base.Add(29 * time.Minute), EntityType: "github"},
				{Timestamp: base, EntityType: "github"},
			},
			wantLen: 1,
		},
		{
			name: "nil project excluded from projects list",
			events: []Event{
				{Timestamp: base, EntityType: "github", Project: nil},
			},
			wantLen: 1,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				if diff := cmp.Diff([]string{}, sessions[0].Projects); diff != "" {
					t.Errorf("projects mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "multiple sessions ordered newest first",
			events: []Event{
				{Timestamp: base.Add(5 * time.Hour), EntityType: "github"},
				{Timestamp: base.Add(3 * time.Hour), EntityType: "github"},
				{Timestamp: base, EntityType: "github"},
			},
			wantLen: 3,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				if !sessions[0].Start.After(sessions[1].Start) {
					t.Error("sessions not ordered newest first")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sessions := GroupSessions(tt.events)
			if len(sessions) != tt.wantLen {
				t.Fatalf("GroupSessions() = %d sessions, want %d", len(sessions), tt.wantLen)
			}
			if tt.wantFunc != nil {
				tt.wantFunc(t, sessions)
			}
		})
	}
}

func assertEventCount(t *testing.T, sessions []Session, idx, want int) {
	t.Helper()
	if sessions[idx].EventCount != want {
		t.Errorf("session[%d] event count = %d, want %d", idx, sessions[idx].EventCount, want)
	}
}

// TestGroupSessions_Adversarial adds boundary and adversarial cases beyond the happy-path table.
//
func TestGroupSessions_Adversarial(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 17, 9, 0, 0, 0, time.UTC)

	t.Run("exactly 29m59s gap — same session", func(t *testing.T) {
		t.Parallel()
		events := []Event{
			{Timestamp: base.Add(29*time.Minute + 59*time.Second), EntityType: "github"},
			{Timestamp: base, EntityType: "github"},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1 (gap < 30m)", len(got))
		}
	})

	t.Run("exactly 30m00s gap — new session", func(t *testing.T) {
		t.Parallel()
		events := []Event{
			{Timestamp: base.Add(30 * time.Minute), EntityType: "github"},
			{Timestamp: base, EntityType: "github"},
		}
		got := GroupSessions(events)
		if len(got) != 2 {
			t.Fatalf("GroupSessions() = %d sessions, want 2 (gap == 30m)", len(got))
		}
	})

	t.Run("single event — duration is 0m0s", func(t *testing.T) {
		t.Parallel()
		events := []Event{
			{Timestamp: base, EntityType: "github"},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		if got[0].Duration != "0s" {
			t.Errorf("GroupSessions() single event Duration = %q, want %q", got[0].Duration, "0s")
		}
		if !got[0].Start.Equal(got[0].End) {
			t.Errorf("GroupSessions() single event Start != End: %v vs %v", got[0].Start, got[0].End)
		}
	})

	t.Run("empty project string treated same as nil — excluded from projects", func(t *testing.T) {
		t.Parallel()
		empty := ""
		events := []Event{
			{Timestamp: base, EntityType: "github", Project: &empty},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		if len(got[0].Projects) != 0 {
			t.Errorf("GroupSessions() empty project string produced projects = %v, want []", got[0].Projects)
		}
	})

	t.Run("duplicate entity_type in multiple events — deduplicated in Sources", func(t *testing.T) {
		t.Parallel()
		events := []Event{
			{Timestamp: base.Add(10 * time.Minute), EntityType: "github"},
			{Timestamp: base.Add(5 * time.Minute), EntityType: "github"},
			{Timestamp: base, EntityType: "github"},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		if len(got[0].Sources) != 1 || got[0].Sources[0] != "github" {
			t.Errorf("GroupSessions() Sources = %v, want [github]", got[0].Sources)
		}
	})

	t.Run("sources sorted alphabetically", func(t *testing.T) {
		t.Parallel()
		events := []Event{
			{Timestamp: base.Add(5 * time.Minute), EntityType: "rss"},
			{Timestamp: base, EntityType: "github"},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		want := []string{"github", "rss"}
		if diff := cmp.Diff(want, got[0].Sources); diff != "" {
			t.Errorf("GroupSessions() Sources mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("projects sorted alphabetically", func(t *testing.T) {
		t.Parallel()
		projA := "alpha"
		projZ := "zeta"
		events := []Event{
			{Timestamp: base.Add(5 * time.Minute), EntityType: "github", Project: &projZ},
			{Timestamp: base, EntityType: "github", Project: &projA},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		want := []string{"alpha", "zeta"}
		if diff := cmp.Diff(want, got[0].Projects); diff != "" {
			t.Errorf("GroupSessions() Projects mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("session duration truncated to minute precision", func(t *testing.T) {
		t.Parallel()
		// 15 minutes and 30 seconds — within sessionGap (30m), duration truncates to 15m0s
		events := []Event{
			{Timestamp: base.Add(15*time.Minute + 30*time.Second), EntityType: "github"},
			{Timestamp: base, EntityType: "github"},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		want := "15m0s"
		if got[0].Duration != want {
			t.Errorf("GroupSessions() Duration = %q, want %q", got[0].Duration, want)
		}
	})

	t.Run("result is always ordered newest first", func(t *testing.T) {
		t.Parallel()
		// three sessions: 9h, 5h, 0h
		s1 := base.Add(9 * time.Hour)
		s2 := base.Add(5 * time.Hour)
		s3 := base
		events := []Event{
			{Timestamp: s1, EntityType: "github"},
			// gap > 30m before s2
			{Timestamp: s2, EntityType: "github"},
			// gap > 30m before s3
			{Timestamp: s3, EntityType: "github"},
		}
		got := GroupSessions(events)
		for i := 1; i < len(got); i++ {
			if got[i].Start.After(got[i-1].Start) {
				t.Errorf("GroupSessions() session[%d].Start=%v > session[%d].Start=%v — not ordered newest first",
					i, got[i].Start, i-1, got[i-1].Start)
			}
		}
	})

	t.Run("unicode entity_type stored verbatim", func(t *testing.T) {
		t.Parallel()
		events := []Event{
			{Timestamp: base, EntityType: "source-繁體中文"},
		}
		got := GroupSessions(events)
		if len(got) != 1 {
			t.Fatalf("GroupSessions() = %d sessions, want 1", len(got))
		}
		if !slices.Contains(got[0].Sources, "source-繁體中文") {
			t.Errorf("GroupSessions() Sources = %v, want to contain %q", got[0].Sources, "source-繁體中文")
		}
	})
}

// TestGroupSessions_SessionCount_Full verifies multi-session detection with full struct comparison.
func TestGroupSessions_SessionCount_Full(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 17, 9, 0, 0, 0, time.UTC)
	projBlog := "blog"

	// Two sessions: morning (9:00-9:10) and afternoon (11:00-11:20)
	events := []Event{
		{Timestamp: base.Add(11*time.Hour + 20*time.Minute), EntityType: "rss", Project: &projBlog},
		{Timestamp: base.Add(11 * time.Hour), EntityType: "github", Project: &projBlog},
		{Timestamp: base.Add(10 * time.Minute), EntityType: "github", Project: &projBlog},
		{Timestamp: base, EntityType: "rss", Project: &projBlog},
	}

	got := GroupSessions(events)

	want := []Session{
		{
			Start:      base.Add(11 * time.Hour),
			End:        base.Add(11*time.Hour + 20*time.Minute),
			Duration:   "20m0s",
			EventCount: 2,
			Sources:    []string{"github", "rss"},
			Projects:   []string{"blog"},
		},
		{
			Start:      base,
			End:        base.Add(10 * time.Minute),
			Duration:   "10m0s",
			EventCount: 2,
			Sources:    []string{"github", "rss"},
			Projects:   []string{"blog"},
		},
	}

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("GroupSessions() mismatch (-want +got):\n%s", diff)
	}
}

// FuzzGroupSessions verifies GroupSessions never panics on arbitrary event slices.
func FuzzGroupSessions(f *testing.F) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	f.Add("github", int64(0))
	f.Add("", int64(0))
	f.Add("rss", int64(1800))            // exactly 30 min
	f.Add("github", int64(1799))         // 29m59s
	f.Add("unicode-中文", int64(-3600))    // negative offset
	f.Add("'; DROP TABLE --", int64(60)) // SQL injection in entity_type

	f.Fuzz(func(t *testing.T, entityType string, offsetSec int64) {
		project := "project"
		events := []Event{
			{
				Timestamp:  base.Add(time.Duration(offsetSec) * time.Second),
				EntityType: entityType,
				Project:    &project,
			},
			{
				Timestamp:  base,
				EntityType: "baseline",
			},
		}
		// must not panic
		got := GroupSessions(events)

		// invariant: at least one session
		if len(got) == 0 {
			t.Error("GroupSessions(non-empty) returned empty result")
		}
		// invariant: Sources is never nil
		for _, s := range got {
			if s.Sources == nil {
				t.Error("GroupSessions() Sources is nil, want non-nil slice")
			}
			if s.Projects == nil {
				t.Error("GroupSessions() Projects is nil, want non-nil slice")
			}
			if s.EventCount <= 0 {
				t.Errorf("GroupSessions() EventCount = %d, want > 0", s.EventCount)
			}
		}
		// invariant: sessions are ordered newest-first
		for i := 1; i < len(got); i++ {
			if got[i].Start.After(got[i-1].Start) {
				t.Errorf("sessions not ordered newest-first at index %d", i)
			}
		}
	})
}

// BenchmarkGroupSessions measures session grouping on a realistic workday dataset.
func BenchmarkGroupSessions(b *testing.B) {
	b.ReportAllocs()

	base := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	// Simulate 3 sessions of 20 events each with realistic gaps
	events := make([]Event, 60)
	for i := range events {
		sessionStart := base.Add(time.Duration(i/20) * 3 * time.Hour)
		offset := time.Duration(i%20) * time.Minute
		events[i] = Event{
			Timestamp:  sessionStart.Add(offset),
			EntityType: []string{"github", "rss", "manual"}[i%3],
		}
	}
	// reverse to newest-first (DESC) as caller would provide
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	for b.Loop() {
		_ = GroupSessions(events)
	}
}

// BenchmarkSetToSlice measures the map-to-sorted-slice conversion.
func BenchmarkSetToSlice(b *testing.B) {
	b.ReportAllocs()
	m := map[string]struct{}{
		"github":  {},
		"rss":     {},
		"manual":  {},
		"content": {},
		"todo":    {},
	}
	for b.Loop() {
		_ = setToSlice(m)
	}
}

// Ensure strings import is used.
var _ = strings.Contains
