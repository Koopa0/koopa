package activity

import (
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
				{Timestamp: base, Source: "github", Project: project("blog")},
			},
			wantLen: 1,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				if sessions[0].EventCount != 1 {
					t.Errorf("event count = %d, want 1", sessions[0].EventCount)
				}
			},
		},
		{
			name: "two events within gap",
			events: []Event{
				{Timestamp: base.Add(20 * time.Minute), Source: "github", Project: project("blog")},
				{Timestamp: base, Source: "obsidian", Project: project("blog")},
			},
			wantLen: 1,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				if sessions[0].EventCount != 2 {
					t.Errorf("event count = %d, want 2", sessions[0].EventCount)
				}
				if !slices.Contains(sessions[0].Sources, "github") || !slices.Contains(sessions[0].Sources, "obsidian") {
					t.Errorf("sources = %v, want github+obsidian", sessions[0].Sources)
				}
			},
		},
		{
			name: "gap splits into two sessions",
			events: []Event{
				{Timestamp: base.Add(2 * time.Hour), Source: "github"},
				{Timestamp: base.Add(10 * time.Minute), Source: "obsidian"},
				{Timestamp: base, Source: "obsidian"},
			},
			wantLen: 2,
			wantFunc: func(t *testing.T, sessions []Session) {
				t.Helper()
				// newest first
				if sessions[0].EventCount != 1 {
					t.Errorf("session[0] event count = %d, want 1", sessions[0].EventCount)
				}
				if sessions[1].EventCount != 2 {
					t.Errorf("session[1] event count = %d, want 2", sessions[1].EventCount)
				}
			},
		},
		{
			name: "exact 30min gap is new session",
			events: []Event{
				{Timestamp: base.Add(30 * time.Minute), Source: "github"},
				{Timestamp: base, Source: "github"},
			},
			wantLen: 2,
		},
		{
			name: "29min gap stays in same session",
			events: []Event{
				{Timestamp: base.Add(29 * time.Minute), Source: "github"},
				{Timestamp: base, Source: "github"},
			},
			wantLen: 1,
		},
		{
			name: "nil project excluded from projects list",
			events: []Event{
				{Timestamp: base, Source: "github", Project: nil},
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
				{Timestamp: base.Add(5 * time.Hour), Source: "github"},
				{Timestamp: base.Add(3 * time.Hour), Source: "github"},
				{Timestamp: base, Source: "github"},
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
				t.Fatalf("got %d sessions, want %d", len(sessions), tt.wantLen)
			}
			if tt.wantFunc != nil {
				tt.wantFunc(t, sessions)
			}
		})
	}
}
