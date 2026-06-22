// Copyright 2026 Koopa. All rights reserved.

package project

import (
	"testing"
	"time"
)

// ref is the fixed "now" every case measures against. Hand-computed gaps
// below are relative to this instant so the expected stalled/neglected
// verdicts are literals, not re-derivations of the function under test.
var ref = time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

// daysAgo returns a *time.Time that many calendar days before ref.
func daysAgo(d int) *time.Time {
	t := ref.AddDate(0, 0, -d)
	return &t
}

// hoursAgo returns a *time.Time that many hours before ref.
func hoursAgo(h int) *time.Time {
	t := ref.Add(-time.Duration(h) * time.Hour)
	return &t
}

func TestStalled(t *testing.T) {
	tests := []struct {
		name       string
		lastHuman  *time.Time
		cadence    string
		openAction bool
		want       bool
	}{
		// No open next action → never stalled regardless of how stale.
		{name: "no open action, very stale daily", lastHuman: daysAgo(100), cadence: "daily", openAction: false, want: false},
		{name: "no open action, never touched weekly", lastHuman: nil, cadence: "weekly", openAction: false, want: false},

		// daily: threshold = 2×1 = 2 days. >2 days stalled.
		{name: "daily, 1 day ago, open", lastHuman: daysAgo(1), cadence: "daily", openAction: true, want: false},
		{name: "daily, 2 days exactly, open", lastHuman: daysAgo(2), cadence: "daily", openAction: true, want: false},
		{name: "daily, 3 days ago, open", lastHuman: daysAgo(3), cadence: "daily", openAction: true, want: true},

		// weekly: threshold = 2×7 = 14 days.
		{name: "weekly, 10 days ago, open", lastHuman: daysAgo(10), cadence: "weekly", openAction: true, want: false},
		{name: "weekly, 14 days exactly, open", lastHuman: daysAgo(14), cadence: "weekly", openAction: true, want: false},
		{name: "weekly, 21 days ago, open", lastHuman: daysAgo(21), cadence: "weekly", openAction: true, want: true},

		// biweekly: threshold = 2×14 = 28 days.
		{name: "biweekly, 20 days ago, open", lastHuman: daysAgo(20), cadence: "biweekly", openAction: true, want: false},
		{name: "biweekly, 30 days ago, open", lastHuman: daysAgo(30), cadence: "biweekly", openAction: true, want: true},

		// monthly: threshold = 2×30 = 60 days.
		{name: "monthly, 59 days ago, open", lastHuman: daysAgo(59), cadence: "monthly", openAction: true, want: false},
		{name: "monthly, 61 days ago, open", lastHuman: daysAgo(61), cadence: "monthly", openAction: true, want: true},

		// Boundary just past the threshold by an hour (daily threshold = 48h).
		{name: "daily, 49 hours ago, open", lastHuman: hoursAgo(49), cadence: "daily", openAction: true, want: true},
		{name: "daily, 47 hours ago, open", lastHuman: hoursAgo(47), cadence: "daily", openAction: true, want: false},

		// Never any human activity but open → stalled (nothing to measure
		// against, so treated as past any threshold).
		{name: "weekly, never touched, open", lastHuman: nil, cadence: "weekly", openAction: true, want: true},

		// Unrecognised cadence → not stalled (no threshold defined).
		{name: "unknown cadence, very stale, open", lastHuman: daysAgo(365), cadence: "yearly", openAction: true, want: false},
		{name: "empty cadence, very stale, open", lastHuman: daysAgo(365), cadence: "", openAction: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Stalled(tt.lastHuman, tt.cadence, tt.openAction, ref)
			if got != tt.want {
				t.Errorf("Stalled(%v, %q, openAction=%v) = %v, want %v",
					tt.lastHuman, tt.cadence, tt.openAction, got, tt.want)
			}
		})
	}
}

func TestAreaNeglected(t *testing.T) {
	tests := []struct {
		name      string
		lastHuman *time.Time
		want      bool
	}{
		// Threshold is 14 days.
		{name: "never any human activity", lastHuman: nil, want: true},
		{name: "active today", lastHuman: daysAgo(0), want: false},
		{name: "13 days ago", lastHuman: daysAgo(13), want: false},
		{name: "14 days exactly", lastHuman: daysAgo(14), want: false},
		{name: "15 days ago", lastHuman: daysAgo(15), want: true},
		// One hour past the 14-day boundary.
		{name: "14 days plus one hour", lastHuman: hoursAgo(14*24 + 1), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AreaNeglected(tt.lastHuman, ref)
			if got != tt.want {
				t.Errorf("AreaNeglected(%v) = %v, want %v", tt.lastHuman, got, tt.want)
			}
		})
	}
}

func TestDaysSince(t *testing.T) {
	tests := []struct {
		name      string
		lastHuman *time.Time
		want      *int
	}{
		{name: "nil → nil", lastHuman: nil, want: nil},
		{name: "0 days", lastHuman: daysAgo(0), want: intp(0)},
		{name: "3 days", lastHuman: daysAgo(3), want: intp(3)},
		// 36h truncates to 1 day.
		{name: "36 hours → 1 day", lastHuman: hoursAgo(36), want: intp(1)},
		// A future instant (clock skew) clamps to 0.
		{name: "future instant clamps to 0", lastHuman: future(ref, 5), want: intp(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DaysSince(tt.lastHuman, ref)
			switch {
			case tt.want == nil && got != nil:
				t.Errorf("DaysSince(%v) = %d, want nil", tt.lastHuman, *got)
			case tt.want != nil && got == nil:
				t.Errorf("DaysSince(%v) = nil, want %d", tt.lastHuman, *tt.want)
			case tt.want != nil && got != nil && *got != *tt.want:
				t.Errorf("DaysSince(%v) = %d, want %d", tt.lastHuman, *got, *tt.want)
			}
		})
	}
}

func intp(n int) *int { return &n }

func future(base time.Time, hours int) *time.Time {
	t := base.Add(time.Duration(hours) * time.Hour)
	return &t
}
