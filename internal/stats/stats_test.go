// Copyright 2026 Koopa. All rights reserved.

package stats

// Tests for internal/stats.
//
// Scope (unit, no DB):
//   - computeAreaDrift: pure business logic — division-by-zero guards, empty
//     maps, single-side data (goals but no events, events but no goals), sort
//     order.
//   - parseDays: drift-window bounds clamping (0, negative, >90, exact
//     boundaries 1 and 90, non-numeric) plus a fuzz test on arbitrary input.
//   - successRateState / nonZeroState: the pure cell-state mappers consumed by
//     the process-runs summary.
//   - SystemHealthSnapshot wire contract: marshaling-only pins on the nested
//     field names the Today fan-out consumes.
//
// The store aggregators (Overview / SystemHealth / ProcessRunsSince /
// RecentProcessRuns) run against a real PostgreSQL container in
// internal/stats/integration_test.go — never a hand-rolled db.DBTX, which would
// prove nothing about the SQL.

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// ── computeAreaDrift unit tests ────────────────────────────────────────────────

func TestComputeAreaDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		goalsByArea  map[string]int
		totalGoals   int
		eventsByArea map[string]int
		totalEvents  int
		wantLen      int
		wantAreas    []AreaDrift // checked with cmpopts.EquateApprox for floats
	}{
		{
			name:         "empty both sides — no areas",
			goalsByArea:  map[string]int{},
			totalGoals:   0,
			eventsByArea: map[string]int{},
			totalEvents:  0,
			wantLen:      0,
			wantAreas:    []AreaDrift{},
		},
		{
			name:         "goals only, no events — event percent is 0, drift is negative goal pct",
			goalsByArea:  map[string]int{"backend": 2},
			totalGoals:   2,
			eventsByArea: map[string]int{},
			totalEvents:  0,
			wantLen:      1,
			wantAreas: []AreaDrift{
				{Area: "backend", ActiveGoals: 2, EventCount: 0,
					GoalPercent: 100.0, EventPercent: 0, DriftPercent: -100.0},
			},
		},
		{
			name:         "events only, no goals — goal percent is 0, drift is positive event pct",
			goalsByArea:  map[string]int{},
			totalGoals:   0,
			eventsByArea: map[string]int{"frontend": 5},
			totalEvents:  5,
			wantLen:      1,
			wantAreas: []AreaDrift{
				{Area: "frontend", ActiveGoals: 0, EventCount: 5,
					GoalPercent: 0, EventPercent: 100.0, DriftPercent: 100.0},
			},
		},
		{
			name:         "zero totals with populated maps — no division, all percents are 0",
			goalsByArea:  map[string]int{"a": 3},
			totalGoals:   0, // caller passes 0 — pathological but must not panic
			eventsByArea: map[string]int{"a": 7},
			totalEvents:  0,
			wantLen:      1,
			wantAreas: []AreaDrift{
				{Area: "a", ActiveGoals: 3, EventCount: 7,
					GoalPercent: 0, EventPercent: 0, DriftPercent: 0},
			},
		},
		{
			name:         "balanced distribution — drift close to zero",
			goalsByArea:  map[string]int{"go": 1, "rust": 1},
			totalGoals:   2,
			eventsByArea: map[string]int{"go": 1, "rust": 1},
			totalEvents:  2,
			wantLen:      2,
			wantAreas: []AreaDrift{
				{Area: "go", ActiveGoals: 1, EventCount: 1, GoalPercent: 50, EventPercent: 50, DriftPercent: 0},
				{Area: "rust", ActiveGoals: 1, EventCount: 1, GoalPercent: 50, EventPercent: 50, DriftPercent: 0},
			},
		},
		{
			name:         "sorted by absolute drift descending",
			goalsByArea:  map[string]int{"a": 1, "b": 1, "c": 1},
			totalGoals:   3,
			eventsByArea: map[string]int{"a": 3, "b": 0, "c": 0},
			totalEvents:  3,
			// a: goal=33.3, event=100 → drift=+66.7  abs=66.7
			// b: goal=33.3, event=0   → drift=-33.3  abs=33.3
			// c: goal=33.3, event=0   → drift=-33.3  abs=33.3
			// a must come first; b and c tied (both at abs 33.3)
			wantLen: 3,
			// We only check the first element here; the equal pair can be in any order.
			wantAreas: nil, // custom check below
		},
		{
			name:         "disjoint areas — union is taken",
			goalsByArea:  map[string]int{"ai": 2},
			totalGoals:   2,
			eventsByArea: map[string]int{"ops": 3},
			totalEvents:  3,
			wantLen:      2,
			wantAreas: []AreaDrift{
				{Area: "ai", ActiveGoals: 2, EventCount: 0, GoalPercent: 100, EventPercent: 0, DriftPercent: -100},
				{Area: "ops", ActiveGoals: 0, EventCount: 3, GoalPercent: 0, EventPercent: 100, DriftPercent: 100},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := computeAreaDrift(tt.goalsByArea, tt.totalGoals, tt.eventsByArea, tt.totalEvents)

			if len(got) != tt.wantLen {
				t.Fatalf("computeAreaDrift() len = %d, want %d; got %+v", len(got), tt.wantLen, got)
			}

			assertAreaDriftResults(t, tt.name, got, tt.wantAreas)
		})
	}
}

// TestComputeAreaDrift_NoPanic ensures the function never panics on any zero-value
// combination without needing a fuzz harness.
func TestComputeAreaDrift_NoPanic(t *testing.T) {
	t.Parallel()

	cases := []struct {
		goals  map[string]int
		tg     int
		events map[string]int
		te     int
	}{
		{nil, 0, nil, 0},
		{nil, 5, nil, 5},
		{map[string]int{"x": 0}, 0, map[string]int{"x": 0}, 0},
		{map[string]int{"x": 1}, 1, nil, 0},
		{nil, 0, map[string]int{"x": 1}, 1},
	}
	for _, c := range cases {
		// Must not panic.
		_ = computeAreaDrift(c.goals, c.tg, c.events, c.te)
	}
}

// ── Drift percent sort property: result is always sorted by abs(DriftPercent) desc ──

func TestComputeAreaDrift_SortInvariant(t *testing.T) {
	t.Parallel()

	goals := map[string]int{"a": 10, "b": 5, "c": 1}
	events := map[string]int{"a": 1, "b": 10, "c": 5}
	areas := computeAreaDrift(goals, 16, events, 16)

	for i := 1; i < len(areas); i++ {
		prev := math.Abs(areas[i-1].DriftPercent)
		curr := math.Abs(areas[i].DriftPercent)
		if curr > prev {
			t.Errorf("sort invariant violated at index %d: |drift[%d]|=%f > |drift[%d]|=%f",
				i, i, curr, i-1, prev)
		}
	}
}

// ── parseDays clamp unit tests ─────────────────────────────────────────────────

// TestParseDays pins the drift-window bounds: valid in-range values pass
// through, everything else (≤0, >driftMaxDays, non-numeric, empty) falls back to
// driftDefaultDays. Expected values are hand-computed against the [1,90]/30
// contract.
//
// Mutation it catches: changing `d <= 0` to `d < 0` would let 0 through;
// dropping the upper bound would let 91 through; swapping the fallback constant
// would break every out-of-range case.
func TestParseDays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "empty falls back to default", raw: "", want: 30},
		{name: "valid 7", raw: "7", want: 7},
		{name: "lower boundary 1", raw: "1", want: 1},
		{name: "upper boundary 90", raw: "90", want: 90},
		{name: "zero falls back", raw: "0", want: 30},
		{name: "negative falls back", raw: "-5", want: 30},
		{name: "91 exceeds max, falls back", raw: "91", want: 30},
		{name: "non-numeric falls back", raw: "abc", want: 30},
		{name: "float string falls back", raw: "7.5", want: 30},
		{name: "trailing space falls back (Atoi rejects)", raw: "7 ", want: 30},
		{name: "overflow falls back", raw: "9999999999999999999", want: 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseDays(tt.raw); got != tt.want {
				t.Errorf("parseDays(%q) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

// FuzzParseDays verifies parseDays never panics and always returns a value
// inside the valid window [1, driftMaxDays] for arbitrary input. It also
// re-derives the expected result independently (Atoi on the RAW string — no
// trimming, matching parseDays) so a drift in the bounds logic surfaces.
func FuzzParseDays(f *testing.F) {
	for _, seed := range []string{"30", "1", "90", "0", "-1", "91", "", "abc", "7.5", "1e2", "9999999999999999999", " 30 "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := parseDays(raw) // must not panic
		if got < 1 || got > driftMaxDays {
			t.Errorf("parseDays(%q) = %d, outside [1, %d]", raw, got, driftMaxDays)
		}

		// Independent expectation: parseDays does NOT trim, so classify against
		// the raw string exactly as strconv.Atoi sees it.
		d, err := strconv.Atoi(raw)
		want := driftDefaultDays
		if err == nil && d > 0 && d <= driftMaxDays {
			want = d
		}
		if got != want {
			t.Errorf("parseDays(%q) = %d, want %d", raw, got, want)
		}
	})
}

// ── cell-state mapper unit tests ───────────────────────────────────────────────

// TestSuccessRateState pins the three-band success-rate cell state: ≥95 ok,
// ≥80 warn, below error. Boundary values are the ones the UI colour-codes on.
//
// Mutation it catches: using `>` instead of `>=` at a boundary would flip 95 to
// warn and 80 to error.
func TestSuccessRateState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pct  float64
		want string
	}{
		{name: "100 is ok", pct: 100, want: "ok"},
		{name: "95 boundary is ok", pct: 95, want: "ok"},
		{name: "94.9 is warn", pct: 94.9, want: "warn"},
		{name: "80 boundary is warn", pct: 80, want: "warn"},
		{name: "79.9 is error", pct: 79.9, want: "error"},
		{name: "0 is error", pct: 0, want: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := successRateState(tt.pct); got != tt.want {
				t.Errorf("successRateState(%v) = %q, want %q", tt.pct, got, tt.want)
			}
		})
	}
}

// TestNonZeroState pins the zero-vs-elevated cell state: a zero count is always
// "ok", any non-zero count yields the caller-supplied elevated label.
//
// Mutation it catches: returning the elevated label for n==0, or always
// returning "ok", would break the retry/failure warning surfaces.
func TestNonZeroState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		n        int
		elevated string
		want     string
	}{
		{name: "zero is ok regardless of elevated label", n: 0, elevated: "warn", want: "ok"},
		{name: "one with warn label", n: 1, elevated: "warn", want: "warn"},
		{name: "many with error label", n: 17, elevated: "error", want: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := nonZeroState(tt.n, tt.elevated); got != tt.want {
				t.Errorf("nonZeroState(%d, %q) = %q, want %q", tt.n, tt.elevated, got, tt.want)
			}
		})
	}
}

// assertAreaDriftResults checks the computed drift results against expected values.
func assertAreaDriftResults(t *testing.T, testName string, got, wantAreas []AreaDrift) {
	t.Helper()
	// Special case: sorted-by-drift test only checks first element.
	if testName == "sorted by absolute drift descending" {
		if got[0].Area != "a" {
			t.Errorf("computeAreaDrift() first area = %q, want %q", got[0].Area, "a")
		}
		if math.Abs(got[0].DriftPercent-66.666) > 0.1 {
			t.Errorf("computeAreaDrift() first drift = %f, want ~66.7", got[0].DriftPercent)
		}
		return
	}
	if wantAreas == nil {
		return
	}
	opts := cmp.Options{
		cmpopts.EquateApprox(0, 0.0001),
		cmpopts.SortSlices(func(a, b AreaDrift) bool { return a.Area < b.Area }),
	}
	if diff := cmp.Diff(wantAreas, got, opts...); diff != "" {
		t.Errorf("computeAreaDrift() mismatch (-want +got):\n%s", diff)
	}
}

// Track 1B — Today fan-out wire contract.
//
// GET /api/admin/system/health is one of the six Today fan-out sources.
// SystemService.getHealth() → TodayService buildWarnings() consumes
// feeds.failing_feeds[].name / .error and pipelines.failed. These marshaling
// tests pin those nested wire field names (and the null-vs-empty rule on
// failing_feeds) without a database.

func TestSystemHealthSnapshotWireContract(t *testing.T) {
	snap := SystemHealthSnapshot{
		Feeds:     FeedHealth{FailingFeeds: []FailingFeed{{Name: "Go Blog", Error: "timeout"}}},
		Pipelines: PipelineHealth{Failed: 2},
	}
	keys := healthWireKeys(t, snap)

	for _, want := range []string{"feeds", "pipelines", "database"} {
		if _, ok := keys[want]; !ok {
			t.Errorf("SystemHealthSnapshot missing wire field %q", want)
		}
	}

	feeds := healthSub(t, keys["feeds"])
	if _, ok := feeds["failing_feeds"]; !ok {
		t.Fatal("feeds.failing_feeds missing")
	}
	ff := healthFirstItem(t, feeds["failing_feeds"])
	for _, want := range []string{"name", "error"} {
		if _, ok := ff[want]; !ok {
			t.Errorf("failing_feeds[].%s missing (TodayService buildWarnings consumes it)", want)
		}
	}

	pipes := healthSub(t, keys["pipelines"])
	if _, ok := pipes["failed"]; !ok {
		t.Error("pipelines.failed missing (TodayService buildWarnings consumes it)")
	}
}

// TestFailingFeedsEmptyIsArrayNotNull pins null-vs-empty: the store
// initializes FailingFeeds to a non-nil slice, so a healthy system serializes
// "failing_feeds":[] per the json-api rule, never null.
func TestFailingFeedsEmptyIsArrayNotNull(t *testing.T) {
	b, err := json.Marshal(FeedHealth{FailingFeeds: []FailingFeed{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"failing_feeds":[]`)) {
		t.Errorf("empty FeedHealth must serialize \"failing_feeds\":[], got %s", b)
	}
}

func healthWireKeys(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func healthSub(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal sub-object: %v", err)
	}
	return m
}

func healthFirstItem(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal array: %v", err)
	}
	if len(arr) == 0 {
		t.Fatal("array empty")
	}
	return arr[0]
}
