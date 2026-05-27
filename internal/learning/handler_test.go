package learning

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Track 1B — Today fan-out wire contract.
//
// GET /api/admin/learning/summary is one of the six Today fan-out sources.
// LearningService.summary() → TodayService consumes the due_reviews field.
// learningSummaryResponse is unexported, so this is a white-box test pinning
// the wire field names without a database — a rename of due_reviews breaks the
// Today review badge silently.

func TestLearningSummaryWireContract(t *testing.T) {
	resp := learningSummaryResponse{
		StreakDays: 4,
		DueReviews: 3,
		Domains:    []DomainMastery{},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{"streak_days", "due_reviews", "domains"} {
		if _, ok := m[want]; !ok {
			t.Errorf("learningSummaryResponse missing wire field %q (TodayService consumes due_reviews)", want)
		}
	}
}

// TestDashboardWireContract pins the wire shape of GET /api/admin/learning/dashboard.
// Marshalled white-box from constructed DTOs — no DB required. Asserts every
// field name in api-spec.md §4.1 is present and that empty slices/maps encode
// as `[]` / `{}` (NEVER `null`).
//
// Any rename of these JSON tags breaks the Angular admin Learning dashboard
// page silently — this test surfaces the rename at unit-test time.
func TestDashboardWireContract(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	nextDue := now.Add(48 * time.Hour)
	lastReviewedAt := now.Add(-7 * 24 * time.Hour)

	resp := DashboardResponse{
		StreakDays:      4,
		DueReviewsCount: 3,
		Concepts: DashboardConcepts{
			CountTotal:     1,
			CountsByDomain: map[string]int{"leetcode": 1},
			Rows: []DashboardConceptRow{
				{
					Slug:         "sliding-window",
					Kind:         "pattern",
					Domain:       "leetcode",
					ObsCount:     14,
					MasteryValue: 0.5,
					MasteryStage: StageDeveloping,
					NextDue:      &nextDue,
				},
			},
		},
		DueToday: DashboardDueToday{
			Count: 1,
			Items: []DashboardDueTodayItem{
				{
					CardID: uuid.New(),
					Target: DashboardDueTodayTarget{
						ID:    uuid.New(),
						Title: "LC 76",
					},
					Domain:         "leetcode",
					Retention:      0.62,
					LastReviewedAt: &lastReviewedAt,
				},
			},
		},
		RecentObservations: []DashboardRecentObservation{
			{
				ID:          uuid.New(),
				Signal:      "weakness",
				Category:    "state-transition",
				Body:        "missed the base case",
				Domain:      "leetcode",
				ConceptSlug: "dp",
				Confidence:  "high",
				CreatedAt:   now,
			},
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Top-level field set.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal top: %v", err)
	}
	for _, want := range []string{"streak_days", "due_reviews_count", "concepts", "due_today", "recent_observations"} {
		if _, ok := top[want]; !ok {
			t.Errorf("DashboardResponse missing top-level wire field %q", want)
		}
	}

	// concepts envelope.
	var concepts map[string]json.RawMessage
	if err := json.Unmarshal(top["concepts"], &concepts); err != nil {
		t.Fatalf("unmarshal concepts: %v", err)
	}
	for _, want := range []string{"count_total", "counts_by_domain", "rows"} {
		if _, ok := concepts[want]; !ok {
			t.Errorf("concepts envelope missing wire field %q", want)
		}
	}

	// concept row.
	var conceptRows []map[string]json.RawMessage
	if err := json.Unmarshal(concepts["rows"], &conceptRows); err != nil {
		t.Fatalf("unmarshal concepts.rows: %v", err)
	}
	if len(conceptRows) != 1 {
		t.Fatalf("concepts.rows len = %d, want 1", len(conceptRows))
	}
	for _, want := range []string{"slug", "kind", "domain", "obs_count", "mastery_value", "mastery_stage", "next_due"} {
		if _, ok := conceptRows[0][want]; !ok {
			t.Errorf("concept row missing wire field %q", want)
		}
	}

	// due_today envelope.
	var dueToday map[string]json.RawMessage
	if err := json.Unmarshal(top["due_today"], &dueToday); err != nil {
		t.Fatalf("unmarshal due_today: %v", err)
	}
	for _, want := range []string{"count", "items"} {
		if _, ok := dueToday[want]; !ok {
			t.Errorf("due_today envelope missing wire field %q", want)
		}
	}

	// due_today item.
	var dueItems []map[string]json.RawMessage
	if err := json.Unmarshal(dueToday["items"], &dueItems); err != nil {
		t.Fatalf("unmarshal due_today.items: %v", err)
	}
	if len(dueItems) != 1 {
		t.Fatalf("due_today.items len = %d, want 1", len(dueItems))
	}
	for _, want := range []string{"card_id", "target", "domain", "retention", "last_reviewed_at"} {
		if _, ok := dueItems[0][want]; !ok {
			t.Errorf("due_today item missing wire field %q", want)
		}
	}

	// due_today.items[0].target nested object.
	var target map[string]json.RawMessage
	if err := json.Unmarshal(dueItems[0]["target"], &target); err != nil {
		t.Fatalf("unmarshal due_today.items[0].target: %v", err)
	}
	for _, want := range []string{"id", "title"} {
		if _, ok := target[want]; !ok {
			t.Errorf("due_today item target missing wire field %q", want)
		}
	}

	// recent_observations row.
	var obs []map[string]json.RawMessage
	if err := json.Unmarshal(top["recent_observations"], &obs); err != nil {
		t.Fatalf("unmarshal recent_observations: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("recent_observations len = %d, want 1", len(obs))
	}
	for _, want := range []string{"id", "signal", "category", "body", "domain", "concept_slug", "confidence", "created_at"} {
		if _, ok := obs[0][want]; !ok {
			t.Errorf("recent_observation row missing wire field %q", want)
		}
	}
}

// TestDashboardWireContract_EmptyEncoding asserts that an "empty"
// dashboard response — no concepts, no due items, no recent
// observations — encodes its containers as `[]` / `{}`, never as `null`.
// json-api.md is explicit: list/map fields must NEVER be null.
func TestDashboardWireContract_EmptyEncoding(t *testing.T) {
	resp := DashboardResponse{
		Concepts:           emptyDashboardConcepts(),
		DueToday:           emptyDashboardDueToday(),
		RecentObservations: []DashboardRecentObservation{},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"counts_by_domain":{}`,
		`"rows":[]`,
		`"items":[]`,
		`"recent_observations":[]`,
	} {
		if !contains(got, want) {
			t.Errorf("empty dashboard JSON missing %q\nfull JSON: %s", want, got)
		}
	}
	// And NEVER null for any of these fields.
	for _, never := range []string{
		`"counts_by_domain":null`,
		`"rows":null`,
		`"items":null`,
		`"recent_observations":null`,
	} {
		if contains(got, never) {
			t.Errorf("empty dashboard JSON has forbidden %q\nfull JSON: %s", never, got)
		}
	}
}

// contains is a tiny strings.Contains alias to keep the imports minimal
// inside a wire-shape unit test that already pulls encoding/json.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestMasteryValueFormula pins the formula and the deliberate absence
// of the MinObservationsForVerdict floor. The floor lives only in
// DeriveMasteryStage; mastery_value is a raw ratio so the dashboard's
// percentage gauge renders honestly even at low observation counts.
func TestMasteryValueFormula(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		mastery, total int64
		want           float64
	}{
		{name: "zero / zero — protected by total==0 guard", mastery: 0, total: 0, want: 0.0},
		{name: "zero mastery, nonzero total", mastery: 0, total: 5, want: 0.0},
		{name: "30% mastery", mastery: 3, total: 10, want: 0.3},
		{name: "70% mastery", mastery: 7, total: 10, want: 0.7},
		{name: "single mastery, single total — NO <3 floor", mastery: 2, total: 2, want: 1.0},
		{name: "1/1 also bypasses floor", mastery: 1, total: 1, want: 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := MasteryValue(tt.mastery, tt.total)
			if got != tt.want {
				t.Errorf("MasteryValue(mastery=%d, total=%d) = %v, want %v",
					tt.mastery, tt.total, got, tt.want)
			}
		})
	}
}
