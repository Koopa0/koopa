package learning

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// TestConceptsListWireContract pins the wire shape of one row in
// GET /api/admin/learning/concepts. Marshalled white-box from a
// constructed ConceptListRow — no DB. A rename of any JSON tag breaks
// the Angular concepts catalog page silently.
func TestConceptsListWireContract(t *testing.T) {
	dueAt := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	parent := "two-pointers"

	row := ConceptListRow{
		Slug:         "sliding-window",
		Kind:         "pattern",
		Domain:       "leetcode",
		MasteryStage: StageDeveloping,
		MasteryCounts: SignalCounts{
			Weakness:    5,
			Improvement: 2,
			Mastery:     7,
		},
		ObsCount:   14,
		ParentSlug: &parent,
		NextDueTarget: &ConceptListNextDueTarget{
			ID:    uuid.New(),
			Title: "LC 76",
			DueAt: &dueAt,
		},
	}

	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal top: %v", err)
	}
	for _, want := range []string{
		"slug", "kind", "domain", "mastery_stage", "mastery_counts",
		"obs_count", "parent_slug", "next_due_target",
	} {
		if _, ok := top[want]; !ok {
			t.Errorf("ConceptListRow missing wire field %q", want)
		}
	}

	var counts map[string]json.RawMessage
	if err := json.Unmarshal(top["mastery_counts"], &counts); err != nil {
		t.Fatalf("unmarshal mastery_counts: %v", err)
	}
	for _, want := range []string{"weakness", "improvement", "mastery"} {
		if _, ok := counts[want]; !ok {
			t.Errorf("mastery_counts missing wire field %q", want)
		}
	}

	var target map[string]json.RawMessage
	if err := json.Unmarshal(top["next_due_target"], &target); err != nil {
		t.Fatalf("unmarshal next_due_target: %v", err)
	}
	for _, want := range []string{"id", "title", "due_at"} {
		if _, ok := target[want]; !ok {
			t.Errorf("next_due_target missing wire field %q", want)
		}
	}
}

// TestConceptsListWireContract_NullableFields_AreNullNotOmitted —
// parent_slug and next_due_target are required wire fields; their
// "absent" state is JSON null, NOT omission. A row with no parent and
// no review cards must still expose both keys.
func TestConceptsListWireContract_NullableFields_AreNullNotOmitted(t *testing.T) {
	row := ConceptListRow{
		Slug:          "isolated",
		Kind:          "pattern",
		Domain:        "leetcode",
		MasteryStage:  StageDeveloping,
		MasteryCounts: SignalCounts{},
		ObsCount:      0,
		ParentSlug:    nil,
		NextDueTarget: nil,
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	for _, want := range []string{
		`"parent_slug":null`,
		`"next_due_target":null`,
	} {
		if !contains(got, want) {
			t.Errorf("expected %q in encoded row\nfull JSON: %s", want, got)
		}
	}
}

// TestConceptDetailWireContract pins the wire shape of the
// /concepts/{slug} detail response. Stub arrays (relations,
// linked_notes, linked_contents) MUST encode as `[]`, never null or
// omitted, so the frontend can iterate without a presence check.
func TestConceptDetailWireContract(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	resp := ConceptDetailResponse{
		Slug:         "sliding-window",
		Kind:         "pattern",
		Domain:       "leetcode",
		Name:         "Sliding Window",
		Description:  "Linear-window pattern over a sequence.",
		MasteryStage: StageDeveloping,
		MasteryCounts: SignalCounts{
			Weakness: 5, Improvement: 2, Mastery: 7,
		},
		LowConfidenceCounts: SignalCounts{
			Weakness: 2, Improvement: 0, Mastery: 1,
		},
		Parent:         &NamedConcept{Slug: "two-pointers", Name: "Two Pointers"},
		Children:       []NamedConcept{{Slug: "fixed-window", Name: "Fixed Window"}},
		Relations:      []ConceptDetailRelation{},
		LinkedNotes:    []ConceptDetailLinkedNote{},
		LinkedContents: []ConceptDetailLinkedContent{},
		RecentAttempts: []ConceptDetailRecentAttempt{
			{ID: uuid.New(), TargetTitle: "LC 76", Outcome: "solved_independent", CreatedAt: now},
		},
		RecentObservations: []DashboardRecentObservation{
			{ID: uuid.New(), Signal: "weakness", Category: "state-transition",
				Body: "missed base case", Domain: "leetcode", ConceptSlug: "sliding-window",
				Confidence: "high", CreatedAt: now},
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{
		"slug", "kind", "domain", "name", "description",
		"mastery_stage", "mastery_counts", "low_confidence_counts",
		"parent", "children", "relations", "linked_notes",
		"linked_contents", "recent_attempts", "recent_observations",
	} {
		if _, ok := top[want]; !ok {
			t.Errorf("ConceptDetailResponse missing wire field %q", want)
		}
	}

	// Stub arrays MUST be `[]`, never null.
	asString := string(b)
	for _, want := range []string{
		`"relations":[]`,
		`"linked_notes":[]`,
		`"linked_contents":[]`,
	} {
		if !contains(asString, want) {
			t.Errorf("expected stub field encoded as []: %q\nfull JSON: %s", want, asString)
		}
	}
	for _, never := range []string{
		`"relations":null`,
		`"linked_notes":null`,
		`"linked_contents":null`,
	} {
		if contains(asString, never) {
			t.Errorf("forbidden null encoding: %q\nfull JSON: %s", never, asString)
		}
	}

	// recent_attempts slim shape — exactly four fields, no leakage.
	var attempts []map[string]json.RawMessage
	if err := json.Unmarshal(top["recent_attempts"], &attempts); err != nil {
		t.Fatalf("unmarshal recent_attempts: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("recent_attempts len = %d, want 1", len(attempts))
	}
	for _, want := range []string{"id", "target_title", "outcome", "created_at"} {
		if _, ok := attempts[0][want]; !ok {
			t.Errorf("recent_attempts row missing wire field %q", want)
		}
	}
	for _, forbidden := range []string{"metadata", "external_id", "paradigm", "duration_minutes", "session_id"} {
		if _, present := attempts[0][forbidden]; present {
			t.Errorf("recent_attempts row leaks forbidden field %q", forbidden)
		}
	}

	// recent_observations field names (dashboard-compatible).
	var obs []map[string]json.RawMessage
	if err := json.Unmarshal(top["recent_observations"], &obs); err != nil {
		t.Fatalf("unmarshal recent_observations: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("recent_observations len = %d, want 1", len(obs))
	}
	for _, want := range []string{"id", "signal", "category", "body", "domain", "concept_slug", "confidence", "created_at"} {
		if _, ok := obs[0][want]; !ok {
			t.Errorf("recent_observations row missing wire field %q", want)
		}
	}
	for _, forbidden := range []string{"signal_type", "detail", "severity"} {
		if _, present := obs[0][forbidden]; present {
			t.Errorf("recent_observations row leaks legacy field %q", forbidden)
		}
	}
}

// TestConceptDetail_MissingDomainReturns400 pins handler-level rejection.
// No DB needed — the handler short-circuits before any store call when
// `domain` is absent. The store is nil here on purpose; if the handler
// ever stops short-circuiting, a nil-deref will surface as a panic
// instead of silently 500.
func TestConceptDetail_MissingDomainReturns400(t *testing.T) {
	h := &Handler{logger: slog.Default()}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/learning/concepts/sliding-window", http.NoBody)
	req.SetPathValue("slug", "sliding-window")
	w := httptest.NewRecorder()
	h.ConceptDetail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ConceptDetail without domain status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var body map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if got := body["error"]["code"]; got != "BAD_REQUEST" {
		t.Errorf("error.code = %q, want %q", got, "BAD_REQUEST")
	}
}

// TestConceptsList_RejectsInvalidMasteryStage — unknown
// mastery_stage values are a 400, NOT a silent empty-result.
func TestConceptsList_RejectsInvalidMasteryStage(t *testing.T) {
	h := &Handler{logger: slog.Default()}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/learning/concepts?mastery_stage=bogus", http.NoBody)
	w := httptest.NewRecorder()
	h.ConceptsList(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("ConceptsList(mastery_stage=bogus) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
