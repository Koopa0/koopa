package learning

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/content"
)

func TestTimeline_GroupsByDay(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp", "ac-independent", "leetcode"}, CreatedAt: base},
		{ID: uuid.New(), Slug: "b", Title: "B", Tags: []string{"graph", "ac-with-hints", "leetcode"}, CreatedAt: base.Add(2 * time.Hour)},
		{ID: uuid.New(), Slug: "c", Title: "C", Tags: []string{"dp", "incomplete", "leetcode"}, CreatedAt: base.AddDate(0, 0, -1)},
	}

	result := Timeline(entries, base)

	if len(result.Days) != 2 {
		t.Fatalf("Timeline() Days len = %d, want 2", len(result.Days))
	}
	// Most recent day first.
	if result.Days[0].Date != "2026-03-25" {
		t.Errorf("Days[0].Date = %q, want %q", result.Days[0].Date, "2026-03-25")
	}
	if len(result.Days[0].Entries) != 2 {
		t.Errorf("Days[0] entries = %d, want 2", len(result.Days[0].Entries))
	}
	if result.Days[1].Date != "2026-03-24" {
		t.Errorf("Days[1].Date = %q, want %q", result.Days[1].Date, "2026-03-24")
	}
	if len(result.Days[1].Entries) != 1 {
		t.Errorf("Days[1] entries = %d, want 1", len(result.Days[1].Entries))
	}
}

func TestTimeline_Summary(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp", "ac-independent", "leetcode"}, CreatedAt: base},
		{ID: uuid.New(), Slug: "b", Title: "B", Tags: []string{"graph", "ac-with-hints", "leetcode"}, CreatedAt: base.Add(2 * time.Hour)},
		{ID: uuid.New(), Slug: "c", Title: "C", Tags: []string{"dp", "incomplete", "leetcode"}, CreatedAt: base.AddDate(0, 0, -1)},
	}

	result := Timeline(entries, base)

	if result.Summary.TotalEntries != 3 {
		t.Errorf("TotalEntries = %d, want 3", result.Summary.TotalEntries)
	}
	if result.Summary.ActiveDays != 2 {
		t.Errorf("ActiveDays = %d, want 2", result.Summary.ActiveDays)
	}
	if result.Summary.CurrentStreak != 2 {
		t.Errorf("CurrentStreak = %d, want 2", result.Summary.CurrentStreak)
	}
}

func TestTimeline_StreakSkipsToday(t *testing.T) {
	t.Parallel()

	// Today has no entries, yesterday and day before do.
	now := time.Date(2026, 3, 27, 10, 0, 0, 0, time.UTC)
	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp"}, CreatedAt: now.AddDate(0, 0, -1)},
		{ID: uuid.New(), Slug: "b", Title: "B", Tags: []string{"dp"}, CreatedAt: now.AddDate(0, 0, -2)},
	}

	result := Timeline(entries, now)

	if result.Summary.CurrentStreak != 2 {
		t.Errorf("CurrentStreak = %d, want 2 (yesterday + day before)", result.Summary.CurrentStreak)
	}
}

func TestTimeline_StreakBrokenByGap(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 27, 10, 0, 0, 0, time.UTC)
	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp"}, CreatedAt: now},                   // today
		{ID: uuid.New(), Slug: "b", Title: "B", Tags: []string{"dp"}, CreatedAt: now.AddDate(0, 0, -2)}, // 2 days ago (gap at -1)
	}

	result := Timeline(entries, now)

	if result.Summary.CurrentStreak != 1 {
		t.Errorf("CurrentStreak = %d, want 1 (only today, gap breaks streak)", result.Summary.CurrentStreak)
	}
}

func TestTimeline_Empty(t *testing.T) {
	t.Parallel()

	result := Timeline(nil, time.Now())

	if result.Summary.TotalEntries != 0 {
		t.Errorf("TotalEntries = %d, want 0", result.Summary.TotalEntries)
	}
	if result.Summary.CurrentStreak != 0 {
		t.Errorf("CurrentStreak = %d, want 0", result.Summary.CurrentStreak)
	}
	if len(result.Days) != 0 {
		t.Errorf("Days len = %d, want 0", len(result.Days))
	}
}

func TestTimeline_ExtractsMetadata(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		"learning_type": "leetcode",
		"weakness_observations": []any{
			map[string]any{"tag": "weakness:x", "observation": "missed edge case", "status": "new"},
		},
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}

	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp"}, AIMetadata: metadataJSON, CreatedAt: time.Now()},
	}

	result := Timeline(entries, time.Now())

	if len(result.Days) != 1 || len(result.Days[0].Entries) != 1 {
		t.Fatalf("expected 1 day with 1 entry, got %d days", len(result.Days))
	}
	entry := result.Days[0].Entries[0]
	if entry.LearningType != "leetcode" {
		t.Errorf("LearningType = %q, want %q", entry.LearningType, "leetcode")
	}
	wantObs := []WeaknessObservation{{Tag: "weakness:x", Observation: "missed edge case", Status: "new"}}
	if diff := cmp.Diff(wantObs, entry.WeaknessObservations); diff != "" {
		t.Errorf("WeaknessObservations mismatch (-want +got):\n%s", diff)
	}
}

func TestTimeline_NilMetadataGraceful(t *testing.T) {
	t.Parallel()

	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp", "ac-independent"}, CreatedAt: time.Now()},
	}

	result := Timeline(entries, time.Now())

	entry := result.Days[0].Entries[0]
	if entry.LearningType != "" {
		t.Errorf("LearningType = %q, want empty", entry.LearningType)
	}
	if entry.WeaknessObservations != nil {
		t.Errorf("WeaknessObservations = %v, want nil", entry.WeaknessObservations)
	}
}

func TestTimeline_ResultExtraction(t *testing.T) {
	t.Parallel()

	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp", "ac-independent"}, CreatedAt: time.Now()},
		{ID: uuid.New(), Slug: "b", Title: "B", Tags: []string{"graph"}, CreatedAt: time.Now()}, // no result tag
	}

	result := Timeline(entries, time.Now())

	if len(result.Days[0].Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Days[0].Entries))
	}
	if result.Days[0].Entries[0].Result != "ac-independent" {
		t.Errorf("Entries[0].Result = %q, want %q", result.Days[0].Entries[0].Result, "ac-independent")
	}
	if result.Days[0].Entries[1].Result != "" {
		t.Errorf("Entries[1].Result = %q, want empty", result.Days[0].Entries[1].Result)
	}
}

func TestTimeline_ByProjectCounts(t *testing.T) {
	t.Parallel()

	now := time.Now()
	entries := []content.RichTagEntry{
		{ID: uuid.New(), Slug: "a", Title: "A", Tags: []string{"dp"}, ProjectSlug: "leetcode", CreatedAt: now},
		{ID: uuid.New(), Slug: "b", Title: "B", Tags: []string{"graph"}, ProjectSlug: "leetcode", CreatedAt: now},
		{ID: uuid.New(), Slug: "c", Title: "C", Tags: []string{"chapter-5"}, ProjectSlug: "ddia", CreatedAt: now},
		{ID: uuid.New(), Slug: "d", Title: "D", Tags: []string{"dp"}, CreatedAt: now}, // no project
	}

	result := Timeline(entries, now)

	want := map[string]int{"leetcode": 2, "ddia": 1}
	if diff := cmp.Diff(want, result.Summary.ByProject, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("ByProject mismatch (-want +got):\n%s", diff)
	}
}
