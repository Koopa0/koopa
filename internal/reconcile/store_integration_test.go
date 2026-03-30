//go:build integration

package reconcile

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa0.dev/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setupStore(t *testing.T) *Store {
	t.Helper()
	testdb.Truncate(t, testPool, "reconcile_runs")
	return NewStore(testPool)
}

// emptyReport is a Report with no drift.
var emptyReport = &Report{}

// TestSaveAndRecentRuns_RoundTrip inserts a run and reads it back, verifying all fields.
func TestSaveAndRecentRuns_RoundTrip(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	startedAt := time.Now().UTC().Truncate(time.Microsecond)
	completedAt := startedAt.Add(2 * time.Second)

	report := &Report{
		ObsidianMissing:  []string{"slug-a", "slug-b"},
		ObsidianOrphaned: []string{"slug-old"},
		ProjectsMissing:  []string{"proj-1"},
		ProjectsOrphaned: []string{"proj-orphan"},
		GoalsMissing:     []string{"goal-x", "goal-y"},
		GoalsOrphaned:    nil,
	}
	errs := []string{"timeout on github api"}

	id, err := s.SaveRun(ctx, startedAt, completedAt, report, errs)
	if err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if id == 0 {
		t.Fatal("SaveRun() returned id 0")
	}

	runs, err := s.RecentRuns(ctx, 10)
	if err != nil {
		t.Fatalf("RecentRuns() error: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("RecentRuns() count = %d, want 1", len(runs))
	}

	got := runs[0]

	if got.ID != id {
		t.Errorf("RecentRuns()[0].ID = %d, want %d", got.ID, id)
	}
	if got.ObsidianMissing != 2 {
		t.Errorf("RecentRuns()[0].ObsidianMissing = %d, want 2", got.ObsidianMissing)
	}
	if got.ObsidianOrphaned != 1 {
		t.Errorf("RecentRuns()[0].ObsidianOrphaned = %d, want 1", got.ObsidianOrphaned)
	}
	if got.NotionProjMissing != 1 {
		t.Errorf("RecentRuns()[0].NotionProjMissing = %d, want 1", got.NotionProjMissing)
	}
	if got.NotionProjOrphan != 1 {
		t.Errorf("RecentRuns()[0].NotionProjOrphan = %d, want 1", got.NotionProjOrphan)
	}
	if got.NotionGoalMissing != 2 {
		t.Errorf("RecentRuns()[0].NotionGoalMissing = %d, want 2", got.NotionGoalMissing)
	}
	if got.NotionGoalOrphan != 0 {
		t.Errorf("RecentRuns()[0].NotionGoalOrphan = %d, want 0", got.NotionGoalOrphan)
	}
	if got.TotalDrift != 7 {
		t.Errorf("RecentRuns()[0].TotalDrift = %d, want 7 (2+1+1+1+2+0)", got.TotalDrift)
	}
	if got.ErrorCount != 1 {
		t.Errorf("RecentRuns()[0].ErrorCount = %d, want 1", got.ErrorCount)
	}
	if got.CompletedAt == nil {
		t.Fatal("RecentRuns()[0].CompletedAt = nil, want non-nil")
	}
}

// TestSaveRun_WithErrors verifies that error strings are persisted as JSON.
func TestSaveRun_WithErrors(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	errs := []string{"github timeout", "notion rate limit", "db connection lost"}
	_, err := s.SaveRun(ctx, time.Now(), time.Now(), emptyReport, errs)
	if err != nil {
		t.Fatalf("SaveRun() with errors error: %v", err)
	}

	runs, err := s.RecentRuns(ctx, 1)
	if err != nil {
		t.Fatalf("RecentRuns() error: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("RecentRuns() returned no runs")
	}

	got := runs[0]
	if got.ErrorCount != 3 {
		t.Errorf("RecentRuns()[0].ErrorCount = %d, want 3", got.ErrorCount)
	}
	if got.Errors == nil {
		t.Fatal("RecentRuns()[0].Errors = nil, want JSON array")
	}

	var parsedErrs []string
	if unmarshalErr := json.Unmarshal(got.Errors, &parsedErrs); unmarshalErr != nil {
		t.Fatalf("json.Unmarshal(Errors) error: %v", unmarshalErr)
	}

	if diff := cmp.Diff(errs, parsedErrs); diff != "" {
		t.Errorf("RecentRuns()[0].Errors mismatch (-want +got):\n%s", diff)
	}
}

// TestSaveRun_EmptyReport verifies that a zero-drift run stores all counts as zero.
func TestSaveRun_EmptyReport(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.SaveRun(ctx, time.Now(), time.Now(), emptyReport, nil)
	if err != nil {
		t.Fatalf("SaveRun() empty report error: %v", err)
	}

	runs, err := s.RecentRuns(ctx, 1)
	if err != nil {
		t.Fatalf("RecentRuns() error: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("RecentRuns() returned no runs")
	}

	got := runs[0]
	want := RunRecord{
		// ID, StartedAt, CompletedAt, CreatedAt are dynamic — ignored below.
		ObsidianMissing:   0,
		ObsidianOrphaned:  0,
		NotionProjMissing: 0,
		NotionProjOrphan:  0,
		NotionGoalMissing: 0,
		NotionGoalOrphan:  0,
		TotalDrift:        0,
		ErrorCount:        0,
		Errors:            nil,
	}

	opts := cmp.Options{
		cmpopts.IgnoreFields(RunRecord{}, "ID", "StartedAt", "CompletedAt", "CreatedAt"),
	}
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("SaveRun(empty) mismatch (-want +got):\n%s", diff)
	}
}

// TestRecentRuns_RespectsLimit verifies that the limit parameter is honoured.
func TestRecentRuns_RespectsLimit(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	// Insert 5 runs.
	for range 5 {
		if _, err := s.SaveRun(ctx, time.Now(), time.Now(), emptyReport, nil); err != nil {
			t.Fatalf("SaveRun() setup error: %v", err)
		}
	}

	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "limit 1", limit: 1, want: 1},
		{name: "limit 3", limit: 3, want: 3},
		{name: "limit 5", limit: 5, want: 5},
		{name: "limit 10 (more than exist)", limit: 10, want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runs, err := s.RecentRuns(ctx, tt.limit)
			if err != nil {
				t.Fatalf("RecentRuns(%d) error: %v", tt.limit, err)
			}
			if len(runs) != tt.want {
				t.Errorf("RecentRuns(%d) count = %d, want %d", tt.limit, len(runs), tt.want)
			}
		})
	}
}

// TestRecentRuns_OrderedByStartedAtDesc verifies newest runs appear first.
func TestRecentRuns_OrderedByStartedAtDesc(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	base := time.Now().UTC()

	// Insert three runs with explicit, strictly increasing started_at times.
	times := []time.Time{
		base.Add(-2 * time.Second),
		base.Add(-1 * time.Second),
		base,
	}
	for _, ts := range times {
		if _, err := s.SaveRun(ctx, ts, ts.Add(100*time.Millisecond), emptyReport, nil); err != nil {
			t.Fatalf("SaveRun() error: %v", err)
		}
	}

	runs, err := s.RecentRuns(ctx, 10)
	if err != nil {
		t.Fatalf("RecentRuns() error: %v", err)
	}
	if len(runs) != 3 {
		t.Fatalf("RecentRuns() count = %d, want 3", len(runs))
	}

	// runs[0] should have the most recent started_at (base), runs[2] the oldest.
	for i := 1; i < len(runs); i++ {
		if !runs[i-1].StartedAt.After(runs[i].StartedAt) && !runs[i-1].StartedAt.Equal(runs[i].StartedAt) {
			t.Errorf("RecentRuns() not ordered desc: runs[%d].StartedAt (%v) <= runs[%d].StartedAt (%v)",
				i-1, runs[i-1].StartedAt, i, runs[i].StartedAt)
		}
	}
}

// TestRecentRuns_Empty verifies that an empty table returns a non-nil empty slice.
func TestRecentRuns_Empty(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	runs, err := s.RecentRuns(ctx, 10)
	if err != nil {
		t.Fatalf("RecentRuns() on empty table error: %v", err)
	}
	if runs == nil {
		t.Error("RecentRuns() = nil, want empty slice")
	}
	if len(runs) != 0 {
		t.Errorf("RecentRuns() count = %d, want 0", len(runs))
	}
}

// TestSaveRun_TotalDrift_ComputedCorrectly verifies the total drift sum is accurate.
func TestSaveRun_TotalDrift_ComputedCorrectly(t *testing.T) {
	tests := []struct {
		name      string
		report    *Report
		wantDrift int
	}{
		{
			name:      "all zero",
			report:    emptyReport,
			wantDrift: 0,
		},
		{
			name: "only obsidian missing",
			report: &Report{
				ObsidianMissing: []string{"a", "b", "c"},
			},
			wantDrift: 3,
		},
		{
			name: "all six buckets populated",
			report: &Report{
				ObsidianMissing:  []string{"a", "b"},
				ObsidianOrphaned: []string{"c"},
				ProjectsMissing:  []string{"d"},
				ProjectsOrphaned: []string{"e", "f"},
				GoalsMissing:     []string{"g"},
				GoalsOrphaned:    []string{"h", "i"},
			},
			wantDrift: 9, // 2+1+1+2+1+2=9
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := setupStore(t)
			ctx := t.Context()

			_, err := s.SaveRun(ctx, time.Now(), time.Now(), tt.report, nil)
			if err != nil {
				t.Fatalf("SaveRun() error: %v", err)
			}

			runs, err := s.RecentRuns(ctx, 1)
			if err != nil {
				t.Fatalf("RecentRuns() error: %v", err)
			}
			if len(runs) == 0 {
				t.Fatal("RecentRuns() returned no runs")
			}

			if runs[0].TotalDrift != tt.wantDrift {
				t.Errorf("SaveRun(%q).TotalDrift = %d, want %d", tt.name, runs[0].TotalDrift, tt.wantDrift)
			}
		})
	}
}

// TestSaveRun_NilErrors verifies that nil errors produce nil Errors JSON field.
func TestSaveRun_NilErrors(t *testing.T) {
	s := setupStore(t)
	ctx := t.Context()

	_, err := s.SaveRun(ctx, time.Now(), time.Now(), emptyReport, nil)
	if err != nil {
		t.Fatalf("SaveRun(nil errs) error: %v", err)
	}

	runs, err := s.RecentRuns(ctx, 1)
	if err != nil {
		t.Fatalf("RecentRuns() error: %v", err)
	}
	if len(runs) == 0 {
		t.Fatal("RecentRuns() returned no runs")
	}

	if runs[0].Errors != nil {
		t.Errorf("RecentRuns()[0].Errors = %s, want nil", runs[0].Errors)
	}
}

// errorsIs is declared to satisfy the linter — errors is used only for sentinel checks.
var _ = errors.Is
