// Copyright 2026 Koopa. All rights reserved.

//go:build integration

package stats

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/testdb"
)

// TestStore_LastAgentScheduleRuns_Integration exercises the read query that
// powers system_status.last_agent_schedule_runs. The query reduces every
// process_runs(kind='agent_schedule') row to one entry per agent, keyed on
// the leading agent token of process_runs.name, with value = MAX(started_at).
// Behaviour pinned:
//   - Multiple runs for the same agent collapse to the latest started_at.
//   - Rows with other kinds (crawl) are ignored.
//   - Rows still pending (started_at IS NULL) do not contribute.
//   - An agent without any agent_schedule row is absent — the MCP layer
//     overlays registry expectations on top of this read.
func TestStore_LastAgentScheduleRuns_Integration(t *testing.T) {
	pool := testdb.NewPool(t)
	ctx := t.Context()

	seedAgent(t, ctx, pool, "planner", "claude-cowork")
	seedAgent(t, ctx, pool, "learning-studio", "claude-cowork")
	seedAgent(t, ctx, pool, "fixture-lab", "claude-cowork")

	// planner — three runs; the latest (08:00) is what we expect to read.
	hqEarliest := time.Date(2026, time.May, 25, 8, 0, 0, 0, time.UTC)
	hqMiddle := time.Date(2026, time.May, 26, 8, 0, 0, 0, time.UTC)
	hqLatest := time.Date(2026, time.May, 27, 8, 0, 0, 0, time.UTC)
	insertCompletedAgentScheduleRun(t, ctx, pool, "planner:morning-briefing", "claude-cowork", hqEarliest)
	insertCompletedAgentScheduleRun(t, ctx, pool, "planner:morning-briefing", "claude-cowork", hqMiddle)
	insertCompletedAgentScheduleRun(t, ctx, pool, "planner:morning-briefing", "claude-cowork", hqLatest)

	// learning-studio — single completed run.
	learningRun := time.Date(2026, time.May, 27, 14, 0, 0, 0, time.UTC)
	insertCompletedAgentScheduleRun(t, ctx, pool, "learning-studio:weekly-review", "claude-cowork", learningRun)

	// fixture-lab — only a pending row (started_at IS NULL). The query
	// must skip it; fixture-lab must NOT appear in the result.
	insertPendingAgentScheduleRun(t, ctx, pool, "fixture-lab:industry-scan", "claude-cowork")

	// An unrelated crawl run — must be ignored by the query.
	insertCompletedCrawlRun(t, ctx, pool, "rss-feed-collector", time.Date(2026, time.May, 27, 12, 0, 0, 0, time.UTC))

	store := NewStore(pool)
	got, err := store.LastAgentScheduleRuns(ctx)
	if err != nil {
		t.Fatalf("LastAgentScheduleRuns(ctx) error = %v, want nil", err)
	}

	want := map[string]time.Time{
		"planner":         hqLatest,
		"learning-studio": learningRun,
	}

	if diff := cmp.Diff(want, got, cmp.Comparer(func(a, b time.Time) bool { return a.Equal(b) })); diff != "" {
		t.Errorf("LastAgentScheduleRuns() mismatch (-want +got):\n%s", diff)
	}
}

// TestStore_LastAgentScheduleRuns_Empty pins the empty-DB behaviour:
// no agent_schedule rows → empty (but non-nil) map. The MCP layer relies
// on this to overlay registry expectations on a fresh deployment.
func TestStore_LastAgentScheduleRuns_Empty(t *testing.T) {
	pool := testdb.NewPool(t)
	ctx := t.Context()

	store := NewStore(pool)
	got, err := store.LastAgentScheduleRuns(ctx)
	if err != nil {
		t.Fatalf("LastAgentScheduleRuns(ctx) error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("LastAgentScheduleRuns() returned nil map on empty DB, want empty map")
	}
	if len(got) != 0 {
		t.Errorf("LastAgentScheduleRuns() on empty DB = %v, want empty map", got)
	}
}

// seedAgent inserts an agents row. process_runs has no FK to agents but
// activity_events does; the audit trigger fires on every process_runs
// insert, so we keep agent fixtures present to avoid surprises if the
// audit chain grows new dependencies.
func seedAgent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, platform string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
        INSERT INTO agents (name, display_name, platform, description, status)
        VALUES ($1, $1, $2, 'integration fixture', 'active')
        ON CONFLICT (name) DO NOTHING
    `, name, platform)
	if err != nil {
		t.Fatalf("seedAgent(%q): %v", name, err)
	}
}

// insertCompletedAgentScheduleRun writes one terminal agent_schedule row.
// The CHECK constraints require error IS NULL on completed, ended_at NOT
// NULL on terminal states, and subsystem NOT NULL when kind='agent_schedule'.
func insertCompletedAgentScheduleRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, subsystem string, startedAt time.Time) {
	t.Helper()
	endedAt := startedAt.Add(10 * time.Second)
	_, err := pool.Exec(ctx, `
        INSERT INTO process_runs (id, kind, subsystem, name, status, started_at, ended_at)
        VALUES ($1, 'agent_schedule', $2, $3, 'completed', $4, $5)
    `, uuid.New(), subsystem, name, startedAt, endedAt)
	if err != nil {
		t.Fatalf("insertCompletedAgentScheduleRun(%q, %v): %v", name, startedAt, err)
	}
}

// insertPendingAgentScheduleRun writes a row with started_at IS NULL —
// the read query must skip it.
func insertPendingAgentScheduleRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, subsystem string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
        INSERT INTO process_runs (id, kind, subsystem, name, status)
        VALUES ($1, 'agent_schedule', $2, $3, 'pending')
    `, uuid.New(), subsystem, name)
	if err != nil {
		t.Fatalf("insertPendingAgentScheduleRun(%q): %v", name, err)
	}
}

// insertCompletedCrawlRun writes one terminal crawl row — a negative
// fixture that the agent_schedule query must filter out.
func insertCompletedCrawlRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, startedAt time.Time) {
	t.Helper()
	endedAt := startedAt.Add(5 * time.Second)
	_, err := pool.Exec(ctx, `
        INSERT INTO process_runs (id, kind, name, status, started_at, ended_at)
        VALUES ($1, 'crawl', $2, 'completed', $3, $4)
    `, uuid.New(), name, startedAt, endedAt)
	if err != nil {
		t.Fatalf("insertCompletedCrawlRun(%q): %v", name, err)
	}
}
