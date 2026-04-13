//go:build integration

package mcp

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Koopa0/koopa0.dev/internal/synthesis"
	"github.com/Koopa0/koopa0.dev/internal/testdb"
)

// TestLivePathDoesNotWriteSynthesis is the runtime proof that the
// synthesis historical substrate is not a cache.
//
// The rule: the live MCP handler path (weekly_summary, goal_progress,
// session_delta, and every other read-oriented tool) MUST NOT touch
// the syntheses table. Only the consolidation path (triggered via
// POST /api/admin/consolidate/weekly or a future cron) may write.
//
// This test exercises the live path directly — calling weeklySummary
// against a fresh database with seeded primary state — and then
// asserts that the syntheses table is still empty. A regression that
// wires cache-aside writes into a live handler would flip the final
// assertion and fail loudly.
//
// It is deliberately placed in package mcp (not mcp_test) so it can
// call the unexported handler directly, matching the pattern of the
// other integration tests in this package.
func TestLivePathDoesNotWriteSynthesis(t *testing.T) {
	pool := testdb.NewPool(t)
	ctx := t.Context()

	// Seed one completed task in the current week so the handler
	// has something to return. We do not care about the specific
	// content — we only care that the handler runs to completion
	// and that syntheses stays empty afterward.
	weekStart := synthesis.MondayOf(time.Now().UTC())
	_, err := pool.Exec(ctx, `
        INSERT INTO tasks (title, status, assignee, completed_at, created_at)
        VALUES ('purity-probe', 'done', 'human', $1, $1)
    `, weekStart.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}

	synthStore := synthesis.NewStore(pool)
	before, err := synthStore.CountByKind(ctx, synthesis.SubjectWeek, synthesis.KindWeeklyReview)
	if err != nil {
		t.Fatalf("count before: %v", err)
	}
	if before != 0 {
		t.Fatalf("syntheses not empty at test start: count = %d", before)
	}

	// Build a real Server wired to the testcontainer pool. The
	// handler executes against real DB queries; this is the most
	// faithful "live path" available short of running the MCP
	// stdio server.
	server := NewServer(pool, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Call weeklySummary through its registered handler. No week_of
	// filter — defaults to the current week.
	_, _, err = server.weeklySummary(ctx, nil, WeeklySummaryInput{})
	if err != nil {
		t.Fatalf("weeklySummary: %v", err)
	}

	// The assertion: live handler must not have written a row.
	after, err := synthStore.CountByKind(ctx, synthesis.SubjectWeek, synthesis.KindWeeklyReview)
	if err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 0 {
		t.Errorf("live weekly_summary wrote %d synthesis row(s); historical substrate must not be written by live handlers", after)
	}
}
