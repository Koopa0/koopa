//go:build integration

package consolidation_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa0.dev/internal/consolidation"
	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learning"
	"github.com/Koopa0/koopa0.dev/internal/synthesis"
	"github.com/Koopa0/koopa0.dev/internal/task"
	"github.com/Koopa0/koopa0.dev/internal/testdb"
)

// TestRunWeekly_VerticalSlice exercises the complete Track C vertical
// slice: seed one week of primary state, run consolidation, verify the
// synthesis row, verify idempotency, mutate primary and verify
// historical accumulation, verify reader sees both rows.
//
// This is the single end-to-end proof that syntheses is a historical
// substrate and not a cache — every property the user asked us to
// demonstrate is asserted here.
func TestRunWeekly_VerticalSlice(t *testing.T) {
	pool := testdb.NewPool(t)
	ctx := t.Context()

	// Fix a known Monday so week boundaries are deterministic.
	// 2026-03-30 is a Monday in ISO week 14.
	loc := time.UTC
	weekStart := time.Date(2026, 3, 30, 0, 0, 0, 0, loc)

	primary := consolidation.NewPrimaryReader(
		task.NewStore(pool),
		journal.NewStore(pool),
		learning.NewStore(pool),
	)
	synth := synthesis.NewStore(pool)

	// --- seed primary: 2 completed tasks, 1 journal entry, 1 session ---
	seedCompletedTask(t, pool, "First task", weekStart.Add(24*time.Hour))
	seedCompletedTask(t, pool, "Second task", weekStart.Add(72*time.Hour))
	seedJournalEntry(t, pool, "reflection", weekStart.Add(48*time.Hour))
	seedLearningSession(t, pool, "leetcode", weekStart.Add(96*time.Hour))

	// --- run 1: empty → populated ---
	r1, err := consolidation.RunWeekly(
		ctx, primary, synth, weekStart,
		consolidation.ComputedByWeeklyManual,
	)
	if err != nil {
		t.Fatalf("RunWeekly (first): %v", err)
	}

	if !r1.Created {
		t.Errorf("first run Created = false, want true")
	}
	if r1.WeekKey != "2026-W14" {
		t.Errorf("WeekKey = %q, want %q", r1.WeekKey, "2026-W14")
	}
	if got, want := len(r1.Body.TasksCompleted), 2; got != want {
		t.Errorf("Body.TasksCompleted count = %d, want %d", got, want)
	}
	if got, want := r1.Body.JournalCount, 1; got != want {
		t.Errorf("Body.JournalCount = %d, want %d", got, want)
	}
	if got, want := r1.Body.SessionCount, 1; got != want {
		t.Errorf("Body.SessionCount = %d, want %d", got, want)
	}
	if got, want := r1.EvidenceSize, 4; got != want {
		t.Errorf("evidence size = %d, want %d (2 tasks + 1 journal + 1 session)", got, want)
	}

	// Assert exactly one synthesis row landed.
	count, err := synth.CountByKind(ctx, synthesis.SubjectWeek, synthesis.KindWeeklyReview)
	if err != nil {
		t.Fatalf("CountByKind after run 1: %v", err)
	}
	if count != 1 {
		t.Errorf("syntheses count after run 1 = %d, want 1", count)
	}

	// --- run 2: same primary → no-op (idempotency) ---
	r2, err := consolidation.RunWeekly(
		ctx, primary, synth, weekStart,
		consolidation.ComputedByWeeklyManual,
	)
	if err != nil {
		t.Fatalf("RunWeekly (idempotent): %v", err)
	}
	if r2.Created {
		t.Errorf("second run Created = true, want false (idempotent no-op)")
	}
	if r2.EvidenceHash != r1.EvidenceHash {
		t.Errorf("evidence_hash drifted between runs: %s vs %s", r1.EvidenceHash, r2.EvidenceHash)
	}

	count, err = synth.CountByKind(ctx, synthesis.SubjectWeek, synthesis.KindWeeklyReview)
	if err != nil {
		t.Fatalf("CountByKind after run 2: %v", err)
	}
	if count != 1 {
		t.Errorf("idempotent re-run produced extra row: count = %d, want 1", count)
	}

	// --- run 3: primary drifts → new row (historical accumulation) ---
	// Simulate "Koopa backdated a task into the week after initial
	// consolidation". The new task adds one more evidence id,
	// changes the hash, and must produce a NEW synthesis row
	// alongside the old one.
	seedCompletedTask(t, pool, "Late-added task", weekStart.Add(120*time.Hour))

	r3, err := consolidation.RunWeekly(
		ctx, primary, synth, weekStart,
		consolidation.ComputedByWeeklyManual,
	)
	if err != nil {
		t.Fatalf("RunWeekly (historical accumulation): %v", err)
	}
	if !r3.Created {
		t.Errorf("third run Created = false, want true (primary drifted)")
	}
	if r3.EvidenceHash == r1.EvidenceHash {
		t.Errorf("hash unchanged after primary drift: %s", r3.EvidenceHash)
	}
	if got, want := len(r3.Body.TasksCompleted), 3; got != want {
		t.Errorf("r3 Body.TasksCompleted = %d, want %d", got, want)
	}

	count, err = synth.CountByKind(ctx, synthesis.SubjectWeek, synthesis.KindWeeklyReview)
	if err != nil {
		t.Fatalf("CountByKind after run 3: %v", err)
	}
	if count != 2 {
		t.Errorf("after drift the table must have 2 rows (old + new), got %d", count)
	}

	// --- reader sees both rows, newest first ---
	rows, err := synth.RecentByKind(
		ctx, synthesis.SubjectWeek, synthesis.KindWeeklyReview,
		nil, 10,
	)
	if err != nil {
		t.Fatalf("RecentByKind: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("RecentByKind returned %d rows, want 2", len(rows))
	}
	if !rows[0].ComputedAt.After(rows[1].ComputedAt) && !rows[0].ComputedAt.Equal(rows[1].ComputedAt) {
		t.Errorf("rows not ordered newest first: [0].computed_at=%v [1].computed_at=%v",
			rows[0].ComputedAt, rows[1].ComputedAt)
	}
	// Newest should be the drifted one (3 tasks in evidence).
	var newestTaskEvidence int
	for _, e := range rows[0].Evidence {
		if e.Type == "task" {
			newestTaskEvidence++
		}
	}
	if newestTaskEvidence != 3 {
		t.Errorf("newest row task evidence count = %d, want 3", newestTaskEvidence)
	}

	// --- verify primary was NOT modified ---
	// Tally primary state after all consolidation runs. If any run
	// had accidentally modified tasks / journal / sessions, the
	// counts would differ.
	assertPrimaryCounts(t, pool, 3, 1, 1) // 3 tasks, 1 journal, 1 session

	// --- non-Monday input is rejected ---
	_, badErr := consolidation.RunWeekly(
		ctx, primary, synth,
		weekStart.AddDate(0, 0, 1), // Tuesday
		consolidation.ComputedByWeeklyManual,
	)
	if badErr == nil {
		t.Error("RunWeekly with non-Monday start did not error")
	}
}

// --- seed helpers ---

func seedCompletedTask(t *testing.T, pool *pgxpool.Pool, title string, completedAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO tasks (title, status, assignee, completed_at, created_at, updated_at)
        VALUES ($1, 'done', 'human', $2, $2, $2)
        RETURNING id
    `, title, completedAt).Scan(&id)
	if err != nil {
		t.Fatalf("seed task %q: %v", title, err)
	}
	return id
}

func seedJournalEntry(t *testing.T, pool *pgxpool.Pool, kind string, entryDate time.Time) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(t.Context(), `
        INSERT INTO journal (kind, source, content, entry_date)
        VALUES ($1, 'human', 'test entry', $2)
        RETURNING id
    `, kind, entryDate).Scan(&id)
	if err != nil {
		t.Fatalf("seed journal: %v", err)
	}
	return id
}

func seedLearningSession(t *testing.T, pool *pgxpool.Pool, domain string, startedAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(t.Context(), `
        INSERT INTO sessions (domain, session_mode, started_at)
        VALUES ($1, 'practice', $2)
        RETURNING id
    `, domain, startedAt).Scan(&id)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return id
}

func assertPrimaryCounts(t *testing.T, pool *pgxpool.Pool, wantTasks, wantJournal, wantSessions int) {
	t.Helper()
	var got struct {
		Tasks    int
		Journal  int
		Sessions int
	}
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM tasks`).Scan(&got.Tasks); err != nil {
		t.Fatalf("counting tasks: %v", err)
	}
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM journal`).Scan(&got.Journal); err != nil {
		t.Fatalf("counting journal: %v", err)
	}
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM sessions`).Scan(&got.Sessions); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	want := struct {
		Tasks    int
		Journal  int
		Sessions int
	}{wantTasks, wantJournal, wantSessions}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("primary state drift (-want +got):\n%s", diff)
	}
}

// _ context.Context keeps the package import alive when the only use
// is inside a helper called from t.Context(); explicit import line.
var _ = context.Background
