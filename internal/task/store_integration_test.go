//go:build integration

package task

import (
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

func setup(t *testing.T) *Store {
	t.Helper()
	if err := testdb.TruncateCtx(t.Context(), testPool, "tasks"); err != nil {
		t.Fatal(err)
	}
	return NewStore(testPool)
}

func TestUpsertByNotionPageID_InsertAndRead(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	due := time.Date(2026, 3, 25, 0, 0, 0, 0, time.UTC)
	params := &UpsertByNotionParams{
		Title:        "Write integration tests",
		Status:       StatusTodo,
		Due:          &due,
		NotionPageID: "notion-page-001",
		Assignee:     "human",
		Energy:       "high",
		Priority:     "P1",
		MyDay:        true,
		Description:  "Cover task and note stores",
	}

	created, err := s.UpsertByNotionPageID(ctx, params)
	if err != nil {
		t.Fatalf("UpsertByNotionPageID(insert) error: %v", err)
	}
	if created.ID.String() == "" {
		t.Fatal("UpsertByNotionPageID(insert) returned empty ID")
	}

	// Read back by Notion page ID.
	got, err := s.TaskByNotionPageID(ctx, "notion-page-001")
	if err != nil {
		t.Fatalf("TaskByNotionPageID(%q) error: %v", "notion-page-001", err)
	}

	ignoreTimestamps := cmpopts.IgnoreFields(Task{}, "CreatedAt", "UpdatedAt")
	if diff := cmp.Diff(created, got, ignoreTimestamps, cmpopts.EquateApproxTime(time.Second)); diff != "" {
		t.Errorf("TaskByNotionPageID(%q) mismatch (-want +got):\n%s", "notion-page-001", diff)
	}

	// Verify individual fields round-tripped correctly.
	if got.Title != "Write integration tests" {
		t.Errorf("TaskByNotionPageID(%q).Title = %q, want %q", "notion-page-001", got.Title, "Write integration tests")
	}
	if got.Status != StatusTodo {
		t.Errorf("TaskByNotionPageID(%q).Status = %q, want %q", "notion-page-001", got.Status, StatusTodo)
	}
	if got.Energy != "high" {
		t.Errorf("TaskByNotionPageID(%q).Energy = %q, want %q", "notion-page-001", got.Energy, "high")
	}
	if got.MyDay != true {
		t.Errorf("TaskByNotionPageID(%q).MyDay = %v, want true", "notion-page-001", got.MyDay)
	}
	if got.CompletedAt != nil {
		t.Errorf("TaskByNotionPageID(%q).CompletedAt = %v, want nil", "notion-page-001", got.CompletedAt)
	}
}

func TestUpsertByNotionPageID_UpdateExisting(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	params := &UpsertByNotionParams{
		Title:        "Original title",
		Status:       StatusTodo,
		NotionPageID: "notion-page-002",
		Assignee:     "human",
		Energy:       "low",
		Priority:     "P3",
	}

	original, err := s.UpsertByNotionPageID(ctx, params)
	if err != nil {
		t.Fatalf("UpsertByNotionPageID(insert) error: %v", err)
	}

	// Upsert with updated fields using the same Notion page ID.
	params.Title = "Updated title"
	params.Energy = "high"
	params.Priority = "P1"
	params.MyDay = true

	updated, err := s.UpsertByNotionPageID(ctx, params)
	if err != nil {
		t.Fatalf("UpsertByNotionPageID(update) error: %v", err)
	}

	// Same row: ID must match.
	if updated.ID != original.ID {
		t.Errorf("UpsertByNotionPageID(update).ID = %s, want %s (same row)", updated.ID, original.ID)
	}
	if updated.Title != "Updated title" {
		t.Errorf("UpsertByNotionPageID(update).Title = %q, want %q", updated.Title, "Updated title")
	}
	if updated.Energy != "high" {
		t.Errorf("UpsertByNotionPageID(update).Energy = %q, want %q", updated.Energy, "high")
	}
	if updated.MyDay != true {
		t.Errorf("UpsertByNotionPageID(update).MyDay = %v, want true", updated.MyDay)
	}
}

func TestUpdateStatus(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create a task in todo status.
	task, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "Task for status test",
		Status:       StatusTodo,
		NotionPageID: "notion-status-001",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}

	tests := []struct {
		name            string
		toStatus        Status
		wantCompletedAt bool
	}{
		{
			name:            "todo to in-progress",
			toStatus:        StatusInProgress,
			wantCompletedAt: false,
		},
		{
			name:            "in-progress to done sets completed_at",
			toStatus:        StatusDone,
			wantCompletedAt: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := s.UpdateStatus(ctx, task.ID, tt.toStatus)
			if err != nil {
				t.Fatalf("UpdateStatus(%s, %q) error: %v", task.ID, tt.toStatus, err)
			}
			if updated.Status != tt.toStatus {
				t.Errorf("UpdateStatus(%s, %q).Status = %q, want %q", task.ID, tt.toStatus, updated.Status, tt.toStatus)
			}
			hasCompleted := updated.CompletedAt != nil
			if hasCompleted != tt.wantCompletedAt {
				t.Errorf("UpdateStatus(%s, %q).CompletedAt present = %v, want %v", task.ID, tt.toStatus, hasCompleted, tt.wantCompletedAt)
			}
			// Carry forward the task reference for the next subtest.
			task = updated
		})
	}
}

func TestUpdateStatus_DoneToDone_PreservesCompletedAt(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create a done task (completed_at is set by DB on insert).
	task, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "Already done task",
		Status:       StatusDone,
		NotionPageID: "notion-done-001",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}
	if task.CompletedAt == nil {
		t.Fatal("UpsertByNotionPageID(done).CompletedAt is nil, want non-nil")
	}
	originalCompleted := *task.CompletedAt

	// Wait briefly so any new now() would differ.
	time.Sleep(10 * time.Millisecond)

	// Update status to done again.
	updated, err := s.UpdateStatus(ctx, task.ID, StatusDone)
	if err != nil {
		t.Fatalf("UpdateStatus(%s, done) error: %v", task.ID, err)
	}
	if updated.CompletedAt == nil {
		t.Fatal("UpdateStatus(done->done).CompletedAt is nil, want preserved")
	}
	if !updated.CompletedAt.Equal(originalCompleted) {
		t.Errorf("UpdateStatus(done->done).CompletedAt = %v, want %v (preserved)", *updated.CompletedAt, originalCompleted)
	}
}

func TestPendingTasks(t *testing.T) {
	store := setup(t)
	ctx := t.Context()

	// Create tasks with mixed statuses.
	seeds := []struct {
		title  string
		status Status
		pageID string
	}{
		{"Todo task", StatusTodo, "pend-001"},
		{"In progress task", StatusInProgress, "pend-002"},
		{"Done task", StatusDone, "pend-003"},
		{"Another todo", StatusTodo, "pend-004"},
	}
	for _, seed := range seeds {
		_, err := store.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        seed.title,
			Status:       seed.status,
			NotionPageID: seed.pageID,
			Assignee:     "human",
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", seed.title, err)
		}
	}

	pending, err := store.PendingTasks(ctx)
	if err != nil {
		t.Fatalf("PendingTasks() error: %v", err)
	}

	// Should return 3 non-done tasks (todo + in-progress).
	if len(pending) != 3 {
		t.Errorf("PendingTasks() count = %d, want 3", len(pending))
	}

	// Verify no done tasks are included.
	for _, p := range pending {
		if p.Title == "Done task" {
			t.Error("PendingTasks() returned a done task")
		}
	}
}

func TestTasks_ReturnsAll(t *testing.T) {
	store := setup(t)
	ctx := t.Context()

	// Insert 3 tasks with different statuses.
	seeds := []struct {
		title  string
		status Status
		pageID string
	}{
		{"Task A", StatusTodo, "all-001"},
		{"Task B", StatusInProgress, "all-002"},
		{"Task C", StatusDone, "all-003"},
	}
	for _, seed := range seeds {
		_, err := store.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        seed.title,
			Status:       seed.status,
			NotionPageID: seed.pageID,
			Assignee:     "human",
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", seed.title, err)
		}
	}

	all, err := store.Tasks(ctx)
	if err != nil {
		t.Fatalf("Tasks() error: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("Tasks() count = %d, want 3", len(all))
	}
}

func TestCompletedSince(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	since := time.Now().Add(-1 * time.Hour)

	// Create a done task (completed_at = now()).
	_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "Completed recently",
		Status:       StatusDone,
		NotionPageID: "comp-001",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}
	// Create a non-done task.
	_, err = s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "Still pending",
		Status:       StatusTodo,
		NotionPageID: "comp-002",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}

	count, err := s.CompletedSince(ctx, since)
	if err != nil {
		t.Fatalf("CompletedSince() error: %v", err)
	}
	if count != 1 {
		t.Errorf("CompletedSince() = %d, want 1", count)
	}
}

func TestCompletedTasksDetailSince(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	since := time.Now().Add(-1 * time.Hour)

	// Create a done task.
	_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "Completed detail task",
		Status:       StatusDone,
		NotionPageID: "detail-001",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}

	details, err := s.CompletedTasksDetailSince(ctx, since)
	if err != nil {
		t.Fatalf("CompletedTasksDetailSince() error: %v", err)
	}
	if len(details) != 1 {
		t.Fatalf("CompletedTasksDetailSince() count = %d, want 1", len(details))
	}
	if details[0].Title != "Completed detail task" {
		t.Errorf("CompletedTasksDetailSince()[0].Title = %q, want %q", details[0].Title, "Completed detail task")
	}
	if details[0].CompletedAt == nil {
		t.Error("CompletedTasksDetailSince()[0].CompletedAt is nil, want non-nil")
	}
	// No project assigned, so project_title should be empty.
	if details[0].ProjectTitle != "" {
		t.Errorf("CompletedTasksDetailSince()[0].ProjectTitle = %q, want empty", details[0].ProjectTitle)
	}
}

func TestDailySummaryHintForDate(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	// Create tasks:
	// 1. my_day=true, done (completed today) -> counts in my_day_total, my_day_completed, total_completed
	// 2. my_day=true, todo -> counts in my_day_total
	// 3. my_day=false, done (completed today) -> counts in non_my_day_completed, total_completed
	// 4. my_day=false, todo -> not counted at all by the query
	seeds := []struct {
		title  string
		status Status
		myDay  bool
		pageID string
	}{
		{"MyDay done", StatusDone, true, "hint-001"},
		{"MyDay todo", StatusTodo, true, "hint-002"},
		{"NonMyDay done", StatusDone, false, "hint-003"},
		{"NonMyDay todo", StatusTodo, false, "hint-004"},
	}
	for _, seed := range seeds {
		_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        seed.title,
			Status:       seed.status,
			MyDay:        seed.myDay,
			NotionPageID: seed.pageID,
			Assignee:     "human",
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", seed.title, err)
		}
	}

	hint, err := s.DailySummaryHintForDate(ctx, dayStart, dayEnd)
	if err != nil {
		t.Fatalf("DailySummaryHintForDate() error: %v", err)
	}

	// The query uses: WHERE my_day = true OR (status = 'done' AND completed_at in range)
	// my_day_total: count of rows with my_day=true -> 2 (MyDay done + MyDay todo)
	if hint.MyDayTasksTotal != 2 {
		t.Errorf("DailySummaryHintForDate().MyDayTasksTotal = %d, want 2", hint.MyDayTasksTotal)
	}
	// my_day_completed: my_day=true AND done AND completed in range -> 1
	if hint.MyDayTasksCompleted != 1 {
		t.Errorf("DailySummaryHintForDate().MyDayTasksCompleted = %d, want 1", hint.MyDayTasksCompleted)
	}
	// non_my_day_completed: my_day=false AND done AND completed in range -> 1
	if hint.NonMyDayCompleted != 1 {
		t.Errorf("DailySummaryHintForDate().NonMyDayCompleted = %d, want 1", hint.NonMyDayCompleted)
	}
	// total_completed: done AND completed in range -> 2
	if hint.TotalCompleted != 2 {
		t.Errorf("DailySummaryHintForDate().TotalCompleted = %d, want 2", hint.TotalCompleted)
	}
	// completed_titles should include both done tasks.
	if len(hint.CompletedTitles) != 2 {
		t.Errorf("DailySummaryHintForDate().CompletedTitles count = %d, want 2", len(hint.CompletedTitles))
	}
}

func TestNotionPageIDs(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create two tasks with Notion page IDs.
	for _, pageID := range []string{"page-a", "page-b"} {
		_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        "Task " + pageID,
			Status:       StatusTodo,
			NotionPageID: pageID,
			Assignee:     "human",
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", pageID, err)
		}
	}

	ids, err := s.NotionPageIDs(ctx)
	if err != nil {
		t.Fatalf("NotionPageIDs() error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("NotionPageIDs() count = %d, want 2", len(ids))
	}
}

func TestArchiveByNotionPageID(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "To archive",
		Status:       StatusTodo,
		NotionPageID: "archive-001",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}

	n, err := s.ArchiveByNotionPageID(ctx, "archive-001")
	if err != nil {
		t.Fatalf("ArchiveByNotionPageID(%q) error: %v", "archive-001", err)
	}
	if n != 1 {
		t.Errorf("ArchiveByNotionPageID(%q) = %d rows, want 1", "archive-001", n)
	}

	// Verify the task is now done.
	task, err := s.TaskByNotionPageID(ctx, "archive-001")
	if err != nil {
		t.Fatalf("TaskByNotionPageID(%q) error: %v", "archive-001", err)
	}
	if task.Status != StatusDone {
		t.Errorf("TaskByNotionPageID(%q).Status = %q, want %q", "archive-001", task.Status, StatusDone)
	}
	if task.CompletedAt == nil {
		t.Error("TaskByNotionPageID(archive-001).CompletedAt is nil, want non-nil")
	}

	// Archiving again should affect 0 rows (already done).
	n2, err := s.ArchiveByNotionPageID(ctx, "archive-001")
	if err != nil {
		t.Fatalf("ArchiveByNotionPageID(%q) second call error: %v", "archive-001", err)
	}
	if n2 != 0 {
		t.Errorf("ArchiveByNotionPageID(%q) second call = %d rows, want 0", "archive-001", n2)
	}
}

func TestArchiveOrphanNotion(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create 3 tasks.
	for _, pageID := range []string{"active-001", "active-002", "orphan-001"} {
		_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        "Task " + pageID,
			Status:       StatusTodo,
			NotionPageID: pageID,
			Assignee:     "human",
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", pageID, err)
		}
	}

	// Only active-001 and active-002 are active; orphan-001 should be archived.
	n, err := s.ArchiveOrphanNotion(ctx, []string{"active-001", "active-002"})
	if err != nil {
		t.Fatalf("ArchiveOrphanNotion() error: %v", err)
	}
	if n != 1 {
		t.Errorf("ArchiveOrphanNotion() = %d, want 1", n)
	}

	orphan, err := s.TaskByNotionPageID(ctx, "orphan-001")
	if err != nil {
		t.Fatalf("TaskByNotionPageID(%q) error: %v", "orphan-001", err)
	}
	if orphan.Status != StatusDone {
		t.Errorf("orphan task status = %q, want %q", orphan.Status, StatusDone)
	}
}

func TestArchiveOrphanNotion_EmptyActiveIDs(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create a task.
	_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "Should not be archived",
		Status:       StatusTodo,
		NotionPageID: "safe-001",
		Assignee:     "human",
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}

	// Empty activeIDs should return 0 immediately (safety guard).
	n, err := s.ArchiveOrphanNotion(ctx, []string{})
	if err != nil {
		t.Fatalf("ArchiveOrphanNotion(empty) error: %v", err)
	}
	if n != 0 {
		t.Errorf("ArchiveOrphanNotion(empty) = %d, want 0", n)
	}
}

func TestUpdateMyDay(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	task, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
		Title:        "MyDay test",
		Status:       StatusTodo,
		NotionPageID: "myday-001",
		Assignee:     "human",
		MyDay:        false,
	})
	if err != nil {
		t.Fatalf("UpsertByNotionPageID() error: %v", err)
	}

	// Set my_day = true.
	if err := s.UpdateMyDay(ctx, task.ID, true); err != nil {
		t.Fatalf("UpdateMyDay(%s, true) error: %v", task.ID, err)
	}

	got, err := s.TaskByID(ctx, task.ID)
	if err != nil {
		t.Fatalf("TaskByID(%s) error: %v", task.ID, err)
	}
	if !got.MyDay {
		t.Errorf("TaskByID(%s).MyDay = false, want true", task.ID)
	}
}

func TestClearAllMyDay(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create two my_day=true tasks.
	for _, pageID := range []string{"clear-001", "clear-002"} {
		_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        "Clear " + pageID,
			Status:       StatusTodo,
			NotionPageID: pageID,
			Assignee:     "human",
			MyDay:        true,
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", pageID, err)
		}
	}

	n, err := s.ClearAllMyDay(ctx)
	if err != nil {
		t.Fatalf("ClearAllMyDay() error: %v", err)
	}
	if n != 2 {
		t.Errorf("ClearAllMyDay() = %d, want 2", n)
	}
}

func TestPendingTasksByTitle(t *testing.T) {
	s := setup(t)
	ctx := t.Context()

	// Create tasks with varied titles.
	seeds := []struct {
		title  string
		status Status
		pageID string
	}{
		{"Fix login bug", StatusTodo, "title-001"},
		{"Fix signup bug", StatusInProgress, "title-002"},
		{"Deploy to prod", StatusTodo, "title-003"},
		{"Fix done bug", StatusDone, "title-004"},
	}
	for _, seed := range seeds {
		_, err := s.UpsertByNotionPageID(ctx, &UpsertByNotionParams{
			Title:        seed.title,
			Status:       seed.status,
			NotionPageID: seed.pageID,
			Assignee:     "human",
		})
		if err != nil {
			t.Fatalf("UpsertByNotionPageID(%q) error: %v", seed.title, err)
		}
	}

	results, err := s.PendingTasksByTitle(ctx, "Fix")
	if err != nil {
		t.Fatalf("PendingTasksByTitle(%q) error: %v", "Fix", err)
	}
	// Should match "Fix login bug" and "Fix signup bug" (not the done one).
	if len(results) != 2 {
		t.Errorf("PendingTasksByTitle(%q) count = %d, want 2", "Fix", len(results))
	}
}
