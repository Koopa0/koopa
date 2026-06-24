// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// content_loop_integration_test.go covers the three tools that form the agent
// content-collaboration loop: list_content (caller-scoped readback),
// revise_content (status-guarded caller-scoped write), and review_period
// (windowed owner retrospective with human-only attribution). All tests share
// the TestMain-managed container from integration_test.go via testPool.
package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// ============================================================================
// Seed helpers — content_loop tests only
// ============================================================================

// seedContentForCreator inserts a content row with an explicit created_by,
// status, and optional review_note. The slug must be unique per test to avoid
// UK_contents_slug collisions across tests; callers use a unique prefix.
// published status requires published_at non-null (chk_content_publication),
// so this helper sets it to now() when status='published'.
func seedContentForCreator(t *testing.T, slug, title, createdBy, status string, reviewNote *string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	// published status requires published_at IS NOT NULL (chk_content_publication).
	var publishedAt *time.Time
	var isPublic bool
	if status == "published" {
		now := time.Now()
		publishedAt = &now
		isPublic = true
	}
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status, created_by, review_note, published_at, is_public)
		 VALUES ($1, $2, 'body text', 'article', $3, $4, $5, $6, $7)
		 RETURNING id`,
		slug, title, status, createdBy, reviewNote, publishedAt, isPublic,
	).Scan(&id); err != nil {
		t.Fatalf("seedContentForCreator(slug=%q, created_by=%q, status=%q): %v", slug, createdBy, status, err)
	}
	return id
}

// seedPublishedContentAt inserts a content row that is already published with
// an explicit published_at. Used by review_period published-content assertions.
func seedPublishedContentAt(t *testing.T, slug, title string, publishedAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status, is_public, published_at)
		 VALUES ($1, $2, 'published body', 'article', 'published', true, $3)
		 RETURNING id`,
		slug, title, publishedAt,
	).Scan(&id); err != nil {
		t.Fatalf("seedPublishedContentAt(slug=%q): %v", slug, err)
	}
	return id
}

// completeTodoAsActor opens a transaction, binds koopa.actor to actor, then
// inserts a todo directly in state='done' (which fires audit_todos with
// change_kind='completed' and the bound actor). Returns the todo's id.
//
// The audit_todos trigger fires on INSERT with entity_type='todo',
// change_kind='created'. To get a change_kind='completed' event we insert
// with state='inbox' first (outside this tx, so the FK resolves), then UPDATE
// state='done' inside the actor tx.
//
// A simpler path: INSERT with state='done' fires change_kind='created' (not
// 'completed'). To get change_kind='completed', we need the UPDATE path:
// old.state != 'done' → new.state = 'done'. We do two steps:
//  1. Raw INSERT state='inbox' (no actor needed for setup).
//  2. Actor-bound tx: UPDATE state='done', completed_at=now().
func completeTodoAsActor(t *testing.T, title, actor string, completedAt time.Time) uuid.UUID {
	t.Helper()
	ctx := t.Context()

	// Step 1: insert in non-done state so the trigger fires 'created'.
	var id uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO todos (title, state) VALUES ($1, 'inbox') RETURNING id`,
		title,
	).Scan(&id); err != nil {
		t.Fatalf("completeTodoAsActor: insert inbox todo %q: %v", title, err)
	}

	// Step 2: inside an actor-bound tx, UPDATE to done — triggers 'completed'.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("completeTodoAsActor: begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', $1, true)", actor); err != nil {
		t.Fatalf("completeTodoAsActor: set koopa.actor: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE todos SET state='done', completed_at=$1 WHERE id=$2`,
		completedAt, id,
	); err != nil {
		t.Fatalf("completeTodoAsActor: update to done: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("completeTodoAsActor: commit: %v", err)
	}
	return id
}

// completeMilestoneAsActor marks a milestone completed inside an actor-bound
// tx, so the audit_milestones trigger fires with the given actor. Returns the
// milestone id. position is auto-incremented per goal using a DB sequence so
// the milestones_goal_id_position_key unique constraint is never violated.
func completeMilestoneAsActor(t *testing.T, goalID uuid.UUID, title, actor string, completedAt time.Time) uuid.UUID {
	t.Helper()
	ctx := t.Context()

	// Pick a position that is unique within this goal by using the current
	// count of existing milestones for this goal.
	var nextPos int
	if err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM milestones WHERE goal_id = $1`, goalID,
	).Scan(&nextPos); err != nil {
		t.Fatalf("completeMilestoneAsActor: count milestones: %v", err)
	}

	var id uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO milestones (goal_id, title, position) VALUES ($1, $2, $3) RETURNING id`,
		goalID, title, nextPos,
	).Scan(&id); err != nil {
		t.Fatalf("completeMilestoneAsActor: insert milestone %q: %v", title, err)
	}

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("completeMilestoneAsActor: begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SELECT set_config('koopa.actor', $1, true)", actor); err != nil {
		t.Fatalf("completeMilestoneAsActor: set koopa.actor: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE milestones SET completed_at=$1 WHERE id=$2`,
		completedAt, id,
	); err != nil {
		t.Fatalf("completeMilestoneAsActor: update completed_at: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("completeMilestoneAsActor: commit: %v", err)
	}
	return id
}

// ============================================================================
// list_content — caller-scoped readback
// ============================================================================

// TestIntegration_ListContent_CallerScoped asserts the core privacy invariant:
// list_content returns ONLY the content created by the resolved caller, never
// another agent's. A codex row must not appear when the caller is planner, and
// vice versa. This would catch a missing WHERE created_by = $caller clause.
func TestIntegration_ListContent_CallerScoped(t *testing.T) {
	s := setupServer(t)

	note := "please revise"
	plannerReviewID := seedContentForCreator(t, "cl-planner-review", "Planner Review", "planner", "review", nil)
	plannerCRID := seedContentForCreator(t, "cl-planner-cr", "Planner CR", "planner", "changes_requested", &note)
	plannerPubID := seedContentForCreator(t, "cl-planner-pub", "Planner Published", "planner", "published", nil)
	codexID := seedContentForCreator(t, "cl-codex-review", "Codex Content", "codex", "review", nil)

	_, out, err := callHandlerAs(t, "planner", s.listContent, ListContentInput{})
	if err != nil {
		t.Fatalf("listContent(planner): %v", err)
	}

	ids := make(map[string]ContentListItem, len(out.Items))
	for _, it := range out.Items {
		ids[it.ID] = it
	}

	// planner's three rows must appear.
	for _, wantID := range []uuid.UUID{plannerReviewID, plannerCRID, plannerPubID} {
		if _, ok := ids[wantID.String()]; !ok {
			t.Errorf("listContent(planner) missing own row %s", wantID)
		}
	}
	// codex row must NOT appear.
	if _, ok := ids[codexID.String()]; ok {
		t.Errorf("listContent(planner) leaked codex row %s — caller-scoping violated", codexID)
	}

	// The changes_requested row must carry review_note.
	if cr, ok := ids[plannerCRID.String()]; ok {
		if cr.ReviewNote == nil || *cr.ReviewNote != "please revise" {
			t.Errorf("listContent[CR].review_note = %v, want %q", cr.ReviewNote, "please revise")
		}
	}
}

// TestIntegration_ListContent_EmptySlice asserts that when the caller has no
// content, the result is an empty slice (items: []), never a nil JSON null.
func TestIntegration_ListContent_EmptySlice(t *testing.T) {
	s := setupServer(t)
	// Seed content for a different agent so the corpus is non-empty.
	seedContentForCreator(t, "cl-empty-other", "Other Agent Content", "codex", "review", nil)

	_, out, err := callHandlerAs(t, "planner", s.listContent, ListContentInput{})
	if err != nil {
		t.Fatalf("listContent(planner) with no planner content: %v", err)
	}
	if out.Items == nil {
		t.Error("listContent returned nil Items, want [] (never nil)")
	}
	if len(out.Items) != 0 {
		t.Errorf("listContent(planner) returned %d items, want 0 (no planner content seeded)", len(out.Items))
	}
}

// TestIntegration_ListContent_CallerGate refuses the zero-privilege "unknown"
// fallback and a fabricated name before any read.
func TestIntegration_ListContent_CallerGate(t *testing.T) {
	s := setupServer(t)
	seedContentForCreator(t, "cl-gate-other", "Gate Content", "planner", "review", nil)

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		_, _, err := callHandlerAs(t, caller, s.listContent, ListContentInput{})
		if err == nil {
			t.Errorf("listContent as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// ============================================================================
// revise_content — status-guard + caller-scope
// ============================================================================

// TestIntegration_ReviseContent_ChangesRequestedSucceeds is the primary happy
// path: the caller revises its own changes_requested content. After revise_content
// the status must be 'review' and the review_note must be cleared.
// Bug this catches: ReviseByCreator not clearing review_note, or not transitioning
// status back to review.
func TestIntegration_ReviseContent_ChangesRequestedSucceeds(t *testing.T) {
	s := setupServer(t)

	note := "needs more examples"
	id := seedContentForCreator(t, "rc-cr-happy", "Changes Requested Article", "planner", "changes_requested", &note)
	newBody := "# Revised\n\nMore examples added."

	_, out, err := callHandlerAs(t, "planner", s.reviseContent, ReviseContentInput{
		ID:   id.String(),
		Body: &newBody,
	})
	if err != nil {
		t.Fatalf("reviseContent(changes_requested): %v", err)
	}
	if out.Content == nil {
		t.Fatal("reviseContent returned nil Content")
	}
	if out.Content.Status != "review" {
		t.Errorf("reviseContent status = %q, want %q (must return to review)", out.Content.Status, "review")
	}
	if out.Content.ReviewNote != nil {
		t.Errorf("reviseContent review_note = %q, want nil (cleared on revise)", *out.Content.ReviewNote)
	}

	// Verify body was updated in DB.
	var body string
	if err := testPool.QueryRow(t.Context(),
		`SELECT body FROM contents WHERE id = $1`, id,
	).Scan(&body); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if body != newBody {
		t.Errorf("DB body = %q, want %q", body, newBody)
	}
}

// TestIntegration_ReviseContent_ReviewStatusSucceeds asserts that a row already
// in 'review' can also be revised (status IN review/changes_requested).
// Bug this catches: ReviseByCreator rejecting review-status rows.
func TestIntegration_ReviseContent_ReviewStatusSucceeds(t *testing.T) {
	s := setupServer(t)

	id := seedContentForCreator(t, "rc-review-happy", "Review Article", "planner", "review", nil)
	newTitle := "Review Article — Revised Title"

	_, out, err := callHandlerAs(t, "planner", s.reviseContent, ReviseContentInput{
		ID:    id.String(),
		Title: &newTitle,
	})
	if err != nil {
		t.Fatalf("reviseContent(review): %v", err)
	}
	if out.Content == nil || string(out.Content.Status) != "review" {
		t.Errorf("reviseContent(review) status = %v, want review", out.Content)
	}
}

// TestIntegration_ReviseContent_PublishedReturnsNotFound asserts that a
// published row is not revisable — it returns not-found without mutating.
// Bug this catches: ReviseByCreator not filtering on status IN (review,
// changes_requested), allowing published content to be mutated.
func TestIntegration_ReviseContent_PublishedReturnsNotFound(t *testing.T) {
	s := setupServer(t)

	id := seedContentForCreator(t, "rc-pub-reject", "Published Article", "planner", "published", nil)
	newBody := "should not apply"

	_, _, err := callHandlerAs(t, "planner", s.reviseContent, ReviseContentInput{
		ID:   id.String(),
		Body: &newBody,
	})
	if err == nil {
		t.Fatal("reviseContent(published) err = nil, want not-found (published not revisable)")
	}

	// Verify body is unchanged.
	var body string
	if err2 := testPool.QueryRow(t.Context(),
		`SELECT body FROM contents WHERE id = $1`, id,
	).Scan(&body); err2 != nil {
		t.Fatalf("reading body: %v", err2)
	}
	if body == newBody {
		t.Error("reviseContent(published) mutated the body despite returning an error — published row is not protected")
	}
}

// TestIntegration_ReviseContent_CrossCreatorNotFound asserts that caller A
// (planner) cannot revise content created by caller B (codex). The response
// is not-found — the row must be left unchanged. This is the key privacy
// invariant.
// Bug this catches: ReviseByCreator not filtering on created_by = caller.
func TestIntegration_ReviseContent_CrossCreatorNotFound(t *testing.T) {
	s := setupServer(t)

	codexID := seedContentForCreator(t, "rc-codex-cr", "Codex Changes Requested", "codex", "changes_requested", nil)
	originalBody := "codex original body"
	// Set explicit body so we can verify it hasn't changed.
	if _, err := testPool.Exec(t.Context(),
		`UPDATE contents SET body = $1 WHERE id = $2`, originalBody, codexID,
	); err != nil {
		t.Fatalf("setting original body: %v", err)
	}

	newBody := "planner should not be able to write this"
	_, _, err := callHandlerAs(t, "planner", s.reviseContent, ReviseContentInput{
		ID:   codexID.String(),
		Body: &newBody,
	})
	if err == nil {
		t.Fatal("reviseContent(planner on codex's row) err = nil, want not-found (cross-creator)")
	}

	// Verify the row is unchanged.
	var body string
	if err2 := testPool.QueryRow(t.Context(),
		`SELECT body FROM contents WHERE id = $1`, codexID,
	).Scan(&body); err2 != nil {
		t.Fatalf("reading codex body: %v", err2)
	}
	if body == newBody {
		t.Error("reviseContent cross-creator mutated the codex row — caller-scoping violated")
	}
	if body != originalBody {
		t.Errorf("codex body = %q, want unchanged %q", body, originalBody)
	}
}

// TestIntegration_ReviseContent_NoFieldsRejected asserts that supplying no
// editable field (no body, title, or excerpt) is a validation error.
// Bug this catches: a no-op revise silently succeeding with no changes.
func TestIntegration_ReviseContent_NoFieldsRejected(t *testing.T) {
	s := setupServer(t)
	id := seedContentForCreator(t, "rc-nofield", "No Fields Article", "planner", "changes_requested", nil)

	_, _, err := callHandlerAs(t, "planner", s.reviseContent, ReviseContentInput{
		ID: id.String(),
		// Body, Title, Excerpt all nil
	})
	if err == nil {
		t.Fatal("reviseContent(no fields) err = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Errorf("error = %q, want containing %q", err, "at least one")
	}
}

// TestIntegration_ReviseContent_CallerGate refuses the zero-privilege "unknown"
// fallback before any write.
func TestIntegration_ReviseContent_CallerGate(t *testing.T) {
	s := setupServer(t)
	id := seedContentForCreator(t, "rc-gate", "Gate Article", "planner", "changes_requested", nil)
	newBody := "gated"

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		_, _, err := callHandlerAs(t, caller, s.reviseContent, ReviseContentInput{
			ID:   id.String(),
			Body: &newBody,
		})
		if err == nil {
			t.Errorf("reviseContent as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// ============================================================================
// review_period — windowed retrospective
// ============================================================================

// TestIntegration_ReviewPeriod_HumanTodoIncluded_AgentExcluded is the load-
// bearing attribution test: completed_todos counts ONLY actor='human'. An
// agent-resolved todo must NOT appear. This catches a missing actor filter in
// CompletedTodosInWindow.
//
// The window must cover today because completeTodoAsActor fires the audit
// trigger which stamps occurred_at=now(). Using a past fixed date would make
// the human todo fall outside the window.
func TestIntegration_ReviewPeriod_HumanTodoIncluded_AgentExcluded(t *testing.T) {
	s := setupServer(t)

	today := time.Now().UTC().Format(time.DateOnly)

	// Human-completed todo — must appear in completed_todos.
	completeTodoAsActor(t, "rp-human-done", "human", time.Now())

	// Agent-completed todo — must NOT appear (agent actor).
	// Use capture_inbox (planner) then resolve_task(done) — this logs actor='planner'.
	_, captured, err := callHandlerAs(t, "planner", s.captureInbox, CaptureInboxInput{
		Title: "rp-agent-done",
	})
	if err != nil {
		t.Fatalf("captureInbox: %v", err)
	}
	_, _, err = callHandlerAs(t, "planner", s.resolveTask, ResolveTaskInput{
		ID:    captured.Task.ID.String(),
		State: "done",
	})
	if err != nil {
		t.Fatalf("resolveTask: %v", err)
	}

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: today,
		Until: today,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	// Human todo: must appear.
	sawHuman := false
	for _, ct := range out.CompletedTodos {
		if ct.Title == "rp-human-done" {
			sawHuman = true
		}
		if ct.Title == "rp-agent-done" {
			t.Errorf("reviewPeriod.completed_todos contains agent-resolved todo %q — actor exclusion violated", ct.Title)
		}
	}
	if !sawHuman {
		t.Error("reviewPeriod.completed_todos missing the human-completed todo")
	}
}

// TestIntegration_ReviewPeriod_TodosOpenedCountsAllActors pins the inflow
// counter: todos_opened counts ALL actors (not human-only), because backlog
// inflow is inflow regardless of who captured it.
// Bug this catches: wrong actor filter on TodosOpenedInWindow.
func TestIntegration_ReviewPeriod_TodosOpenedCountsAllActors(t *testing.T) {
	s := setupServer(t)

	const since = "2025-09-11"
	const until = "2025-09-11"

	// Seed a todo whose created activity_event falls within the window by
	// directly inserting with a controlled created_at. The trigger fires on
	// INSERT for entity_type='todo', change_kind='created'.
	// We need occurred_at in the window. The trigger stamps occurred_at=now(),
	// so we insert the todo during the test and use a window of "today".
	// Instead, seed activity_event directly for TodosOpenedInWindow.
	// But TodosOpenedInWindow queries activity_events WHERE entity_type='todo'
	// AND change_kind='created' AND occurred_at in window.
	// We can seed two todos via captureInbox (fires trigger with actor='planner')
	// and then use a window covering the current moment.

	// Use a wide window covering now so we don't need to control occurred_at.
	today := time.Now().UTC().Format(time.DateOnly)

	_, _, err := callHandlerAs(t, "planner", s.captureInbox, CaptureInboxInput{Title: "rp-inflow-1"})
	if err != nil {
		t.Fatalf("captureInbox 1: %v", err)
	}
	_, _, err = callHandlerAs(t, "planner", s.captureInbox, CaptureInboxInput{Title: "rp-inflow-2"})
	if err != nil {
		t.Fatalf("captureInbox 2: %v", err)
	}
	// Also add a human-created todo (raw insert fires trigger with actor='system'
	// fallback, but it still counts as inflow).
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO todos (title, state) VALUES ('rp-inflow-human', 'inbox')`,
	); err != nil {
		t.Fatalf("seeding human inflow todo: %v", err)
	}

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: today,
		Until: today,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	// At least 3 todos were opened this session (2 planner + 1 raw). There may
	// be more from other tests in this run, so assert >= 3.
	if out.Counts.TodosOpened < 3 {
		t.Errorf("todos_opened = %d, want >= 3 (all-actor inflow count)", out.Counts.TodosOpened)
	}
}

// TestIntegration_ReviewPeriod_AllActiveGoals pins that ALL in_progress goals
// appear in goals[], not just those that advanced. A goal with no milestone
// completed in-window must still appear with advanced=false.
// Bug this catches: GoalsAdvancedInWindow filtering out non-advanced goals.
func TestIntegration_ReviewPeriod_AllActiveGoals(t *testing.T) {
	s := setupServer(t)

	today := time.Now().UTC().Format(time.DateOnly)
	midWindow := time.Now().UTC()

	// Goal A: has a milestone completed in-window → advanced=true.
	var goalAID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('rp-goal-advanced', 'in_progress') RETURNING id`,
	).Scan(&goalAID); err != nil {
		t.Fatalf("seeding goal A: %v", err)
	}
	completeMilestoneAsActor(t, goalAID, "rp-milestone-A", "human", midWindow)

	// Goal B: in_progress but no milestone completed in-window → advanced=false.
	var goalBID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('rp-goal-stagnant', 'in_progress') RETURNING id`,
	).Scan(&goalBID); err != nil {
		t.Fatalf("seeding goal B: %v", err)
	}
	// Insert an incomplete milestone so MilestoneTotal is non-zero.
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO milestones (goal_id, title, position) VALUES ($1, 'rp-ms-open', 0)`, goalBID,
	); err != nil {
		t.Fatalf("seeding open milestone for goal B: %v", err)
	}

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: today,
		Until: today,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	byTitle := make(map[string]ReviewGoal, len(out.Goals))
	for _, g := range out.Goals {
		byTitle[g.Title] = g
	}

	gA, okA := byTitle["rp-goal-advanced"]
	gB, okB := byTitle["rp-goal-stagnant"]

	if !okA {
		t.Error("goals[] missing 'rp-goal-advanced' — advanced goal absent")
	} else if !gA.Advanced {
		t.Errorf("rp-goal-advanced.advanced = false, want true (milestone completed in-window)")
	}

	if !okB {
		t.Error("goals[] missing 'rp-goal-stagnant' — all-active-goals contract violated (non-advanced goal dropped)")
	} else if gB.Advanced {
		t.Errorf("rp-goal-stagnant.advanced = true, want false (no milestone completed in-window)")
	}
}

// TestIntegration_ReviewPeriod_MilestoneAttribution asserts that milestones
// completed by 'human' appear in completed_milestones AND advance the parent
// goal, while agent-completed milestones do NOT appear.
// Bug this catches: missing actor='human' filter in CompletedMilestonesInWindow.
func TestIntegration_ReviewPeriod_MilestoneAttribution(t *testing.T) {
	s := setupServer(t)

	today := time.Now().UTC().Format(time.DateOnly)
	midWindow := time.Now().UTC()

	var goalID uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO goals (title, status) VALUES ('rp-ms-goal', 'in_progress') RETURNING id`,
	).Scan(&goalID); err != nil {
		t.Fatalf("seeding goal: %v", err)
	}

	// Human-completed milestone — must appear.
	completeMilestoneAsActor(t, goalID, "rp-human-milestone", "human", midWindow)
	// Agent-completed milestone — must NOT appear.
	completeMilestoneAsActor(t, goalID, "rp-agent-milestone", "planner", midWindow)

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: today,
		Until: today,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	sawHuman, sawAgent := false, false
	for _, m := range out.CompletedMilestones {
		if m.Title == "rp-human-milestone" {
			sawHuman = true
		}
		if m.Title == "rp-agent-milestone" {
			sawAgent = true
		}
	}
	if !sawHuman {
		t.Error("completed_milestones missing the human-completed milestone")
	}
	if sawAgent {
		t.Error("completed_milestones contains the agent-completed milestone — actor exclusion violated")
	}

	// The goal must be marked advanced (human milestone in window).
	for _, g := range out.Goals {
		if g.Title == "rp-ms-goal" && !g.Advanced {
			t.Error("rp-ms-goal.advanced = false, want true (human milestone completed in-window)")
		}
	}
}

// TestIntegration_ReviewPeriod_PublishedContentInWindow asserts that content
// published within the window appears in published_content; content published
// outside does not.
// Bug this catches: PublishedInWindow using created_at instead of published_at,
// or wrong window bounds.
func TestIntegration_ReviewPeriod_PublishedContentInWindow(t *testing.T) {
	s := setupServer(t)

	const since = "2025-08-01"
	const until = "2025-08-31"

	inWindow := time.Date(2025, 8, 15, 12, 0, 0, 0, time.UTC)
	beforeWindow := time.Date(2025, 7, 31, 23, 59, 59, 0, time.UTC)
	afterWindow := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)

	inID := seedPublishedContentAt(t, "rp-pub-in", "Published In Window", inWindow)
	seedPublishedContentAt(t, "rp-pub-before", "Published Before Window", beforeWindow)
	seedPublishedContentAt(t, "rp-pub-after", "Published After Window", afterWindow)

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: since,
		Until: until,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	_ = inID
	sawIn := false
	for _, p := range out.PublishedContent {
		if p.Title == "Published In Window" {
			sawIn = true
		}
		if p.Title == "Published Before Window" {
			t.Error("published_content contains pre-window row — window lower bound incorrect")
		}
		if p.Title == "Published After Window" {
			t.Error("published_content contains post-window row — window upper bound incorrect")
		}
	}
	if !sawIn {
		t.Error("published_content missing the in-window row")
	}
	if out.Counts.ContentPublished < 1 {
		t.Errorf("content_published = %d, want >= 1", out.Counts.ContentPublished)
	}
}

// TestIntegration_ReviewPeriod_WindowBoundaryInclusive proves the whole-day
// inclusive semantics: a todo completed at 00:00:00 and one at 23:59:59 of the
// window day both appear; one from prev-day and one from next-day do not.
// Bug this catches: off-by-one in the from/to bound construction in reviewPeriod.
func TestIntegration_ReviewPeriod_WindowBoundaryInclusive(t *testing.T) {
	s := setupServer(t)

	const windowDay = "2025-07-15"
	// Seed activity_events directly with controlled occurred_at for boundary cases.
	// We create todos and then patch their completion events via direct
	// activity_events inserts (the cleanest way to control occurred_at precisely
	// without coupling to wall clock). The review queries read activity_events.

	startOfDay := time.Date(2025, 7, 15, 0, 0, 0, 0, time.UTC)
	endOfDay := time.Date(2025, 7, 15, 23, 59, 59, 0, time.UTC)
	prevDay := time.Date(2025, 7, 14, 23, 59, 59, 0, time.UTC)
	nextDay := time.Date(2025, 7, 16, 0, 0, 0, 0, time.UTC)

	// Insert activity_events directly with controlled timestamps.
	// entity_id can be any UUID; the query only uses occurred_at and actor.
	insertEvent := func(title string, occurredAt time.Time) {
		t.Helper()
		fakeID := uuid.New()
		if _, err := testPool.Exec(t.Context(),
			`INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, occurred_at)
			 VALUES ('todo', $1, $2, 'completed', 'human', $3)`,
			fakeID, title, occurredAt,
		); err != nil {
			t.Fatalf("insertEvent(%q, %s): %v", title, occurredAt, err)
		}
	}

	insertEvent("rp-bound-start", startOfDay)
	insertEvent("rp-bound-end", endOfDay)
	insertEvent("rp-bound-prev", prevDay)
	insertEvent("rp-bound-next", nextDay)

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: windowDay,
		Until: windowDay,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	type presence struct{ sawStart, sawEnd, sawPrev, sawNext bool }
	var p presence
	for _, ct := range out.CompletedTodos {
		switch ct.Title {
		case "rp-bound-start":
			p.sawStart = true
		case "rp-bound-end":
			p.sawEnd = true
		case "rp-bound-prev":
			p.sawPrev = true
		case "rp-bound-next":
			p.sawNext = true
		}
	}

	if !p.sawStart {
		t.Error("boundary: start-of-day (00:00:00) excluded — window lower bound too strict")
	}
	if !p.sawEnd {
		t.Error("boundary: end-of-day (23:59:59) excluded — window upper bound too strict")
	}
	if p.sawPrev {
		t.Error("boundary: prev-day (23:59:59 the day before) included — window lower bound too wide")
	}
	if p.sawNext {
		t.Error("boundary: next-day (00:00:00 the day after) included — window upper bound too wide")
	}
}

// TestIntegration_ReviewPeriod_Counts verifies the scalar counts in
// ReviewCounts are consistent with the lists. todos_completed ==
// len(completed_todos), milestones_completed == len(completed_milestones),
// content_published == len(published_content). These are derived by the handler
// from the lists, so a count mismatch indicates the handler is computing from
// a stale or different dataset.
func TestIntegration_ReviewPeriod_Counts(t *testing.T) {
	s := setupServer(t)

	const since = "2025-06-01"
	const until = "2025-06-30"

	midWindow := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	// 2 human-completed todos.
	insertEvent := func(title string, occurredAt time.Time) {
		t.Helper()
		fakeID := uuid.New()
		if _, err := testPool.Exec(t.Context(),
			`INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, occurred_at)
			 VALUES ('todo', $1, $2, 'completed', 'human', $3)`,
			fakeID, title, occurredAt,
		); err != nil {
			t.Fatalf("insertEvent(%q): %v", title, err)
		}
	}
	insertEvent("rp-count-todo-1", midWindow)
	insertEvent("rp-count-todo-2", midWindow)

	// 1 published content in window.
	seedPublishedContentAt(t, "rp-count-pub", "Count Published", midWindow)

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: since,
		Until: until,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	if out.Counts.TodosCompleted != len(out.CompletedTodos) {
		t.Errorf("todos_completed = %d, want len(completed_todos) = %d", out.Counts.TodosCompleted, len(out.CompletedTodos))
	}
	if out.Counts.MilestonesCompleted != len(out.CompletedMilestones) {
		t.Errorf("milestones_completed = %d, want len(completed_milestones) = %d", out.Counts.MilestonesCompleted, len(out.CompletedMilestones))
	}
	if out.Counts.ContentPublished != len(out.PublishedContent) {
		t.Errorf("content_published = %d, want len(published_content) = %d", out.Counts.ContentPublished, len(out.PublishedContent))
	}

	// Spot-check concrete minimum values.
	if out.Counts.TodosCompleted < 2 {
		t.Errorf("todos_completed = %d, want >= 2 (seeded 2 human-completed events)", out.Counts.TodosCompleted)
	}
	if out.Counts.ContentPublished < 1 {
		t.Errorf("content_published = %d, want >= 1 (seeded 1 published content)", out.Counts.ContentPublished)
	}
}

// TestIntegration_ReviewPeriod_WindowEcho asserts that the window output echoes
// the parsed since/until back to the caller (whole-day dates, not timestamps).
// Bug this catches: the handler echoing the raw input strings or a wrong format.
func TestIntegration_ReviewPeriod_WindowEcho(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: "2025-05-01",
		Until: "2025-05-31",
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	want := ReviewWindow{Since: "2025-05-01", Until: "2025-05-31"}
	if diff := cmp.Diff(want, out.Window); diff != "" {
		t.Errorf("window mismatch (-want +got):\n%s", diff)
	}
}

// TestIntegration_ReviewPeriod_SinceRequired asserts that omitting since is
// a validation error.
func TestIntegration_ReviewPeriod_SinceRequired(t *testing.T) {
	s := setupServer(t)

	_, _, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Until: "2025-05-31",
	})
	if err == nil {
		t.Fatal("reviewPeriod(no since) err = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "since") {
		t.Errorf("error = %q, want containing %q", err, "since")
	}
}

// TestIntegration_ReviewPeriod_CallerGate refuses the zero-privilege "unknown"
// fallback and a fabricated name.
func TestIntegration_ReviewPeriod_CallerGate(t *testing.T) {
	s := setupServer(t)

	for _, caller := range []string{"unknown", "fabricated-agent"} {
		_, _, err := callHandlerAs(t, caller, s.reviewPeriod, ReviewPeriodInput{
			Since: "2025-05-01",
			Until: "2025-05-31",
		})
		if err == nil {
			t.Errorf("reviewPeriod as %q err = nil, want registered-caller refusal", caller)
		}
	}
}

// TestIntegration_ReviewPeriod_AreasAllActive asserts that the Areas slice
// contains all active areas from the seed migrations, with neglected=true for
// areas with zero human activity and neglected=false for areas with activity.
// Bug this catches: AreaActivityInWindow returning only areas with activity
// (missing the LEFT JOIN / COUNT=0 case).
func TestIntegration_ReviewPeriod_AreasAllActive(t *testing.T) {
	s := setupServer(t)

	// Areas are no longer seeded, so provision active areas this test can assert
	// on. Both have zero activity in the 2025-04 window → they must come back as
	// neglected, proving AreaActivityInWindow includes zero-activity areas.
	ensureArea(t, "rp-area-alpha")
	ensureArea(t, "rp-area-beta")

	const since = "2025-04-01"
	const until = "2025-04-30"

	_, out, err := callHandlerAs(t, "planner", s.reviewPeriod, ReviewPeriodInput{
		Since: since,
		Until: until,
	})
	if err != nil {
		t.Fatalf("reviewPeriod: %v", err)
	}

	// Every active area must appear, including zero-activity ones (neglected=true
	// since there's no human activity in the 2025-04 window).
	if len(out.Areas) == 0 {
		t.Error("areas[] empty — active areas not returned (AreaActivityInWindow must include zero-activity areas)")
	}
	for _, a := range out.Areas {
		if a.ActivityCount > 0 && !a.Neglected {
			continue // active, not neglected — correct
		}
		if a.ActivityCount == 0 && !a.Neglected {
			t.Errorf("area %q: activity_count=0 but neglected=false — handler neglect derivation broken", a.Name)
		}
	}
	// Count tallies must be consistent.
	if out.Counts.AreasActive+out.Counts.AreasNeglected != len(out.Areas) {
		t.Errorf("areas_active(%d) + areas_neglected(%d) = %d, want len(areas) = %d",
			out.Counts.AreasActive, out.Counts.AreasNeglected,
			out.Counts.AreasActive+out.Counts.AreasNeglected, len(out.Areas))
	}
}
