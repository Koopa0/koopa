//go:build integration

package mcp

import (
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/Koopa0/koopa0.dev/internal/testdb"
)

func setupIntegrationServer(t *testing.T) *Server {
	t.Helper()
	pool := testdb.NewPool(t)
	testdb.Truncate(t, pool,
		"attempt_observations", "attempts", "sessions",
		"plan_items", "plans",
		"daily_plan_items", "journal", "tasks",
		"directives", "reports", "insights",
		"milestones", "goals", "projects",
	)

	// Seed the "test" participant so FK constraints on tasks.created_by etc. pass.
	_, err := pool.Exec(t.Context(),
		`INSERT INTO participant (name, platform, description, can_issue_directives, can_receive_directives, can_write_reports, task_assignable, can_own_schedules)
		 VALUES ('test', 'claude-code', 'test participant', true, true, true, true, false)
		 ON CONFLICT (name) DO NOTHING`)
	if err != nil {
		t.Fatalf("seeding participant: %v", err)
	}

	return NewServer(pool, slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithLocation(time.UTC),
		WithParticipant("test"),
	)
}

// TestDailyCycleWorkflow tests the complete daily planning lifecycle:
// morning_context → capture_inbox → advance_work(clarify) → plan_day → write_journal → reflection_context
func TestDailyCycleWorkflow(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	// 1. Morning context — should return empty state
	_, morning, err := s.morningContext(ctx, nil, MorningContextInput{})
	if err != nil {
		t.Fatalf("morning_context: %v", err)
	}
	if len(morning.OverdueTasks) != 0 {
		t.Errorf("expected 0 overdue tasks, got %d", len(morning.OverdueTasks))
	}

	// 2. Capture a task to inbox
	_, captured, err := s.captureInbox(ctx, nil, CaptureInboxInput{
		Title:       "Review PR #123",
		Description: "Check the auth middleware changes",
	})
	if err != nil {
		t.Fatalf("capture_inbox: %v", err)
	}
	if captured.Task.Title != "Review PR #123" {
		t.Errorf("task title = %q, want %q", captured.Task.Title, "Review PR #123")
	}
	if captured.Task.Status != "inbox" {
		t.Errorf("task status = %q, want %q", captured.Task.Status, "inbox")
	}
	taskID := captured.Task.ID.String()

	// 3. Clarify: inbox → todo
	_, clarified, err := s.advanceWork(ctx, nil, AdvanceWorkInput{
		TaskID: taskID,
		Action: "clarify",
	})
	if err != nil {
		t.Fatalf("advance_work(clarify): %v", err)
	}
	if clarified.Task.Status != "todo" {
		t.Errorf("task status after clarify = %q, want %q", clarified.Task.Status, "todo")
	}

	// 4. Plan the day with this task
	_, plan, err := s.planDay(ctx, nil, PlanDayInput{
		Items: []PlanDayItem{{TaskID: taskID, Position: 1}},
	})
	if err != nil {
		t.Fatalf("plan_day: %v", err)
	}
	if len(plan.Items) != 1 {
		t.Fatalf("plan items = %d, want 1", len(plan.Items))
	}

	// 5. Complete the task
	_, completed, err := s.advanceWork(ctx, nil, AdvanceWorkInput{
		TaskID: taskID,
		Action: "complete",
	})
	if err != nil {
		t.Fatalf("advance_work(complete): %v", err)
	}
	if completed.Task.Status != "done" {
		t.Errorf("task status after complete = %q, want %q", completed.Task.Status, "done")
	}
	if !completed.PlanItemUpdated {
		t.Error("expected plan_item_updated to be true")
	}

	// 6. Write a reflection journal
	_, journal, err := s.writeJournal(ctx, nil, WriteJournalInput{
		Kind:    "reflection",
		Content: "Reviewed the PR, looks good. Auth middleware is solid.",
	})
	if err != nil {
		t.Fatalf("write_journal: %v", err)
	}
	if journal.Entry.Kind != "reflection" {
		t.Errorf("journal kind = %q, want %q", journal.Entry.Kind, "reflection")
	}

	// 7. Reflection context — should show the completed plan item
	_, reflection, err := s.reflectionContext(ctx, nil, ReflectionContextInput{})
	if err != nil {
		t.Fatalf("reflection_context: %v", err)
	}
	if len(reflection.TodayJournals) == 0 {
		t.Error("expected at least 1 journal entry in reflection")
	}
}

// TestProposalWorkflow tests the full propose → commit cycle.
func TestProposalWorkflow(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	// 1. Propose a goal
	_, proposal, err := s.proposeCommitment(ctx, nil, ProposeCommitmentInput{
		Type: "goal",
		Fields: map[string]any{
			"title":       "Pass JLPT N2 by June",
			"description": "Japanese language proficiency test",
			"quarter":     "2026-Q2",
		},
	})
	if err != nil {
		t.Fatalf("propose_commitment: %v", err)
	}
	if proposal.Type != "goal" {
		t.Errorf("proposal type = %q, want %q", proposal.Type, "goal")
	}
	if proposal.ProposalToken == "" {
		t.Fatal("proposal_token is empty")
	}
	if proposal.Preview["title"] != "Pass JLPT N2 by June" {
		t.Errorf("preview title = %v, want %q", proposal.Preview["title"], "Pass JLPT N2 by June")
	}

	// 2. Commit the proposal
	_, committed, err := s.commitProposal(ctx, nil, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commit_proposal: %v", err)
	}
	if committed.Type != "goal" {
		t.Errorf("committed type = %q, want %q", committed.Type, "goal")
	}
	if committed.ID == "" {
		t.Error("committed ID is empty")
	}

	// 3. Verify goal was created by querying the DB directly.
	// goal_progress only shows in-progress goals; newly created goals are "not-started".
	// This is correct behavior — goal_progress is for tracking active work.
	row, err := s.goals.GoalByTitle(ctx, "Pass JLPT N2 by June")
	if err != nil {
		t.Fatalf("goal lookup: %v", err)
	}
	if row.Status != "not-started" {
		t.Errorf("goal status = %q, want %q", row.Status, "not-started")
	}
}

// TestLearningSessionWorkflow tests the learning session lifecycle:
// start_session → record_attempt(×2) → end_session → learning_dashboard
func TestLearningSessionWorkflow(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	// 1. Start a practice session
	_, started, err := s.startSession(ctx, nil, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("start_session: %v", err)
	}
	if started.Session.Domain != "leetcode" {
		t.Errorf("session domain = %q, want %q", started.Session.Domain, "leetcode")
	}
	sessionID := started.Session.ID.String()

	// 2. Cannot start another session while one is active
	_, _, err = s.startSession(ctx, nil, StartSessionInput{
		Domain: "japanese",
		Mode:   "practice",
	})
	if err == nil {
		t.Fatal("expected error for duplicate session, got nil")
	}

	// 3. Record first attempt (solved independently)
	_, attempt1, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Two Sum", ExternalID: strPtr("1")},
		Outcome:   "got it",
		Observations: []ObservationInput{
			{Concept: "hash-map", Signal: "mastery", Category: "data-structure", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("record_attempt(1): %v", err)
	}
	if attempt1.Attempt.Outcome != "solved_independent" {
		t.Errorf("attempt outcome = %q, want %q", attempt1.Attempt.Outcome, "solved_independent")
	}
	if attempt1.ObservationsRecorded != 1 {
		t.Errorf("observations_recorded = %d, want 1", attempt1.ObservationsRecorded)
	}

	// 4. Record second attempt (needed help)
	_, attempt2, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Merge K Sorted Lists", ExternalID: strPtr("23")},
		Outcome:   "needed help",
		Observations: []ObservationInput{
			{Concept: "heap", Signal: "weakness", Category: "data-structure", Severity: strPtr("moderate"), Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("record_attempt(2): %v", err)
	}
	if attempt2.Attempt.Outcome != "solved_with_hint" {
		t.Errorf("attempt outcome = %q, want %q", attempt2.Attempt.Outcome, "solved_with_hint")
	}

	// 5. End the session with reflection
	_, ended, err := s.endSession(ctx, nil, EndSessionInput{
		SessionID:  sessionID,
		Reflection: strPtr("Good session. Need more practice with heaps."),
	})
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	if len(ended.Attempts) != 2 {
		t.Errorf("session attempts = %d, want 2", len(ended.Attempts))
	}
	if ended.Session.EndedAt == nil {
		t.Error("session ended_at should not be nil")
	}

	// 6. Verify dashboard overview shows the session
	_, overview, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
		Domain: strPtr("leetcode"),
	})
	if err != nil {
		t.Fatalf("learning_dashboard(overview): %v", err)
	}
	if overview.Total == 0 {
		t.Error("expected at least 1 session in overview")
	}

	// 7. Verify mastery view shows observations
	_, mastery, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
		Domain: strPtr("leetcode"),
		View:   strPtr("mastery"),
	})
	if err != nil {
		t.Fatalf("learning_dashboard(mastery): %v", err)
	}
	if mastery.Total == 0 {
		t.Error("expected at least 1 concept in mastery view")
	}

	// 8. Verify weaknesses view shows the heap weakness
	_, weaknesses, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
		Domain: strPtr("leetcode"),
		View:   strPtr("weaknesses"),
	})
	if err != nil {
		t.Fatalf("learning_dashboard(weaknesses): %v", err)
	}
	if weaknesses.Total == 0 {
		t.Error("expected at least 1 weakness in weaknesses view")
	}

	// 9. Verify timeline shows session with stats
	_, timeline, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
		Domain: strPtr("leetcode"),
		View:   strPtr("timeline"),
	})
	if err != nil {
		t.Fatalf("learning_dashboard(timeline): %v", err)
	}
	if timeline.Total == 0 {
		t.Error("expected at least 1 session in timeline view")
	}
}

// TestManagePlan_ProgressNonexistent covers the CRITICAL gap where mpProgress
// used to silently return {total:0, items:[]} for a bogus plan_id instead of
// erroring. Every other mp* action fetches the plan first; progress was the
// lone read path that allowed the mistake through.
func TestManagePlan_ProgressNonexistent(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	bogus := "00000000-0000-0000-0000-000000000001"
	_, _, err := s.managePlan(ctx, nil, ManagePlanInput{
		Action: "progress",
		PlanID: bogus,
	})
	if err == nil {
		t.Fatal("managePlan(progress) on nonexistent plan: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "plan") {
		t.Errorf("error should reference plan lookup, got: %v", err)
	}
}

// TestRecordAttempt_RelatedItems covers the related_items write path:
// self-link rejected, cross-domain rejected as warning, duplicate link is
// idempotent (ON CONFLICT DO NOTHING), and valid links are persisted and
// readable via the variations view. Also validates that invalid entries
// become warnings without failing the attempt record.
func TestRecordAttempt_RelatedItems(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	_, started, err := s.startSession(ctx, nil, StartSessionInput{Domain: "leetcode", Mode: "practice"})
	if err != nil {
		t.Fatalf("start_session: %v", err)
	}
	sessionID := started.Session.ID.String()

	// First attempt links to two valid harder variants, one cross-domain
	// (rejected as warning), one with unknown relation_type (rejected),
	// and one with the same external_id as the source (self-link rejected).
	_, attempt, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Two Sum", ExternalID: strPtr("1")},
		Outcome:   "got it",
		RelatedItems: []RelatedItemInput{
			{Title: "3Sum", ExternalID: strPtr("15"), RelationType: "harder_variant"},
			{Title: "4Sum", ExternalID: strPtr("18"), RelationType: "harder_variant"},
			{Title: "Pattern drill", Domain: strPtr("japanese"), RelationType: "same_pattern"}, // cross-domain
			{Title: "Bogus", RelationType: "not_a_real_type"},                                  // bad type
			{Title: "", RelationType: "same_pattern"},                                          // missing title
			{Title: "Two Sum", ExternalID: strPtr("1"), RelationType: "same_pattern"},          // self-link
		},
	})
	if err != nil {
		t.Fatalf("record_attempt: %v", err)
	}
	if attempt.RelationsLinked != 2 {
		t.Errorf("relations_linked = %d, want 2", attempt.RelationsLinked)
	}
	if len(attempt.RelationWarnings) != 4 {
		t.Errorf("relation_warnings = %d (%v), want 4", len(attempt.RelationWarnings), attempt.RelationWarnings)
	}

	// Second attempt re-links to 3Sum with same relation_type — should succeed
	// idempotently (no warning, linked count bumps because the call happened,
	// but the DB row count stays the same via ON CONFLICT DO NOTHING).
	_, attempt2, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Two Sum", ExternalID: strPtr("1")},
		Outcome:   "got it",
		RelatedItems: []RelatedItemInput{
			{Title: "3Sum", ExternalID: strPtr("15"), RelationType: "harder_variant"},
		},
	})
	if err != nil {
		t.Fatalf("record_attempt (idempotent re-link): %v", err)
	}
	if attempt2.RelationsLinked != 1 {
		t.Errorf("idempotent re-link linked = %d, want 1", attempt2.RelationsLinked)
	}
	if len(attempt2.RelationWarnings) != 0 {
		t.Errorf("idempotent re-link should produce no warnings, got: %v", attempt2.RelationWarnings)
	}

	// Verify variations view shows the two relations that actually persisted.
	_, variations, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
		Domain: strPtr("leetcode"),
		View:   strPtr("variations"),
	})
	if err != nil {
		t.Fatalf("learning_dashboard(variations): %v", err)
	}
	if variations.Total < 2 {
		t.Errorf("variations view total = %d, want >= 2 (3Sum, 4Sum)", variations.Total)
	}

	// Clean up — end the session.
	if _, _, err := s.endSession(ctx, nil, EndSessionInput{SessionID: sessionID}); err != nil {
		t.Fatalf("end_session: %v", err)
	}
}

// TestRecordAttempt_FSRSRatingOverride exercises the override path and the
// TOCTOU race-recovery path in createAndReviewCard. The CRITICAL bug was
// that on unique-violation retry, the rating was silently demoted to Again.
// We detect a regression by running N concurrent record_attempt calls for
// the SAME item and checking that no resulting review log carries Again
// when every call requested Easy.
func TestRecordAttempt_FSRSRatingOverride(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	// Each subtest needs its own session; close any session left open by a
	// previous subtest first so startSession doesn't hit ErrActiveExists.
	newSession := func(t *testing.T, domain string) string {
		t.Helper()
		if active, err := s.learn.ActiveSession(ctx); err == nil && active != nil {
			_, _, _ = s.endSession(ctx, nil, EndSessionInput{SessionID: active.ID.String()})
		}
		_, started, err := s.startSession(ctx, nil, StartSessionInput{Domain: domain, Mode: "practice"})
		if err != nil {
			t.Fatalf("start_session: %v", err)
		}
		return started.Session.ID.String()
	}

	t.Run("override replaces outcome-derived rating", func(t *testing.T) {
		sessionID := newSession(t, "leetcode")
		defer func() { _, _, _ = s.endSession(ctx, nil, EndSessionInput{SessionID: sessionID}) }()

		easy := 4
		_, attempt, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
			SessionID:  sessionID,
			Item:       AttemptItem{Title: "Valid Parentheses", ExternalID: strPtr("20")},
			Outcome:    "needed help", // would normally map to Hard
			FSRSRating: &easy,         // explicit override
		})
		if err != nil {
			t.Fatalf("record_attempt: %v", err)
		}
		if attempt.FSRSReviewFailed {
			t.Errorf("fsrs_review_failed = true, want false")
		}
	})

	t.Run("invalid override rating errors at store boundary", func(t *testing.T) {
		sessionID := newSession(t, "leetcode")
		defer func() { _, _, _ = s.endSession(ctx, nil, EndSessionInput{SessionID: sessionID}) }()

		// Rating 9 is out of range. The attempt itself should still persist
		// (FSRS review is auxiliary), but fsrs_review_failed should be true.
		bad := 9
		_, attempt, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
			SessionID:  sessionID,
			Item:       AttemptItem{Title: "Reverse Integer", ExternalID: strPtr("7")},
			Outcome:    "got it",
			FSRSRating: &bad,
		})
		if err != nil {
			t.Fatalf("record_attempt: %v", err)
		}
		if !attempt.FSRSReviewFailed {
			t.Error("fsrs_review_failed should be true for invalid rating")
		}
	})

	t.Run("TOCTOU race recovery preserves Easy rating", func(t *testing.T) {
		// Regression test for the CRITICAL bug: createAndReviewCard retry used
		// to call ReviewItem(ctx, itemID, "", now) which mapped "" to Again,
		// silently demoting the caller's intended rating. The fix re-enters
		// reviewItemWithRating with the original rating in scope.
		//
		// We bypass record_attempt here and drive the store method directly,
		// because record_attempt has its own attempt_number race that would
		// mask this test. The race we want exercises the unique index on
		// review_cards(learning_item_id): exactly one concurrent call wins
		// the INSERT, the rest hit the unique-violation recovery path.
		itemID, err := s.learn.FindOrCreateItem(ctx, "leetcode", "Climbing Stairs", strPtr("70"), nil)
		if err != nil {
			t.Fatalf("FindOrCreateItem: %v", err)
		}

		const parallelism = 8
		errCh := make(chan error, parallelism)
		var wg sync.WaitGroup
		for range parallelism {
			wg.Go(func() {
				_, err := s.learn.ReviewItemWithRating(ctx, itemID, 4 /*Easy*/, time.Now())
				errCh <- err
			})
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				t.Errorf("concurrent ReviewItemWithRating: %v", err)
			}
		}

		// Verify review_logs for the item has no Again ratings. Against the
		// old bug this would flag one Again per unique-violation retry.
		var againCount int
		err = s.pool.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM review_logs rl
			JOIN review_cards rc ON rc.id = rl.card_id
			WHERE rc.learning_item_id = $1 AND rl.rating = 1
		`, itemID).Scan(&againCount)
		if err != nil {
			t.Fatalf("query review logs: %v", err)
		}
		if againCount > 0 {
			t.Errorf("found %d Again ratings for item that was only ever rated Easy — race recovery is dropping the caller's rating", againCount)
		}
	})
}

// Shared comparison options — ignore time fields that vary per run.
var ignoreTimeFields = cmpopts.IgnoreFields(struct{ CreatedAt, StartedAt, EndedAt, AttemptedAt time.Time }{})

// Ensure cmp and ignoreTimeFields are used (prevent lint errors).
var _ = cmp.Diff
var _ = ignoreTimeFields
