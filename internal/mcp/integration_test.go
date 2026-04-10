//go:build integration

package mcp

import (
	"fmt"
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

// TestAttemptHistory exercises all three lookup modes (item, concept, session)
// plus the negative paths. The Improvement Verification Loop in
// docs/Koopa-Learning.md depends on these lookups behaving correctly: a
// regression here silently breaks coaching.
func TestAttemptHistory(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	// Seed: one session with three attempts on two items, one concept with
	// observations on two of the three attempts.
	_, started, err := s.startSession(ctx, nil, StartSessionInput{Domain: "leetcode", Mode: "practice"})
	if err != nil {
		t.Fatalf("start_session: %v", err)
	}
	sessionID := started.Session.ID.String()

	// Attempt 1: Search in Rotated Sorted Array, needed help, weak on
	// invariant reasoning. This is the canonical Improvement Verification
	// Loop scenario from the audit report.
	_, _, err = s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Search in Rotated Sorted Array", ExternalID: strPtr("33")},
		Outcome:   "needed help",
		StuckAt:   strPtr("invariant reasoning across the rotation point"),
		Approach:  strPtr("modified binary search with extra branch"),
		Observations: []ObservationInput{
			{Concept: "binary-search-partition", Signal: "weakness", Category: "approach-selection", Severity: strPtr("moderate"), Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("record_attempt(1): %v", err)
	}

	// Attempt 2: same item again, this time independent. Tests that
	// AttemptsByItem returns multiple attempts in newest-first order.
	_, _, err = s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Search in Rotated Sorted Array", ExternalID: strPtr("33")},
		Outcome:   "got it",
		Approach:  strPtr("clean modified binary search, no branches"),
		Observations: []ObservationInput{
			{Concept: "binary-search-partition", Signal: "improvement", Category: "approach-selection", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("record_attempt(2): %v", err)
	}

	// Attempt 3: different item, no observation on binary-search-partition.
	// This attempt MUST NOT appear in by_concept results — only items with
	// an observation on the concept count.
	_, _, err = s.recordAttempt(ctx, nil, RecordAttemptInput{
		SessionID: sessionID,
		Item:      AttemptItem{Title: "Two Sum", ExternalID: strPtr("1")},
		Outcome:   "got it",
		Observations: []ObservationInput{
			{Concept: "hash-map", Signal: "mastery", Category: "data-structure", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("record_attempt(3): %v", err)
	}

	t.Run("by_item returns newest-first attempts on the item", func(t *testing.T) {
		_, out, err := s.attemptHistory(ctx, nil, AttemptHistoryInput{
			Item: &AttemptHistoryItemRef{Title: "Search in Rotated Sorted Array"},
		})
		if err != nil {
			t.Fatalf("attempt_history(item): %v", err)
		}
		if !out.Resolved {
			t.Errorf("resolved = false, want true (item exists)")
		}
		if out.Mode != "item" {
			t.Errorf("mode = %q, want %q", out.Mode, "item")
		}
		if len(out.Attempts) != 2 {
			t.Fatalf("attempts = %d, want 2", len(out.Attempts))
		}
		// Newest first: attempt 2 (got it) before attempt 1 (needed help)
		if out.Attempts[0].Outcome != "solved_independent" {
			t.Errorf("Attempts[0].Outcome = %q, want %q", out.Attempts[0].Outcome, "solved_independent")
		}
		if out.Attempts[1].Outcome != "solved_with_hint" {
			t.Errorf("Attempts[1].Outcome = %q, want %q", out.Attempts[1].Outcome, "solved_with_hint")
		}
		// Improvement Verification needs stuck_at and approach back.
		if out.Attempts[1].StuckAt == nil || *out.Attempts[1].StuckAt == "" {
			t.Error("Attempts[1].StuckAt should carry the original stuck_at narrative")
		}
		if out.Attempts[1].ApproachUsed == nil || *out.Attempts[1].ApproachUsed == "" {
			t.Error("Attempts[1].ApproachUsed should carry the original approach narrative")
		}
		// by_item must NOT attach matched_observation (concept-only field).
		if out.Attempts[0].Matched != nil {
			t.Error("by_item should not populate Matched")
		}
	})

	t.Run("by_concept attaches matched observation", func(t *testing.T) {
		_, out, err := s.attemptHistory(ctx, nil, AttemptHistoryInput{
			ConceptSlug: strPtr("binary-search-partition"),
		})
		if err != nil {
			t.Fatalf("attempt_history(concept): %v", err)
		}
		if !out.Resolved {
			t.Errorf("resolved = false, want true (concept exists)")
		}
		if out.Mode != "concept" {
			t.Errorf("mode = %q, want %q", out.Mode, "concept")
		}
		// Two attempts observed binary-search-partition; the third (Two Sum)
		// must NOT appear because it has no observation on this concept.
		if len(out.Attempts) != 2 {
			t.Fatalf("attempts = %d, want 2 (Two Sum must be excluded)", len(out.Attempts))
		}
		for i, a := range out.Attempts {
			if a.Matched == nil {
				t.Errorf("Attempts[%d].Matched is nil, want populated", i)
				continue
			}
			if a.Matched.Category != "approach-selection" {
				t.Errorf("Attempts[%d].Matched.Category = %q, want %q", i, a.Matched.Category, "approach-selection")
			}
		}
	})

	t.Run("by_session returns full session in chronological order", func(t *testing.T) {
		_, out, err := s.attemptHistory(ctx, nil, AttemptHistoryInput{
			SessionID: &sessionID,
		})
		if err != nil {
			t.Fatalf("attempt_history(session): %v", err)
		}
		if !out.Resolved {
			t.Errorf("resolved = false, want true")
		}
		if out.Mode != "session" {
			t.Errorf("mode = %q, want %q", out.Mode, "session")
		}
		if len(out.Attempts) != 3 {
			t.Fatalf("attempts = %d, want 3", len(out.Attempts))
		}
		// Chronological (oldest first): attempt 1 → 2 → 3
		if out.Attempts[0].Outcome != "solved_with_hint" {
			t.Errorf("Attempts[0].Outcome = %q, want %q", out.Attempts[0].Outcome, "solved_with_hint")
		}
		if out.Attempts[2].ItemTitle != "Two Sum" {
			t.Errorf("Attempts[2].ItemTitle = %q, want %q", out.Attempts[2].ItemTitle, "Two Sum")
		}
	})

	t.Run("by_item not found returns resolved=false", func(t *testing.T) {
		_, out, err := s.attemptHistory(ctx, nil, AttemptHistoryInput{
			Item: &AttemptHistoryItemRef{Title: "Never Attempted Problem"},
		})
		if err != nil {
			t.Fatalf("attempt_history(missing item): %v", err)
		}
		if out.Resolved {
			t.Error("resolved = true, want false (item does not exist)")
		}
		if len(out.Attempts) != 0 {
			t.Errorf("attempts = %d, want 0", len(out.Attempts))
		}
		if out.Reason == "" {
			t.Error("reason should explain why resolved=false")
		}
	})

	t.Run("zero inputs errors", func(t *testing.T) {
		_, _, err := s.attemptHistory(ctx, nil, AttemptHistoryInput{})
		if err == nil {
			t.Fatal("expected error for empty input, got nil")
		}
	})

	t.Run("multiple inputs errors", func(t *testing.T) {
		_, _, err := s.attemptHistory(ctx, nil, AttemptHistoryInput{
			Item:        &AttemptHistoryItemRef{Title: "Two Sum"},
			ConceptSlug: strPtr("hash-map"),
		})
		if err == nil {
			t.Fatal("expected error for multiple inputs, got nil")
		}
	})

	// Cleanup
	if _, _, err := s.endSession(ctx, nil, EndSessionInput{SessionID: sessionID}); err != nil {
		t.Fatalf("end_session: %v", err)
	}
}

// TestConfidenceFilterRejectsTypos is the regression guard against dead-
// validator drift: an earlier iteration of learningDashboard silently
// coerced any non-"all" confidence_filter value to "high", which defeated
// the store-layer normalizeConfidenceFilter check. This test proves the
// validator fires end-to-end from the MCP boundary. If it starts passing
// with a "hi" request, someone re-introduced the silent coercion.
func TestConfidenceFilterRejectsTypos(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	_, _, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
		View:             strPtr("mastery"),
		ConfidenceFilter: strPtr("hi"), // typo — not "high"
	})
	if err == nil {
		t.Fatal("expected confidence_filter=\"hi\" to be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "confidence_filter") {
		t.Errorf("error should reference confidence_filter, got: %v", err)
	}
}

// TestObservationConfidenceInvariant covers the most important property of
// the new "confidence is a label, not a gate" design: the mastery view's
// weakness_count and the weaknesses view's summed occurrence_count for the
// same concept MUST agree under the same confidence_filter. If they ever
// drift, the dashboard is silently lying — one number for "how often does
// this concept fail" disagrees with the breakdown of where the failures
// happened.
//
// Also verifies that low-confidence observations DO persist (not silently
// dropped like the old gate model) but are EXCLUDED from default reads
// (preserving the old user-facing behaviour).
func TestObservationConfidenceInvariant(t *testing.T) {
	s := setupIntegrationServer(t)
	ctx := t.Context()

	_, started, err := s.startSession(ctx, nil, StartSessionInput{Domain: "leetcode", Mode: "practice"})
	if err != nil {
		t.Fatalf("start_session: %v", err)
	}
	sessionID := started.Session.ID.String()

	// Three high-confidence weakness observations on binary-search across
	// two categories, plus one low-confidence weakness on the same concept.
	// Default mastery should see 3 weaknesses (the highs); confidence_filter=all
	// should see 4. The weaknesses view should produce occurrence_counts that
	// sum to the same number under each filter.
	for i, obs := range []struct {
		title    string
		category string
		conf     string
	}{
		{"Binary Search", "approach-selection", "high"},
		{"Search Insert Position", "approach-selection", "high"},
		{"Find Peak Element", "edge-cases", "high"},
		{"Sqrt(x)", "approach-selection", "low"}, // low — included only when filter=all
	} {
		_, _, err := s.recordAttempt(ctx, nil, RecordAttemptInput{
			SessionID: sessionID,
			Item:      AttemptItem{Title: obs.title, ExternalID: strPtr(fmt.Sprintf("bs-%d", i))},
			Outcome:   "needed help",
			Observations: []ObservationInput{
				{Concept: "binary-search", Signal: "weakness", Category: obs.category, Severity: strPtr("moderate"), Confidence: obs.conf},
			},
		})
		if err != nil {
			t.Fatalf("record_attempt(%d): %v", i, err)
		}
	}

	// Direct DB check: low-confidence observation must have persisted.
	var lowCount int
	err = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM attempt_observations WHERE confidence = 'low'`).Scan(&lowCount)
	if err != nil {
		t.Fatalf("count low observations: %v", err)
	}
	if lowCount != 1 {
		t.Errorf("low-confidence observations in DB = %d, want 1 (Option C: low must persist, not drop)", lowCount)
	}

	checkInvariant := func(t *testing.T, filter string, wantWeaknessCount int64) {
		t.Helper()
		_, mastery, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
			Domain:           strPtr("leetcode"),
			View:             strPtr("mastery"),
			ConfidenceFilter: strPtr(filter),
		})
		if err != nil {
			t.Fatalf("dashboard(mastery, %s): %v", filter, err)
		}
		_, weaknesses, err := s.learningDashboard(ctx, nil, LearningDashboardInput{
			Domain:           strPtr("leetcode"),
			View:             strPtr("weaknesses"),
			ConfidenceFilter: strPtr(filter),
		})
		if err != nil {
			t.Fatalf("dashboard(weaknesses, %s): %v", filter, err)
		}

		// Find binary-search row in mastery.
		var masteryWeakness int64 = -1
		for _, m := range mastery.Mastery {
			if m.Slug == "binary-search" {
				masteryWeakness = m.WeaknessCount
				break
			}
		}
		if masteryWeakness == -1 {
			t.Fatalf("binary-search not found in mastery view (filter=%s)", filter)
		}

		// Sum binary-search occurrences across categories in weaknesses view.
		var weaknessSum int64
		for _, w := range weaknesses.Weaknesses {
			if w.ConceptSlug == "binary-search" {
				weaknessSum += w.OccurrenceCount
			}
		}

		if masteryWeakness != weaknessSum {
			t.Errorf("invariant broken (filter=%s): mastery.weakness_count=%d but weaknesses sum=%d",
				filter, masteryWeakness, weaknessSum)
		}
		if masteryWeakness != wantWeaknessCount {
			t.Errorf("filter=%s mastery weakness_count = %d, want %d",
				filter, masteryWeakness, wantWeaknessCount)
		}
	}

	t.Run("default filter (high) sees 3 weaknesses", func(t *testing.T) {
		checkInvariant(t, "high", 3)
	})

	t.Run("filter=all surfaces the low-confidence weakness", func(t *testing.T) {
		checkInvariant(t, "all", 4)
	})

	// Cleanup
	if _, _, err := s.endSession(ctx, nil, EndSessionInput{SessionID: sessionID}); err != nil {
		t.Fatalf("end_session: %v", err)
	}
}

// Shared comparison options — ignore time fields that vary per run.
var ignoreTimeFields = cmpopts.IgnoreFields(struct{ CreatedAt, StartedAt, EndedAt, AttemptedAt time.Time }{})

// Ensure cmp and ignoreTimeFields are used (prevent lint errors).
var _ = cmp.Diff
var _ = ignoreTimeFields
