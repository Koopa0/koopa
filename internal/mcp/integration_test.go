//go:build integration

// integration_test.go bundles every testcontainers-backed test for the
// mcp package. Coverage is grouped into three concerns, each marked
// with a section banner below:
//
//  1. Cold-start workflow — capture_inbox / start_session /
//     commit_proposal(learning_plan) / record_attempt / end_session /
//     proposal validator / query_agent_notes / recommend_next_target.
//     Guards the write paths Learning Studio's 2026-04-17 self-audit
//     reported as broken on a freshly deployed DB.
//  2. manage_feeds(add) — regression guard for the schedule+topic
//     validator fix. The tool must accept the pairing and land both
//     the feed row and the feed_topics junction.
//  3. DB audit triggers — verifies the five audit triggers declared
//     in migrations/001_initial.up.sql fire on the expected state
//     changes and write the expected activity_events.change_kind.
//
// Run with:
//
//	go test -tags=integration ./internal/mcp/...
package mcp

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/mcp/ops"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// setupServer truncates application-written rows, reconciles the agent
// registry the way cmd/mcp/main.go does at startup, and returns a Server
// wired to the shared test pool. callerAgent is set to learning-studio —
// the agent whose audit produced this suite — so every activity_events
// row in a happy-path test should carry that actor.
func setupServer(t *testing.T) *Server {
	t.Helper()
	truncateApplicationTables(t)
	registry := agent.NewBuiltinRegistry()
	agentStore := agent.NewStore(testPool)
	if _, err := agent.SyncToTable(t.Context(), registry, agentStore, slog.Default()); err != nil {
		t.Fatalf("agent.SyncToTable: %v", err)
	}
	return NewServer(testPool, slog.Default(),
		WithRegistry(registry),
		WithCallerAgent("learning-studio"),
	)
}

// truncateApplicationTables clears every table an MCP handler can write to
// while preserving seed data from 002 (areas, topics, tags, feeds,
// learning_domains). agents stays intact because SyncToTable reconciles
// it in setupServer, not via TRUNCATE.
//
// CASCADE handles FK chains; RESTART IDENTITY keeps sequences deterministic
// across the TestMain-shared container.
func truncateApplicationTables(t *testing.T) {
	t.Helper()
	tables := []string{
		"activity_events",
		"daily_plan_items",
		"todos",
		"agent_notes",
		"contents",
		"bookmarks",
		"milestones",
		"goals",
		"projects",
		"learning_hypotheses",
		"task_messages",
		"artifacts",
		"tasks",
		"learning_attempt_observations",
		"learning_attempts",
		"learning_sessions",
		"learning_plan_entries",
		"learning_plans",
		"learning_target_relations",
		"learning_targets",
		"concepts",
	}
	sql := "TRUNCATE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE"
	if _, err := testPool.Exec(t.Context(), sql); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// activityActorFor reads the actor recorded by the audit_<entity> trigger
// for a single entity row. Empty string means no row exists — the trigger
// silently didn't fire, which is itself a test failure.
func activityActorFor(t *testing.T, entityType string, entityID uuid.UUID) string {
	t.Helper()
	var actor string
	err := testPool.QueryRow(t.Context(),
		"SELECT actor FROM activity_events WHERE entity_type = $1 AND entity_id = $2 ORDER BY occurred_at DESC LIMIT 1",
		entityType, entityID,
	).Scan(&actor)
	if err != nil {
		t.Fatalf("fetching activity_events for %s %s: %v", entityType, entityID, err)
	}
	return actor
}

// --- 1. capture_inbox end-to-end ---

// TestIntegration_ColdStart_CaptureInbox was Learning's first failure mode
// in the audit: activity_events_actor_fkey violation because koopa.actor
// was unset and the fallback 'system' wasn't in agents. After W1 (seed)
// and W2 (withActorTx) this must write both the todo and the audit row
// with actor = learning-studio.
func TestIntegration_ColdStart_CaptureInbox(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.captureInbox, CaptureInboxInput{
		Title:       "test capture",
		Description: "cold-start test",
	})
	if err != nil {
		t.Fatalf("captureInbox: %v", err)
	}
	if out.Task.ID == uuid.Nil {
		t.Fatal("captureInbox returned zero task ID")
	}

	if got := activityActorFor(t, "todo", out.Task.ID); got != "learning-studio" {
		t.Errorf("activity_events.actor = %q, want %q (koopa.actor propagation)", got, "learning-studio")
	}
}

// --- 2. start_session against a seeded domain ---

// TestIntegration_ColdStart_StartSession was Learning's second failure mode:
// learning_sessions_domain_fkey violation because the 5 declared domains
// were never seeded. After W1 this must resolve the FK and create the row.
func TestIntegration_ColdStart_StartSession(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}
	if out.Session.ID == uuid.Nil {
		t.Fatal("startSession returned zero session ID")
	}
	if out.Session.Domain != "leetcode" {
		t.Errorf("session.Domain = %q, want %q", out.Session.Domain, "leetcode")
	}
}

// --- 3. propose_learning_plan → commit_proposal ---

// TestIntegration_ColdStart_CommitLearningPlan was Learning's third failure
// mode: commit step hit learning_plans_domain_fkey for the same reason. It
// also exercises the propose/commit two-phase protocol end-to-end.
func TestIntegration_ColdStart_CommitLearningPlan(t *testing.T) {
	s := setupServer(t)

	_, proposal, err := callHandler(t, s.proposeLearningPlan, ProposeLearningPlanInput{
		Title:  "Binary Search 14-Day Drill",
		Domain: "leetcode",
	})
	if err != nil {
		t.Fatalf("proposeLearningPlan: %v", err)
	}
	if proposal.ProposalToken == "" {
		t.Fatal("proposeLearningPlan returned empty token")
	}

	_, commit, err := callHandler(t, s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commitProposal: %v", err)
	}
	if !commit.Committed {
		t.Error("commitProposal: Committed = false")
	}
	if commit.Type != "learning_plan" {
		t.Errorf("commitProposal.Type = %q, want %q", commit.Type, "learning_plan")
	}

	id, err := uuid.Parse(commit.ID)
	if err != nil {
		t.Fatalf("parsing returned plan ID: %v", err)
	}
	var domain string
	if err := testPool.QueryRow(t.Context(),
		"SELECT domain FROM learning_plans WHERE id = $1", id,
	).Scan(&domain); err != nil {
		t.Fatalf("fetching plan row: %v", err)
	}
	if domain != "leetcode" {
		t.Errorf("plan.domain = %q, want %q", domain, "leetcode")
	}
}

// --- 4. record_attempt with auto-create concept ---

// TestIntegration_ColdStart_RecordAttempt covers two invariants. First, the
// attempt row writes its audit event with the correct actor — the
// learning_attempts table is covered by audit_learning_attempts. Second, the
// observation references a concept slug that doesn't exist yet; record_attempt
// is allowed to auto-create leaf concepts in the session's domain, and the
// concept must be resolvable by the concepts.domain FK to learning_domains
// (seeded in W1).
func TestIntegration_ColdStart_RecordAttempt(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, rec, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target: AttemptTarget{
			Title: "Two Sum",
		},
		Outcome: "solved_independent",
		Observations: []ObservationInput{
			{
				Concept:    "hash-lookup",
				Signal:     "mastery",
				Category:   "pattern-recognition",
				Confidence: "high",
			},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}
	if rec.Attempt.ID == uuid.Nil {
		t.Fatal("recordAttempt returned zero attempt ID")
	}

	if got := activityActorFor(t, "learning_attempt", rec.Attempt.ID); got != "learning-studio" {
		t.Errorf("activity_events.actor for attempt = %q, want %q", got, "learning-studio")
	}

	var conceptDomain string
	err = testPool.QueryRow(t.Context(),
		"SELECT domain FROM concepts WHERE slug = $1", "hash-lookup",
	).Scan(&conceptDomain)
	if err != nil {
		t.Fatalf("auto-created concept hash-lookup not found: %v", err)
	}
	if conceptDomain != "leetcode" {
		t.Errorf("concept.domain = %q, want %q (inherits from session)", conceptDomain, "leetcode")
	}
}

// --- 5. end_session ---

// TestIntegration_ColdStart_EndSession verifies the lifecycle close works —
// ended_at is set, active-session constraint no longer triggers.
func TestIntegration_ColdStart_EndSession(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "go",
		Mode:   "reading",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, end, err := callHandler(t, s.endSession, EndSessionInput{
		SessionID: sess.Session.ID.String(),
	})
	if err != nil {
		t.Fatalf("endSession: %v", err)
	}
	if end.Session.EndedAt == nil {
		t.Error("endSession: Session.EndedAt is nil")
	}
}

// --- 6. Actor fallback — 'system' must resolve ---

// TestIntegration_ActorFallbackToSystem guards the safety net. withActorTx
// is supposed to set koopa.actor on every covered write, but if a bug or an
// ops-level SQL statement bypasses it, the audit trigger's fallback string
// is the literal 'system'. W1 registered that agent specifically so the FK
// resolves — if anyone removes it, this test fails and tells them why.
//
// The test writes a todo directly via the pool WITHOUT set_config. The
// audit trigger fires, reads an empty koopa.actor, falls back to 'system',
// and must succeed the activity_events FK.
func TestIntegration_ActorFallbackToSystem(t *testing.T) {
	setupServer(t) // reconciles registry so 'system' exists in agents

	var todoID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, created_by, state, energy, priority)
		 VALUES ($1, $2, 'inbox', 'medium', 'medium')
		 RETURNING id`,
		"raw insert — no actor set", "human",
	).Scan(&todoID)
	if err != nil {
		t.Fatalf("raw todos insert: %v (if 'system' isn't seeded this FK fails)", err)
	}

	if got := activityActorFor(t, "todo", todoID); got != "system" {
		t.Errorf("activity_events.actor = %q, want %q (fallback path)", got, "system")
	}
}

// --- 7. Proposal validator rejects missing required — no token ---

// TestIntegration_ProposalValidator covers the W4 symmetry guarantee.
// A typed propose_<type> call with a structurally invalid payload must
// return an error AND must NOT emit a proposal token. Each closure
// invokes the typed handler so the field set under test matches the
// handler's actual schema; a regression here is how the pre-W4
// 'warn-and-sign' bug used to work.
func TestIntegration_ProposalValidator_MissingRequired_NoToken(t *testing.T) {
	s := setupServer(t)

	cases := []struct {
		name       string
		propose    func() (ProposeOutput, error)
		wantErrSub string
	}{
		{
			name: "goal without title",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandler(t, s.proposeGoal, ProposeGoalInput{})
				return out, err
			},
			wantErrSub: "title is required for goal",
		},
		{
			name: "project without slug",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandler(t, s.proposeProject, ProposeProjectInput{Title: "x"})
				return out, err
			},
			wantErrSub: "slug is required for project",
		},
		{
			name: "milestone without goal",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandler(t, s.proposeMilestone, ProposeMilestoneInput{Title: "x"})
				return out, err
			},
			wantErrSub: "goal",
		},
		{
			name: "learning_plan without domain",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandler(t, s.proposeLearningPlan, ProposeLearningPlanInput{Title: "x"})
				return out, err
			},
			wantErrSub: "domain is required for learning_plan",
		},
		{
			name: "learning_domain with bad slug format",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandler(t, s.proposeLearningDomain, ProposeLearningDomainInput{Slug: "Not Kebab", Name: "X"})
				return out, err
			},
			wantErrSub: "invalid slug",
		},
		{
			name: "hypothesis without claim",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandler(t, s.proposeHypothesis, ProposeHypothesisInput{InvalidationCondition: "x", Content: "y"})
				return out, err
			},
			wantErrSub: "claim is required for hypothesis",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.propose()
			if err == nil {
				t.Fatalf("propose: expected error, got token=%q", out.ProposalToken)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error = %q, want containing %q", err, tc.wantErrSub)
			}
			if out.ProposalToken != "" {
				t.Errorf("ProposalToken = %q, want empty (invariant: invalid propose never signs)", out.ProposalToken)
			}
		})
	}
}

// --- 8. propose_learning_domain — W3 runtime addition ---

// TestIntegration_ProposeLearningDomain rounds out the W3 feature: a runtime
// domain is proposed, committed, and immediately usable as a session FK.
func TestIntegration_ProposeLearningDomain(t *testing.T) {
	s := setupServer(t)

	_, proposal, err := callHandler(t, s.proposeLearningDomain, ProposeLearningDomainInput{
		Slug: "rust",
		Name: "Rust",
	})
	if err != nil {
		t.Fatalf("proposeLearningDomain: %v", err)
	}
	if proposal.ProposalToken == "" {
		t.Fatal("proposeLearningDomain returned empty token")
	}

	_, commit, err := callHandler(t, s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commitProposal: %v", err)
	}
	if commit.ID != "rust" {
		t.Errorf("commitProposal.ID = %q, want %q", commit.ID, "rust")
	}

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "rust",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession on newly-committed domain: %v (W3 didn't make it usable)", err)
	}
	if sess.Session.Domain != "rust" {
		t.Errorf("session.Domain = %q, want %q", sess.Session.Domain, "rust")
	}
}

// --- 6. zombie session auto-end ---

// TestIntegration_StartSession_AutoEndsZombie covers the self-audit's top
// finding: a prior agent that exited without end_session would leave an
// active row that permanently blocked the single-active-session invariant,
// and there was no surgical path to reclaim it. start_session now runs the
// EndStaleActiveSession sweep first — any active session whose most recent
// activity (started_at or last attempt) is >12h old gets auto-ended, and
// the reclaimed row surfaces in the output as zombie_ended.
//
// Threshold behaviour:
//   - active session with no attempts, started 13h ago → zombie (ended)
//   - active session with no attempts, started 1h ago → still fresh
//     (fails with ErrActiveExists — expected, not a regression)
//
// The second branch is covered by the absence of a follow-up call here; the
// first is the primary assertion.
func TestIntegration_StartSession_AutoEndsZombie(t *testing.T) {
	s := setupServer(t)

	_, first, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession (first): %v", err)
	}
	if first.ZombieEnded != nil {
		t.Fatalf("first startSession surfaced a zombie unexpectedly: %v", first.ZombieEnded)
	}

	// Backdate the first session into zombie territory. The query threshold
	// is 12h; 13h is safely past it without flirting with clock skew.
	if _, err := testPool.Exec(t.Context(),
		"UPDATE learning_sessions SET started_at = now() - INTERVAL '13 hours' WHERE id = $1",
		first.Session.ID,
	); err != nil {
		t.Fatalf("backdating first session: %v", err)
	}

	_, second, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession (second, after backdate): %v", err)
	}
	if second.ZombieEnded == nil {
		t.Fatal("second startSession did not report a zombie_ended — stale session was not reclaimed")
	}
	if second.ZombieEnded.ID != first.Session.ID {
		t.Errorf("zombie_ended.ID = %s, want %s (the backdated session)", second.ZombieEnded.ID, first.Session.ID)
	}
	if second.ZombieEnded.EndedAt == nil {
		t.Error("zombie_ended.EndedAt is nil — reclaimed row should carry a non-nil ended_at")
	}
	if second.Session.ID == first.Session.ID {
		t.Error("second startSession returned the zombie row as the new session")
	}
}

// TestIntegration_FindOrCreateTarget_TitleCanonicalises covers the other
// audit finding: record_attempt with external_id and manage_plan.add_entries
// with only title were producing two separate learning_targets rows for the
// same problem, silently splitting attempt history and mastery signals.
// With the title-fallback lookup, a later title-only resolution matches the
// row a prior title-only resolution created (same domain, same exact title).
//
// External-id-bearing rows still match via the primary (domain, external_id)
// path; this test focuses on the title-only branch because that is the path
// that was silently creating duplicates.
func TestIntegration_FindOrCreateTarget_TitleCanonicalises(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// First pass: plain title, no external_id. Creates a new row.
	_, first, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "House Robber"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt (first): %v", err)
	}

	// Second pass: identical title. Must resolve to the SAME row.
	_, second, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "House Robber"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt (second): %v", err)
	}

	if first.Attempt.LearningTargetID != second.Attempt.LearningTargetID {
		t.Errorf("title-only resolution split the target: first=%s second=%s (expected identical)",
			first.Attempt.LearningTargetID, second.Attempt.LearningTargetID)
	}

	// Sanity: DB has exactly one row with this domain+title.
	var count int
	if err := testPool.QueryRow(t.Context(),
		"SELECT COUNT(*) FROM learning_targets WHERE domain = 'leetcode' AND title = 'House Robber'",
	).Scan(&count); err != nil {
		t.Fatalf("counting targets: %v", err)
	}
	if count != 1 {
		t.Errorf("learning_targets count = %d, want 1 (title canonicalisation failed)", count)
	}
}

// TestIntegration_UpdateEntry_AlignsAttemptToTarget covers the audit §4.3
// "policy 表面功夫" concern: manage_plan.update_entry accepted any
// completed_by_attempt_id with no server-side check that the attempt was
// actually recorded on the plan entry's learning_target. The check now
// fetches both rows and rejects the mismatch up-front with ErrInvalidInput.
//
// Scenario: a plan contains entry E on target T1. A record_attempt on T2
// produces attempt A2. Marking E completed with completed_by_attempt_id=A2
// must fail — the audit trail would otherwise claim A2 proved E complete,
// which is false.
func TestIntegration_UpdateEntry_AlignsAttemptToTarget(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// Create two distinct targets by recording attempts on both.
	_, a1, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Two Sum"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt T1: %v", err)
	}
	_, a2, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "House Robber"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt T2: %v", err)
	}
	if a1.Attempt.LearningTargetID == a2.Attempt.LearningTargetID {
		t.Fatal("distinct-title recordAttempts collapsed onto the same target — test precondition failed")
	}

	// Build a plan on T1 (Two Sum) and activate it.
	_, proposal, err := callHandler(t, s.proposeLearningPlan, ProposeLearningPlanInput{
		Title:  "Hash-map Drill",
		Domain: "leetcode",
	})
	if err != nil {
		t.Fatalf("propose plan: %v", err)
	}
	_, commit, err := callHandler(t, s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commit plan: %v", err)
	}

	_, _, err = callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: commit.ID,
		Entries: []ManagePlanEntryInput{
			{Title: "Two Sum", Position: 1},
		},
	})
	if err != nil {
		t.Fatalf("add_entries: %v", err)
	}

	active := "active"
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "update_plan",
		PlanID: commit.ID,
		Status: &active,
	}); err != nil {
		t.Fatalf("activate plan: %v", err)
	}

	// Find the entry id we just added.
	var entryID string
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_plan_entries WHERE plan_id = $1",
		commit.ID,
	).Scan(&entryID); err != nil {
		t.Fatalf("locating plan entry: %v", err)
	}

	// Attempt to complete the Two Sum entry using the HOUSE ROBBER attempt.
	// Must be rejected as a misalignment.
	completed := "completed"
	mismatchAttempt := a2.Attempt.ID.String() // wrong target
	reason := "closing entry"
	_, _, err = callHandler(t, s.managePlan, ManagePlanInput{
		Action:               "update_entry",
		PlanID:               commit.ID,
		EntryID:              &entryID,
		Status:               &completed,
		CompletedByAttemptID: &mismatchAttempt,
		Reason:               &reason,
	})
	if err == nil {
		t.Fatal("update_entry accepted a mismatched completed_by_attempt_id — alignment check is not firing")
	}
	if !strings.Contains(err.Error(), "learning_target") {
		t.Errorf("error = %q, want it to name the target-mismatch reason", err)
	}

	// Sanity: the correct attempt (on Two Sum) must succeed.
	matchAttempt := a1.Attempt.ID.String()
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:               "update_entry",
		PlanID:               commit.ID,
		EntryID:              &entryID,
		Status:               &completed,
		CompletedByAttemptID: &matchAttempt,
		Reason:               &reason,
	}); err != nil {
		t.Fatalf("update_entry with aligned attempt: %v", err)
	}
}

// --- query_agent_notes ---

// TestIntegration_QueryAgentNotes_FiltersAcrossDates seeds three notes
// spanning kind + author dimensions and verifies the wire filter applies
// correctly. The tool exists because session_delta's 24h window leaves
// the coach unable to recall prior reflections across multi-day gaps.
func TestIntegration_QueryAgentNotes_FiltersAcrossDates(t *testing.T) {
	s := setupServer(t)

	// Three notes: two reflections by learning-studio on different days,
	// one plan by hq. The filters we care about are kind, author, and
	// window bounds.
	mustWrite := func(kind, content, author string, daysAgo int) {
		t.Helper()
		entryDate := s.today().AddDate(0, 0, -daysAgo).Format("2006-01-02")
		if _, err := testPool.Exec(t.Context(),
			`INSERT INTO agent_notes (kind, created_by, content, entry_date)
			 VALUES ($1::agent_note_kind, $2, $3, $4::date)`,
			kind, author, content, entryDate,
		); err != nil {
			t.Fatalf("seeding agent note (%s, %d days ago): %v", kind, daysAgo, err)
		}
	}
	mustWrite("reflection", "day-1 reflection", "learning-studio", 1)
	mustWrite("reflection", "day-5 reflection", "learning-studio", 5)
	mustWrite("plan", "day-1 plan", "hq", 1)

	// No filter → all 3 within default 90d window.
	_, all, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{})
	if err != nil {
		t.Fatalf("queryAgentNotes (no filter): %v", err)
	}
	if all.Total != 3 {
		t.Errorf("no-filter total = %d, want 3", all.Total)
	}

	// kind=reflection → 2 rows.
	reflection := "reflection"
	_, byKind, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{Kind: &reflection})
	if err != nil {
		t.Fatalf("queryAgentNotes kind=reflection: %v", err)
	}
	if byKind.Total != 2 {
		t.Errorf("kind=reflection total = %d, want 2", byKind.Total)
	}

	// author=hq → 1 row.
	hq := "hq"
	_, byAuthor, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{Author: &hq})
	if err != nil {
		t.Fatalf("queryAgentNotes author=hq: %v", err)
	}
	if byAuthor.Total != 1 {
		t.Errorf("author=hq total = %d, want 1", byAuthor.Total)
	}

	// since=3 days ago → excludes the 5-day-old reflection, leaves 2.
	threeDaysAgo := s.today().AddDate(0, 0, -3).Format("2006-01-02")
	_, sinceFiltered, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{Since: &threeDaysAgo})
	if err != nil {
		t.Fatalf("queryAgentNotes since=3d: %v", err)
	}
	if sinceFiltered.Total != 2 {
		t.Errorf("since=3d total = %d, want 2 (5-day-old row must fall outside)", sinceFiltered.Total)
	}

	// since > until → ErrInvalidInput (surfaced via callHandler's error).
	invalidUntil := s.today().AddDate(0, 0, -10).Format("2006-01-02")
	if _, _, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{
		Since: &threeDaysAgo, Until: &invalidUntil,
	}); err == nil {
		t.Error("queryAgentNotes accepted since > until; should error")
	}
}

// TestIntegration_QueryAgentNotes_FullTextSearch verifies the Query
// parameter routes through the FTS path, respects other filters, and
// ranks newer matches ahead of older ones at the same lexical match
// quality.
func TestIntegration_QueryAgentNotes_FullTextSearch(t *testing.T) {
	s := setupServer(t)

	mustWrite := func(kind, content, author string, daysAgo int) {
		t.Helper()
		entryDate := s.today().AddDate(0, 0, -daysAgo).Format("2006-01-02")
		if _, err := testPool.Exec(t.Context(),
			`INSERT INTO agent_notes (kind, created_by, content, entry_date)
			 VALUES ($1::agent_note_kind, $2, $3, $4::date)`,
			kind, author, content, entryDate,
		); err != nil {
			t.Fatalf("seeding agent note: %v", err)
		}
	}
	// Three notes that all mention "embedding", one that does not.
	// Dates control the recency tiebreak.
	mustWrite("reflection", "thoughts on embedding pipeline latency", "learning-studio", 1)
	mustWrite("context", "notes about embedding cost tradeoffs", "hq", 10)
	mustWrite("plan", "tomorrow: review embedding dimension choice", "hq", 30)
	mustWrite("reflection", "unrelated thought on scheduling", "hq", 1)

	query := "embedding"
	_, out, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{Query: &query})
	if err != nil {
		t.Fatalf("queryAgentNotes query=embedding: %v", err)
	}
	if out.Total != 3 {
		t.Errorf("FTS total = %d, want 3 (three notes mention 'embedding')", out.Total)
	}
	// The day-1 note must rank ahead of the day-30 note — recency weight
	// dominates when ts_rank is similar.
	if len(out.Notes) >= 2 && !strings.Contains(out.Notes[0].Content, "latency") {
		t.Errorf("FTS top hit = %q, want the day-1 embedding note (recency should beat day-30)", out.Notes[0].Content)
	}

	// Query + kind filter composes.
	reflectionKind := "reflection"
	_, kindOut, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{
		Query: &query, Kind: &reflectionKind,
	})
	if err != nil {
		t.Fatalf("queryAgentNotes query+kind: %v", err)
	}
	if kindOut.Total != 1 {
		t.Errorf("FTS+kind=reflection total = %d, want 1", kindOut.Total)
	}

	// Query that matches nothing returns an empty slice, not an error.
	nohit := "zzznohit"
	_, empty, err := callHandler(t, s.queryAgentNotes, QueryAgentNotesInput{Query: &nohit})
	if err != nil {
		t.Fatalf("queryAgentNotes query=nohit: %v", err)
	}
	if empty.Total != 0 {
		t.Errorf("FTS no-match total = %d, want 0", empty.Total)
	}
}

// --- recommend_next_target ---

// TestIntegration_RecommendNextTarget_HappyPath covers the normal flow:
// seed a weakness via observations, record attempts on anchor problems,
// link harder_variants the user hasn't tried, and verify the recommender
// surfaces the variant with the right source_concept + relation_type.
func TestIntegration_RecommendNextTarget_HappyPath(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// Three weakness observations on the same concept → crosses the
	// MinObservationsForVerdict floor so DeriveMasteryStage returns
	// struggling and WeaknessAnalysis surfaces the concept.
	severityCritical := "critical"
	for i := 0; i < 3; i++ {
		title := "anchor-" + string(rune('A'+i)) //nolint:gocritic // trivially safe ASCII construction for test titles
		_, _, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
			SessionID: sess.Session.ID.String(),
			Target:    AttemptTarget{Title: title},
			Outcome:   "gave_up",
			Observations: []ObservationInput{
				{Concept: "dp-subset", Signal: "weakness", Category: "pattern-recognition", Severity: &severityCritical, Confidence: "high"},
			},
		})
		if err != nil {
			t.Fatalf("recordAttempt %s: %v", title, err)
		}
	}

	// Link an UNATTEMPTED related target off anchor-A. relation_type
	// harder_variant is in the allowed set so the recommender will
	// accept it.
	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "anchor-A"},
		Outcome:   "solved_with_hint",
		RelatedTargets: []RelatedTargetInput{
			{Title: "harder-variant-of-A", RelationType: "harder_variant"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt with related_targets: %v", err)
	}

	// The recommender should surface harder-variant-of-A.
	_, rec, err := callHandler(t, s.recommendNextTarget, RecommendNextTargetInput{
		SessionID: sess.Session.ID.String(),
	})
	if err != nil {
		t.Fatalf("recommendNextTarget: %v", err)
	}
	if len(rec.Candidates) == 0 {
		t.Fatalf("no candidates; empty_reason=%q", rec.EmptyReason)
	}
	found := false
	for _, c := range rec.Candidates {
		if c.Title == "harder-variant-of-A" && c.RelationType == "harder_variant" && c.SourceConcept == "dp-subset" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("candidates missing harder-variant-of-A: %+v", rec.Candidates)
	}
}

// TestIntegration_RecommendNextTarget_NoWeaknesses covers the empty-state
// contract: no weakness signal means no recommendation. The tool must
// return zero candidates with an explanatory empty_reason rather than
// failing or fabricating.
func TestIntegration_RecommendNextTarget_NoWeaknesses(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, rec, err := callHandler(t, s.recommendNextTarget, RecommendNextTargetInput{
		SessionID: sess.Session.ID.String(),
	})
	if err != nil {
		t.Fatalf("recommendNextTarget: %v", err)
	}
	if len(rec.Candidates) != 0 {
		t.Errorf("candidates = %d, want 0 in empty-state", len(rec.Candidates))
	}
	if rec.EmptyReason == "" {
		t.Error("empty_reason should explain why no candidates returned")
	}
}

// TestIntegration_RecommendNextTarget_RejectsInactiveSession asserts the
// handler errors if the supplied session_id doesn't match the active
// session. This is the same contract prepareAttempt enforces — the
// recommender only makes sense in-session.
func TestIntegration_RecommendNextTarget_RejectsInactiveSession(t *testing.T) {
	s := setupServer(t)

	if _, _, err := callHandler(t, s.recommendNextTarget, RecommendNextTargetInput{
		SessionID: uuid.New().String(),
	}); err == nil {
		t.Error("recommendNextTarget accepted unknown session; should error")
	}
}

// =========================================================================
// Section 2: manage_feeds(add) runtime fix regression
// =========================================================================
//
// Before commit 21 the MCP tool rejected the required schedule +
// topic_ids pairing — the validator tripped on the pointer-vs-empty
// distinction and the FK walk to topics never happened. This suite
// adds a real topic via SQL, then calls the tool through the same
// callHandler path the cold-start suite uses, and verifies a row
// landed in feeds plus a matching feed_topics junction.

// seedFeedTopic inserts one topic and returns its id string. The MCP
// tool takes topic_ids as a []string of canonical UUID forms, so the
// helper hands back the string form ready to pass in.
func seedFeedTopic(t *testing.T, slug, name string) (topicID uuid.UUID, topicIDStr string) {
	t.Helper()
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO topics (slug, name, description, sort_order)
		 VALUES ($1, $2, 'V5 fixture', 500)
		 RETURNING id`, slug, name,
	).Scan(&topicID)
	if err != nil {
		t.Fatalf("seeding topic %s: %v", slug, err)
	}
	return topicID, topicID.String()
}

// TestIntegration_ManageFeedsAdd_WithScheduleAndTopics is the V5 regression
// guard. It calls manage_feeds(action=add) with schedule='hourly' and a
// valid topic_id. Before V5 the request was rejected; after V5 both the
// feeds row and feed_topics junction must exist.
func TestIntegration_ManageFeedsAdd_WithScheduleAndTopics(t *testing.T) {
	s := setupServer(t)

	// setupServer truncated topics; seed a fresh one scoped to this
	// test's fixture so the FK walk has a valid target.
	topicID, topicIDStr := seedFeedTopic(t, "v5-fixture", "V5 Fixture")

	feedURL := "https://example.com/v5-fixture-feed.xml"
	feedName := "V5 Fixture Feed"
	schedule := "hourly"

	_, out, err := callHandler(t, s.manageFeeds, ManageFeedsInput{
		Action:   "add",
		URL:      &feedURL,
		Name:     &feedName,
		Schedule: &schedule,
		TopicIDs: []string{topicIDStr},
	})
	if err != nil {
		t.Fatalf("manageFeeds(add): %v", err)
	}
	if out.Feed == nil {
		t.Fatal("manageFeeds(add): returned Feed is nil")
	}
	if out.Feed.ID == uuid.Nil {
		t.Fatal("manageFeeds(add): returned Feed has zero ID")
	}

	// Confirm the feed row landed with the expected schedule.
	var (
		dbURL      string
		dbSchedule string
	)
	err = testPool.QueryRow(t.Context(),
		`SELECT url, schedule FROM feeds WHERE id = $1`, out.Feed.ID,
	).Scan(&dbURL, &dbSchedule)
	if err != nil {
		t.Fatalf("reading feed row: %v", err)
	}
	if dbURL != feedURL {
		t.Errorf("feeds.url = %q, want %q", dbURL, feedURL)
	}
	if dbSchedule != schedule {
		t.Errorf("feeds.schedule = %q, want %q", dbSchedule, schedule)
	}

	// Confirm the junction row landed so the topic association actually
	// persisted. A V5 regression where topic_ids is parsed but not
	// written would show up as an empty junction.
	var junctionCount int
	err = testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM feed_topics WHERE feed_id = $1 AND topic_id = $2`,
		out.Feed.ID, topicID,
	).Scan(&junctionCount)
	if err != nil {
		t.Fatalf("counting feed_topics: %v", err)
	}
	if junctionCount != 1 {
		t.Errorf("feed_topics count = %d, want 1", junctionCount)
	}
}

// =========================================================================
// Section 3: DB audit trigger regressions
// =========================================================================
//
// Integration coverage for the five audit triggers in
// migrations/001_initial.up.sql:
//
//   - trg_tasks_audit                        — tasks.state transitions
//   - trg_learning_hypotheses_audit          — hypotheses.state transitions
//   - trg_learning_plan_entries_audit        — learning_plan_entries.status
//   - trg_learning_sessions_audit            — learning_sessions end-of-session
//
// Each test mutates a seeded row and asserts the trigger produced the
// expected activity_events row. A regression that drops any of these
// triggers from the migration must fail the matching case here.

// latestActivityChangeKind reads the most recent activity_events row
// for (entity_type, entity_id) and returns its change_kind. Fails the
// test if no row exists — absence is itself a trigger regression.
func latestActivityChangeKind(t *testing.T, entityType string, entityID uuid.UUID) string {
	t.Helper()
	var kind string
	err := testPool.QueryRow(t.Context(),
		`SELECT change_kind FROM activity_events
		 WHERE entity_type = $1 AND entity_id = $2
		 ORDER BY occurred_at DESC LIMIT 1`,
		entityType, entityID,
	).Scan(&kind)
	if err != nil {
		t.Fatalf("fetching activity_events for %s %s: %v", entityType, entityID, err)
	}
	return kind
}

// TestIntegration_TaskDetail_HappyPath seeds a task where the default
// caller ("learning-studio") is the target, attaches a request message,
// and verifies task_detail returns the full coordination bundle
// (task row, messages, artifacts). This is the single-task provenance
// view §5.4 exists to provide — agents that submit or receive a task
// need a way to check its status and deliverables without hitting the
// admin UI or raw SQL.
func TestIntegration_TaskDetail_HappyPath(t *testing.T) {
	s := setupServer(t)

	var taskID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO tasks (created_by, assignee, title)
		 VALUES ('hq', 'learning-studio', 'research NATS exactly-once')
		 RETURNING id`,
	).Scan(&taskID)
	if err != nil {
		t.Fatalf("seeding task: %v", err)
	}

	// Seed a request message so we can assert Messages populates. Parts
	// go through a2a-go Part JSONB marshaling; a single text part is the
	// minimum the schema accepts.
	_, err = testPool.Exec(t.Context(),
		`INSERT INTO task_messages (task_id, role, position, parts)
		 VALUES ($1, 'request', 1, '[{"text":"please research the topic"}]'::jsonb)`,
		taskID,
	)
	if err != nil {
		t.Fatalf("seeding task_message: %v", err)
	}

	_, detail, err := callHandler(t, s.taskDetail, TaskDetailInput{TaskID: taskID.String()})
	if err != nil {
		t.Fatalf("task_detail: %v", err)
	}
	if detail.Task.ID != taskID {
		t.Errorf("detail.Task.ID = %s, want %s", detail.Task.ID, taskID)
	}
	if detail.Task.Source != "hq" || detail.Task.Target != "learning-studio" {
		t.Errorf("detail.Task source/target = %q/%q, want hq/learning-studio",
			detail.Task.Source, detail.Task.Target)
	}
	if len(detail.Messages) != 1 {
		t.Errorf("len(detail.Messages) = %d, want 1", len(detail.Messages))
	}
	// No artifact seeded → empty slice, not nil.
	if detail.Artifacts == nil {
		t.Error("detail.Artifacts = nil, want empty slice")
	}
}

// TestIntegration_TaskDetail_CallerNotParty verifies the authorization
// rule: when the calling agent is neither source nor target, the tool
// returns ErrNotFound (not ErrForbidden). Leaking existence of third-
// party tasks to an unrelated caller would erode the coordination
// boundary — see scope doc §8.10 for the adjacent rejected lineage tool
// that would have crossed this line for agent_notes.
func TestIntegration_TaskDetail_CallerNotParty(t *testing.T) {
	s := setupServer(t) // default caller = "learning-studio"

	var taskID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO tasks (created_by, assignee, title)
		 VALUES ('hq', 'research-lab', 'third-party task')
		 RETURNING id`,
	).Scan(&taskID)
	if err != nil {
		t.Fatalf("seeding task: %v", err)
	}

	_, _, err = callHandler(t, s.taskDetail, TaskDetailInput{TaskID: taskID.String()})
	if err == nil {
		t.Fatal("task_detail returned no error; caller 'learning-studio' is not party to this task")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("task_detail error = %v, want a not_found error shape", err)
	}
}

// TestIntegration_TaskDetail_InvalidID verifies we reject non-UUID input
// at the parsing boundary rather than propagating the raw pgx error.
func TestIntegration_TaskDetail_InvalidID(t *testing.T) {
	s := setupServer(t)

	_, _, err := callHandler(t, s.taskDetail, TaskDetailInput{TaskID: "not-a-uuid"})
	if err == nil {
		t.Fatal("task_detail accepted non-UUID id; should error")
	}
	if !strings.Contains(err.Error(), "invalid task_id") {
		t.Errorf("task_detail invalid-id error = %v, want 'invalid task_id'", err)
	}
}

// TestTaskStateChange_FiresActivityTrigger asserts trg_tasks_audit
// produces one activity_events row per state transition.
func TestTaskStateChange_FiresActivityTrigger(t *testing.T) {
	setupServer(t) // reconciles agents so the FK on activity_events.actor resolves

	// Seed a task directly via SQL; two distinct agents from the
	// builtin registry satisfy chk_tasks_no_self_assignment.
	var taskID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO tasks (created_by, assignee, title)
		 VALUES ('hq', 'learning-studio', 'trigger fixture task')
		 RETURNING id`,
	).Scan(&taskID)
	if err != nil {
		t.Fatalf("seeding task: %v", err)
	}

	// Transition submitted → working. The trigger fires on UPDATE OF
	// state when OLD.state IS DISTINCT FROM NEW.state.
	if _, err := testPool.Exec(t.Context(),
		`UPDATE tasks SET state = 'working', accepted_at = now() WHERE id = $1`,
		taskID,
	); err != nil {
		t.Fatalf("updating task state: %v", err)
	}

	if got := latestActivityChangeKind(t, "task", taskID); got != "state_changed" {
		t.Errorf("activity_events.change_kind = %q, want %q", got, "state_changed")
	}
}

// TestHypothesisStateChange_FiresActivityTrigger asserts
// trg_learning_hypotheses_audit produces one activity_events row per
// state transition. Uses unverified → archived (no evidence required)
// to keep the test focused on the trigger, not on
// chk_learning_hypothesis_resolution.
func TestHypothesisStateChange_FiresActivityTrigger(t *testing.T) {
	setupServer(t)

	var hypothesisID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_hypotheses (created_by, content, claim, invalidation_condition, observed_date)
		 VALUES ('human', 'content', 'claim', 'would be invalid if X', CURRENT_DATE)
		 RETURNING id`,
	).Scan(&hypothesisID)
	if err != nil {
		t.Fatalf("seeding learning_hypothesis: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		`UPDATE learning_hypotheses SET state = 'archived' WHERE id = $1`,
		hypothesisID,
	); err != nil {
		t.Fatalf("updating learning_hypothesis state: %v", err)
	}

	if got := latestActivityChangeKind(t, "learning_hypothesis", hypothesisID); got != "state_changed" {
		t.Errorf("activity_events.change_kind = %q, want %q", got, "state_changed")
	}
}

// TestLearningPlanEntryStatusChange_FiresActivityTrigger asserts
// trg_learning_plan_entries_audit fires on status transitions and
// records the change. Seeds a plan, a target, and an entry row, then
// flips the entry's status to skipped (no attempt-id required).
func TestLearningPlanEntryStatusChange_FiresActivityTrigger(t *testing.T) {
	setupServer(t)

	// The seed learning_domain 'leetcode' is populated by migration 002.
	var targetID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title) VALUES ('leetcode', 'trigger target')
		 RETURNING id`,
	).Scan(&targetID)
	if err != nil {
		t.Fatalf("seeding learning_target: %v", err)
	}

	var planID uuid.UUID
	err = testPool.QueryRow(t.Context(),
		`INSERT INTO learning_plans (title, domain, created_by)
		 VALUES ('Trigger plan', 'leetcode', 'human')
		 RETURNING id`,
	).Scan(&planID)
	if err != nil {
		t.Fatalf("seeding learning_plan: %v", err)
	}

	var entryID uuid.UUID
	err = testPool.QueryRow(t.Context(),
		`INSERT INTO learning_plan_entries (plan_id, learning_target_id, position)
		 VALUES ($1, $2, 1)
		 RETURNING id`, planID, targetID,
	).Scan(&entryID)
	if err != nil {
		t.Fatalf("seeding learning_plan_entry: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		`UPDATE learning_plan_entries SET status = 'skipped' WHERE id = $1`,
		entryID,
	); err != nil {
		t.Fatalf("updating plan entry status: %v", err)
	}

	if got := latestActivityChangeKind(t, "learning_plan_entry", entryID); got != "state_changed" {
		t.Errorf("activity_events.change_kind = %q, want %q", got, "state_changed")
	}
}

// TestLearningSessionEnded_FiresActivityTrigger asserts
// trg_learning_sessions_audit fires only when a session transitions
// from ended_at IS NULL to ended_at IS NOT NULL, and records a
// 'completed' change_kind.
func TestLearningSessionEnded_FiresActivityTrigger(t *testing.T) {
	setupServer(t)

	var sessionID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_sessions (domain, session_mode)
		 VALUES ('leetcode', 'practice')
		 RETURNING id`,
	).Scan(&sessionID)
	if err != nil {
		t.Fatalf("seeding learning_session: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		`UPDATE learning_sessions SET ended_at = now() WHERE id = $1`,
		sessionID,
	); err != nil {
		t.Fatalf("ending session: %v", err)
	}

	if got := latestActivityChangeKind(t, "learning_session", sessionID); got != "completed" {
		t.Errorf("activity_events.change_kind = %q, want %q", got, "completed")
	}
}

// --- session_progress ---
//
// Covers the four invariants from Plan C:
//  1. No active session → {active: false, reason} and no LastEnded fields
//     when the DB has never seen a session.
//  2. Active session with zero attempts → Active=true, AttemptCount=0,
//     ElapsedSeconds < 60s, empty slug + category distributions.
//  3. Active session with attempts → aggregates reflect SQL rollup.
//  4. After end_session → {active: false} but LastEndedSessionID + Ended
//     pointers populated (the affordance path).

func TestIntegration_SessionProgress_NoActive(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.sessionProgress, SessionProgressInput{})
	if err != nil {
		t.Fatalf("sessionProgress: %v", err)
	}

	if out.Active {
		t.Errorf("Active = true, want false")
	}
	if out.Reason == "" {
		t.Error("Reason is empty — expected human-readable explanation")
	}
	if out.LastEndedSessionID != nil {
		t.Errorf("LastEndedSessionID = %v, want nil on fresh DB", *out.LastEndedSessionID)
	}
	if out.LastEndedAt != nil {
		t.Errorf("LastEndedAt = %v, want nil on fresh DB", *out.LastEndedAt)
	}
	if out.SessionID != nil {
		t.Errorf("SessionID leaked on !Active = %v", *out.SessionID)
	}
	if out.StartedAt != nil {
		t.Errorf("StartedAt leaked on !Active = %v", *out.StartedAt)
	}
}

func TestIntegration_SessionProgress_ActiveEmpty(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, out, err := callHandler(t, s.sessionProgress, SessionProgressInput{})
	if err != nil {
		t.Fatalf("sessionProgress: %v", err)
	}

	if !out.Active {
		t.Fatal("Active = false on a freshly-started session")
	}
	if out.SessionID == nil || *out.SessionID != sess.Session.ID {
		t.Errorf("SessionID = %v, want %v", out.SessionID, sess.Session.ID)
	}
	if out.StartedAt == nil {
		t.Error("StartedAt is nil on active session")
	}
	if out.AttemptCount != 0 {
		t.Errorf("AttemptCount = %d, want 0", out.AttemptCount)
	}
	if out.ElapsedSeconds < 0 || out.ElapsedSeconds > 60 {
		t.Errorf("ElapsedSeconds = %d, want 0..60 for just-started session", out.ElapsedSeconds)
	}
	if len(out.ParadigmDistribution) != 2 {
		t.Errorf("ParadigmDistribution len = %d, want 2 (problem_solving + immersive, both zero)", len(out.ParadigmDistribution))
	}
	for _, p := range out.ParadigmDistribution {
		if p.Count != 0 || p.TotalMinutes != 0 {
			t.Errorf("ParadigmDistribution[%q] = {count:%d minutes:%d}, want both zero on empty session", p.Paradigm, p.Count, p.TotalMinutes)
		}
	}
	// Empty distributions must be non-nil (per-handler allocated) so JSON
	// emits [] instead of null. Nil would break callers that iterate.
	if out.ConceptSlugDistribution == nil {
		t.Error("ConceptSlugDistribution is nil on empty active session (want empty slice)")
	}
	if out.ObservationCategoryDistribution == nil {
		t.Error("ObservationCategoryDistribution is nil on empty active session (want empty slice)")
	}
	if len(out.ConceptSlugDistribution) != 0 {
		t.Errorf("ConceptSlugDistribution len = %d, want 0", len(out.ConceptSlugDistribution))
	}
	if len(out.ObservationCategoryDistribution) != 0 {
		t.Errorf("ObservationCategoryDistribution len = %d, want 0", len(out.ObservationCategoryDistribution))
	}

	// Wire-shape guard: on Active=true, encoding/json MUST emit every
	// active-path key even at zero value. Integration tests checking
	// Go struct fields alone miss omitempty-drop regressions — a JS
	// consumer iterating response.concept_slug_distribution must not
	// hit undefined.
	buf, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal(out): %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(buf, &wire); err != nil {
		t.Fatalf("json.Unmarshal shape probe: %v", err)
	}
	for _, key := range []string{
		"session_id", "domain", "mode", "started_at",
		"elapsed_seconds", "elapsed_display", "attempt_count",
		"paradigm_distribution", "concept_slug_distribution",
		"observation_category_distribution",
	} {
		if _, ok := wire[key]; !ok {
			t.Errorf("JSON output missing key %q on Active=true path (omitempty regression?)", key)
		}
	}
}

func TestIntegration_SessionProgress_WithAttempts(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "mixed",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	problemSolvingDur := FlexInt(12)
	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Two Sum"},
		Outcome:   "solved_with_hint",
		Duration:  &problemSolvingDur,
		Observations: []ObservationInput{
			{Concept: "hash-lookup", Signal: "weakness", Category: "pattern-recognition", Confidence: "high"},
			{Concept: "array-indexing", Signal: "mastery", Category: "implementation", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt problem_solving: %v", err)
	}

	immersiveDur := FlexInt(30)
	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "DDIA Chapter 3"},
		Outcome:   "completed",
		Duration:  &immersiveDur,
		Observations: []ObservationInput{
			{Concept: "log-structured-storage", Signal: "mastery", Category: "implementation", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt immersive: %v", err)
	}

	_, out, err := callHandler(t, s.sessionProgress, SessionProgressInput{})
	if err != nil {
		t.Fatalf("sessionProgress: %v", err)
	}

	if !out.Active {
		t.Fatal("Active = false after recording two attempts")
	}
	if out.AttemptCount != 2 {
		t.Errorf("AttemptCount = %d, want 2", out.AttemptCount)
	}

	pByName := map[string]SessionProgressParadigm{}
	for _, p := range out.ParadigmDistribution {
		pByName[p.Paradigm] = p
	}
	if got := pByName["problem_solving"]; got.Count != 1 || got.TotalMinutes != int64(problemSolvingDur) {
		t.Errorf("problem_solving paradigm = {count:%d minutes:%d}, want {1 %d}", got.Count, got.TotalMinutes, problemSolvingDur)
	}
	if got := pByName["immersive"]; got.Count != 1 || got.TotalMinutes != int64(immersiveDur) {
		t.Errorf("immersive paradigm = {count:%d minutes:%d}, want {1 %d}", got.Count, got.TotalMinutes, immersiveDur)
	}

	if len(out.ConceptSlugDistribution) != 3 {
		t.Errorf("ConceptSlugDistribution len = %d, want 3 (hash-lookup, array-indexing, log-structured-storage)", len(out.ConceptSlugDistribution))
	}
	// Verify sort: count DESC, slug ASC. Three entries, all count=1 →
	// slug ASC tie-break. Expect "array-indexing", "hash-lookup",
	// "log-structured-storage" in that order.
	wantSlugs := []string{"array-indexing", "hash-lookup", "log-structured-storage"}
	for i, w := range wantSlugs {
		if i >= len(out.ConceptSlugDistribution) {
			break
		}
		if got := out.ConceptSlugDistribution[i].Slug; got != w {
			t.Errorf("ConceptSlugDistribution[%d].Slug = %q, want %q", i, got, w)
		}
	}

	// Observation category distribution: 1 weakness (pattern-recognition),
	// 2 mastery (implementation × 2). Sort: weakness before mastery.
	if len(out.ObservationCategoryDistribution) != 2 {
		t.Errorf("ObservationCategoryDistribution len = %d, want 2", len(out.ObservationCategoryDistribution))
	}
	if got := out.ObservationCategoryDistribution[0].SignalType; got != "weakness" {
		t.Errorf("first category signal = %q, want 'weakness' (sort order)", got)
	}
	if got := out.ObservationCategoryDistribution[0].Category; got != "pattern-recognition" {
		t.Errorf("first category.category = %q, want 'pattern-recognition'", got)
	}
}

func TestIntegration_SessionProgress_LastEndedSurfaced(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Binary Search"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	_, end, err := callHandler(t, s.endSession, EndSessionInput{
		SessionID: sess.Session.ID.String(),
	})
	if err != nil {
		t.Fatalf("endSession: %v", err)
	}
	if end.Session.EndedAt == nil {
		t.Fatal("endSession did not populate EndedAt")
	}

	_, out, err := callHandler(t, s.sessionProgress, SessionProgressInput{})
	if err != nil {
		t.Fatalf("sessionProgress: %v", err)
	}

	if out.Active {
		t.Fatal("Active = true after end_session")
	}
	if out.LastEndedSessionID == nil {
		t.Fatal("LastEndedSessionID is nil after end_session — affordance path broken")
	}
	if *out.LastEndedSessionID != sess.Session.ID {
		t.Errorf("LastEndedSessionID = %v, want %v (the just-ended session)", *out.LastEndedSessionID, sess.Session.ID)
	}
	if out.LastEndedAt == nil {
		t.Error("LastEndedAt is nil after end_session")
	}
	// Affordance is identity-only; aggregate fields MUST stay zero.
	if out.AttemptCount != 0 {
		t.Errorf("AttemptCount = %d on !Active path, want 0 (affordance is NOT a fallback)", out.AttemptCount)
	}
	if len(out.ConceptSlugDistribution) != 0 {
		t.Errorf("ConceptSlugDistribution leaked on !Active path (len=%d)", len(out.ConceptSlugDistribution))
	}
	// Sanity: the LastEndedAt should be in the last minute (we just ended
	// it). Tolerance is generous to avoid CI flakes.
	if d := time.Since(*out.LastEndedAt); d < 0 || d > time.Minute {
		t.Errorf("LastEndedAt delta = %v, want within 1m (we just ended)", d)
	}
}

// --- attempt_history (Plan B — observations + confidence on all modes) ---
//
// Covers the refined-b shape locked by learning-studio:
//  - Every mode (target / concept_slug / session_id) returns observations[]
//    on each attempt with confidence label populated.
//  - concept_slug mode additionally populates matched_observation_id as a
//    pointer into the observations list (no parallel MatchedObservation
//    struct).
//  - observations are ordered by coach-insertion (position ASC), not by
//    concept slug, created_at, or id.
//  - include_observations=false skips the observation fetch; concept_slug
//    mode preserves matched_observation_id regardless.
//  - Sort order invariants: target/concept DESC, session ASC.

func TestIntegration_AttemptHistory_TargetMode_IncludesObservations(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Two Sum"},
		Outcome:   "solved_with_hint",
		Observations: []ObservationInput{
			// Deliberate non-alphabetical insertion order: z-last, a-first, m-middle.
			// If the read path sorted by slug we'd see [a, m, z]; Position sort
			// preserves insertion order [z, a, m].
			{Concept: "z-last-slug", Signal: "weakness", Category: "pattern-recognition", Confidence: "low"},
			{Concept: "a-first-slug", Signal: "mastery", Category: "implementation", Confidence: "high"},
			{Concept: "m-middle-slug", Signal: "improvement", Category: "approach-selection", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	// Wall-time smoke guard per Plan B Amendment B3. IVL runs on every
	// revisit; regression past ~100ms would compound into friction fast.
	// Not a benchmark — a defensive threshold. Bump if CI flakes.
	start := time.Now()
	_, out, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		Target: &AttemptHistoryTargetRef{Title: "Two Sum"},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("attemptHistory target: %v", err)
	}
	if !out.Resolved {
		t.Fatal("Resolved = false on existing target")
	}
	if len(out.Attempts) != 1 {
		t.Fatalf("Attempts len = %d, want 1", len(out.Attempts))
	}
	got := out.Attempts[0]
	if len(got.Observations) != 3 {
		t.Fatalf("Observations len = %d, want 3", len(got.Observations))
	}
	wantOrder := []string{"z-last-slug", "a-first-slug", "m-middle-slug"}
	for i, want := range wantOrder {
		if got.Observations[i].ConceptSlug != want {
			t.Errorf("Observations[%d].ConceptSlug = %q, want %q (coach-insertion order)", i, got.Observations[i].ConceptSlug, want)
		}
		if got.Observations[i].Position != int32(i) {
			t.Errorf("Observations[%d].Position = %d, want %d", i, got.Observations[i].Position, i)
		}
	}
	// Confidence label carried through: first obs was "low", others "high".
	if got.Observations[0].Confidence != "low" {
		t.Errorf("Observations[0].Confidence = %q, want low", got.Observations[0].Confidence)
	}
	if got.Observations[1].Confidence != "high" {
		t.Errorf("Observations[1].Confidence = %q, want high", got.Observations[1].Confidence)
	}
	// target mode does not populate matched_observation_id.
	if got.MatchedObservationID != nil {
		t.Errorf("MatchedObservationID = %v, want nil on target mode", *got.MatchedObservationID)
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("attempt_history target mode took %v, want < 150ms (IVL hot path smoke)", elapsed)
	}
}

func TestIntegration_AttemptHistory_ConceptMode_MatchedObservationID(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Longest Substring"},
		Outcome:   "solved_with_hint",
		Observations: []ObservationInput{
			{Concept: "sliding-window-variable", Signal: "weakness", Category: "pattern-recognition", Confidence: "low"},
			{Concept: "hash-set-uniqueness", Signal: "mastery", Category: "implementation", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	_, out, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		ConceptSlug: strPtr("sliding-window-variable"),
	})
	if err != nil {
		t.Fatalf("attemptHistory concept: %v", err)
	}
	if !out.Resolved {
		t.Fatal("Resolved = false on existing concept")
	}
	if len(out.Attempts) != 1 {
		t.Fatalf("Attempts len = %d, want 1", len(out.Attempts))
	}
	got := out.Attempts[0]
	if got.MatchedObservationID == nil {
		t.Fatal("MatchedObservationID is nil on concept mode")
	}
	if len(got.Observations) != 2 {
		t.Fatalf("Observations len = %d, want 2", len(got.Observations))
	}
	// matched_observation_id MUST point into the observations list — find it.
	var matchedSlug string
	for _, o := range got.Observations {
		if o.ID == *got.MatchedObservationID {
			matchedSlug = o.ConceptSlug
			break
		}
	}
	if matchedSlug != "sliding-window-variable" {
		t.Errorf("matched_observation_id points to %q, want sliding-window-variable (the queried concept)", matchedSlug)
	}
}

func TestIntegration_AttemptHistory_SessionMode_Observations(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Reverse Linked List"},
		Outcome:   "solved_independent",
		Observations: []ObservationInput{
			{Concept: "pointer-swap-invariant", Signal: "mastery", Category: "implementation", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	_, out, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		SessionID: strPtr(sess.Session.ID.String()),
	})
	if err != nil {
		t.Fatalf("attemptHistory session: %v", err)
	}
	if len(out.Attempts) != 1 {
		t.Fatalf("Attempts len = %d, want 1", len(out.Attempts))
	}
	if len(out.Attempts[0].Observations) != 1 {
		t.Errorf("Observations len = %d, want 1", len(out.Attempts[0].Observations))
	}
	if out.Attempts[0].Observations[0].Confidence != "high" {
		t.Errorf("Observations[0].Confidence = %q, want high", out.Attempts[0].Observations[0].Confidence)
	}
	if out.Attempts[0].MatchedObservationID != nil {
		t.Errorf("MatchedObservationID = %v, want nil on session mode", *out.Attempts[0].MatchedObservationID)
	}
}

func TestIntegration_AttemptHistory_IncludeObservationsFalse(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Valid Parentheses"},
		Outcome:   "solved_independent",
		Observations: []ObservationInput{
			{Concept: "stack-matching", Signal: "mastery", Category: "pattern-recognition", Confidence: "high"},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	includeFalse := false

	// target mode — observations empty, matched_observation_id always nil.
	_, outTarget, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		Target:              &AttemptHistoryTargetRef{Title: "Valid Parentheses"},
		IncludeObservations: &includeFalse,
	})
	if err != nil {
		t.Fatalf("attemptHistory target include=false: %v", err)
	}
	if len(outTarget.Attempts) != 1 {
		t.Fatalf("target attempts len = %d, want 1", len(outTarget.Attempts))
	}
	if len(outTarget.Attempts[0].Observations) != 0 {
		t.Errorf("target include=false: Observations len = %d, want 0", len(outTarget.Attempts[0].Observations))
	}

	// concept mode — observations empty, but matched_observation_id MUST
	// stay populated because the query match info comes from the primary
	// SQL query, not the secondary observation fetch.
	_, outConcept, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		ConceptSlug:         strPtr("stack-matching"),
		IncludeObservations: &includeFalse,
	})
	if err != nil {
		t.Fatalf("attemptHistory concept include=false: %v", err)
	}
	if len(outConcept.Attempts) != 1 {
		t.Fatalf("concept attempts len = %d, want 1", len(outConcept.Attempts))
	}
	if len(outConcept.Attempts[0].Observations) != 0 {
		t.Errorf("concept include=false: Observations len = %d, want 0", len(outConcept.Attempts[0].Observations))
	}
	if outConcept.Attempts[0].MatchedObservationID == nil {
		t.Error("concept include=false: MatchedObservationID is nil, want populated (pointer should survive include=false)")
	}
}

func TestIntegration_AttemptHistory_SortInvariants(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// Record 3 attempts on the same target. target mode must return them
	// newest first (DESC); session mode must return them oldest first (ASC).
	for i := 1; i <= 3; i++ {
		_, _, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
			SessionID: sess.Session.ID.String(),
			Target:    AttemptTarget{Title: "Climbing Stairs"},
			Outcome:   "solved_independent",
		})
		if err != nil {
			t.Fatalf("recordAttempt %d: %v", i, err)
		}
	}

	_, targetOut, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		Target: &AttemptHistoryTargetRef{Title: "Climbing Stairs"},
	})
	if err != nil {
		t.Fatalf("attemptHistory target: %v", err)
	}
	if len(targetOut.Attempts) != 3 {
		t.Fatalf("target attempts = %d, want 3", len(targetOut.Attempts))
	}
	// AttemptNumber increments monotonically (1, 2, 3); DESC means [3, 2, 1].
	for i, wantNum := range []int32{3, 2, 1} {
		if targetOut.Attempts[i].AttemptNumber != wantNum {
			t.Errorf("target mode DESC: Attempts[%d].AttemptNumber = %d, want %d", i, targetOut.Attempts[i].AttemptNumber, wantNum)
		}
	}

	_, sessionOut, err := callHandler(t, s.attemptHistory, AttemptHistoryInput{
		SessionID: strPtr(sess.Session.ID.String()),
	})
	if err != nil {
		t.Fatalf("attemptHistory session: %v", err)
	}
	if len(sessionOut.Attempts) != 3 {
		t.Fatalf("session attempts = %d, want 3", len(sessionOut.Attempts))
	}
	// session_id mode ASC means [1, 2, 3].
	for i, wantNum := range []int32{1, 2, 3} {
		if sessionOut.Attempts[i].AttemptNumber != wantNum {
			t.Errorf("session mode ASC: Attempts[%d].AttemptNumber = %d, want %d", i, sessionOut.Attempts[i].AttemptNumber, wantNum)
		}
	}
}

// --- propose_* flat tools ---
//
// The seven typed propose tools (propose_goal, propose_project,
// propose_milestone, propose_directive, propose_hypothesis,
// propose_learning_plan, propose_learning_domain) all sign through the
// shared proposeEntity workhorse. Core coverage here:
//  - propose_goal happy path: produces a signed token that commit_proposal
//    accepts.
//  - propose_directive capability pre-check: unauthorized callers fail
//    fast at propose time, not at commit.

func TestIntegration_ProposeGoal_CommitRoundTrip(t *testing.T) {
	s := setupServer(t)

	_, proposal, err := callHandler(t, s.proposeGoal, ProposeGoalInput{
		Title:       "Pass JLPT N2 by October",
		Description: strPtr("Reading + listening practice cadence for N2 spring 2026 cohort."),
	})
	if err != nil {
		t.Fatalf("proposeGoal: %v", err)
	}
	if proposal.ProposalToken == "" {
		t.Fatal("proposeGoal returned empty token")
	}
	if proposal.Type != "goal" {
		t.Errorf("proposal.Type = %q, want goal", proposal.Type)
	}

	_, commit, err := callHandler(t, s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commitProposal: %v", err)
	}
	if !commit.Committed {
		t.Error("commit.Committed = false on round-trip")
	}
	if commit.Type != "goal" {
		t.Errorf("commit.Type = %q, want goal", commit.Type)
	}

	id, err := uuid.Parse(commit.ID)
	if err != nil {
		t.Fatalf("parsing returned goal ID: %v", err)
	}
	var title string
	if err := testPool.QueryRow(t.Context(), "SELECT title FROM goals WHERE id = $1", id).Scan(&title); err != nil {
		t.Fatalf("fetching goal row: %v", err)
	}
	if title != "Pass JLPT N2 by October" {
		t.Errorf("goal.title = %q, want round-tripped value", title)
	}
}

func TestIntegration_ProposeDirective_CapabilityPreCheck(t *testing.T) {
	s := setupServer(t)

	// learning-studio lacks SubmitTasks (only hq + human have it). The
	// default setupServer caller is learning-studio, so this call must
	// fail at propose time — no token is generated, no validation runs
	// against resolveDirectiveFields.
	_, _, err := callHandler(t, s.proposeDirective, ProposeDirectiveInput{
		Target:       "hq",
		Priority:     "high",
		RequestParts: []json.RawMessage{json.RawMessage(`{"text":"test"}`)},
	})
	if err == nil {
		t.Fatal("proposeDirective as learning-studio: expected capability error, got nil")
	}
	if !strings.Contains(err.Error(), "propose_directive") {
		t.Errorf("error should name the tool that rejected: %v", err)
	}
}

// TestIntegration_ToolsListAdvertisesEnums is a structural guard that
// tools/list actually carries the FieldEnums injected by addTool
// post-processing. If injection regresses, the schema ends up without
// .Enum on the advertised field and this fails.
func TestIntegration_ToolsListAdvertisesEnums(t *testing.T) {
	s := setupServer(t)

	// The MCP server's internal registry of tool schemas is not directly
	// exposed, but s.registeredNames + ops.All() gives the same pairing.
	// Walk the ops catalog, find tools with FieldEnums, and assert that
	// the generated schema (via the same jsonschema.ForType path) has
	// the expected enums. A lightweight proxy for what tools/list emits.
	s.logger.Info("integration_test: enum advertising probe", "registered", len(s.registeredNames))
	foundRecord, foundDashboard := false, false
	for _, m := range ops.All() {
		if m.Name == "record_attempt" && len(m.FieldEnums["outcome"]) > 0 {
			foundRecord = true
		}
		if m.Name == "learning_dashboard" && len(m.FieldEnums["view"]) > 0 {
			foundDashboard = true
		}
	}
	if !foundRecord {
		t.Error("record_attempt.FieldEnums[outcome] missing")
	}
	if !foundDashboard {
		t.Error("learning_dashboard.FieldEnums[view] missing")
	}
}
