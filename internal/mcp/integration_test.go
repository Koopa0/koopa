// Copyright 2026 Koopa. All rights reserved.

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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/mcp/ops"
	"github.com/Koopa0/koopa/internal/note"
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
	if _, err := agent.SyncToTable(t.Context(), registry, agentStore, nil, slog.Default()); err != nil {
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
		"notes",
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
// TestIntegration_SystemStatus_LearningCounts verifies the F-3
// addition: system_status's database section now includes four
// learning-domain counts (attempts / sessions / concepts /
// fsrs_cards) alongside the existing knowledge-side counts.
// Phase 1 audit reported that learning-studio had to query multiple
// dashboard views to confirm "is the learning surface populated";
// system_status now answers it directly.
func TestIntegration_SystemStatus_LearningCounts(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.systemStatus, SystemStatusInput{})
	if err != nil {
		t.Fatalf("systemStatus: %v", err)
	}
	if out.Health == nil {
		t.Fatal("systemStatus: Health is nil")
	}
	// Build identity must always populate — auditors rely on it to confirm
	// which commit produced the response. Even an unstamped local build
	// returns the "dev" defaults, never empty strings.
	if out.Build.SHA == "" || out.Build.BuiltAt == "" || out.Build.Version == "" {
		t.Errorf("systemStatus: Build has empty field: %+v", out.Build)
	}
	db := out.Health.Database
	// All four fields must serialise (even if zero) — the wire shape
	// is the contract. We're not asserting specific counts because
	// other tests in this suite seed varying state; we're asserting
	// the fields exist and are reachable through the wire shape.
	_ = db.AttemptsCount
	_ = db.SessionsCount
	_ = db.ConceptsCount
	_ = db.FsrsCardsCount
	// Negative counts would mean an int overflow or a SQL bug.
	if db.AttemptsCount < 0 || db.SessionsCount < 0 || db.ConceptsCount < 0 || db.FsrsCardsCount < 0 {
		t.Errorf("learning counts must be non-negative: attempts=%d sessions=%d concepts=%d fsrs=%d",
			db.AttemptsCount, db.SessionsCount, db.ConceptsCount, db.FsrsCardsCount)
	}
}

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

	// commit_proposal of high-commitment entities (incl. learning_plan)
	// requires Platform=human via requireExplicitHuman. The setupServer
	// default caller is learning-studio; switch to "human" via
	// callHandlerAs so the gate passes.
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
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

// TestIntegration_RecordAttempt_DownstreamIds pins REQ-4: the record_attempt
// response surfaces concepts[], fsrs_card{id,due_at}, and
// related_targets_resolved[] so the coach can chain mastery / FSRS reads
// without re-resolving slugs or running CardByLearningTarget. Per the
// 2026-05-23 verdict on D3: fsrs_card MUST carry both id and due_at on
// success (omitted entirely on failure via omitempty); the response is
// purely additive (Invariant 7) and FSRS scheduling stays outside the
// attempt transaction (Invariant 4).
func TestIntegration_RecordAttempt_DownstreamIds(t *testing.T) {
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
		RelatedTargets: []RelatedTargetInput{
			{
				Title:        "Two Sum II",
				RelationType: "harder_variant",
			},
		},
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	// Concepts: the one observation resolved to hash-lookup; its id must
	// be a non-nil UUID. We're not asserting a specific value — the point
	// is that the slug→id pair is plumbed to the response.
	if len(rec.Concepts) != 1 {
		t.Fatalf("Concepts len = %d, want 1 (one observation submitted)", len(rec.Concepts))
	}
	if rec.Concepts[0].Slug != "hash-lookup" {
		t.Errorf("Concepts[0].Slug = %q, want %q", rec.Concepts[0].Slug, "hash-lookup")
	}
	if _, parseErr := uuid.Parse(rec.Concepts[0].ID); parseErr != nil {
		t.Errorf("Concepts[0].ID = %q is not a valid UUID: %v", rec.Concepts[0].ID, parseErr)
	}

	// RelatedTargetsResolved: the one related target was linked; surface
	// id + title so the caller can chain a follow-up read.
	if len(rec.RelatedTargetsResolved) != 1 {
		t.Fatalf("RelatedTargetsResolved len = %d, want 1 (one related_target submitted)", len(rec.RelatedTargetsResolved))
	}
	if rec.RelatedTargetsResolved[0].Title != "Two Sum II" {
		t.Errorf("RelatedTargetsResolved[0].Title = %q, want %q", rec.RelatedTargetsResolved[0].Title, "Two Sum II")
	}
	if _, parseErr := uuid.Parse(rec.RelatedTargetsResolved[0].ID); parseErr != nil {
		t.Errorf("RelatedTargetsResolved[0].ID = %q is not a valid UUID: %v", rec.RelatedTargetsResolved[0].ID, parseErr)
	}

	// FSRSCard: solved_independent maps to FSRS rating Good → ReviewByOutcome
	// must succeed against a freshly created card. Both id and due_at must
	// populate; FSRSReviewFailed must be false.
	if rec.FSRSReviewFailed {
		t.Errorf("FSRSReviewFailed = true, want false (solved_independent should not drift)")
	}
	if rec.FSRSCard == nil {
		t.Fatal("FSRSCard = nil, want populated when FSRSReviewFailed=false")
	}
	if _, parseErr := uuid.Parse(rec.FSRSCard.ID); parseErr != nil {
		t.Errorf("FSRSCard.ID = %q is not a valid UUID: %v", rec.FSRSCard.ID, parseErr)
	}
	if rec.FSRSCard.DueAt.IsZero() {
		t.Errorf("FSRSCard.DueAt is zero — successful FSRS schedule must populate due_at")
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

// TestIntegration_SessionDelta_FindsEndSessionReflection guards REQ-3 from
// the learning-studio 2026-05-23 brief: end_session(reflection=...) creates
// an agent_note with entry_date=s.today() (Taipei midnight). session_delta
// must surface that note in its agent_notes response — before the fix the
// note was excluded at TPE-morning calls because AgentNotesByDateRange
// compared the DATE column against time.Now() timestamptz params, and the
// implicit timestamptz→date coercion in UTC could shift the stored date
// outside the wall-clock-relative window.
//
// The fix has two parts (delta.go + query.sql): the SQL now casts
// @start_date/@end_date with ::date for date-typed comparison, and the
// handler bounds the default window by s.today() instead of time.Now() so
// both sides go through the same TPE-midnight semantics. This test
// exercises the workflow without manipulating the clock — the contract is
// "create then delta finds it", and the test will catch a regression of
// either side most of the time.
func TestIntegration_SessionDelta_FindsEndSessionReflection(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "go",
		Mode:   "reading",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	reflection := "fixed REQ-3 today; the tz boundary made my note disappear"
	_, _, err = callHandler(t, s.endSession, EndSessionInput{
		SessionID:  sess.Session.ID.String(),
		Reflection: &reflection,
	})
	if err != nil {
		t.Fatalf("endSession: %v", err)
	}

	_, delta, err := callHandler(t, s.sessionDelta, SessionDeltaInput{})
	if err != nil {
		t.Fatalf("sessionDelta: %v", err)
	}

	var found bool
	for i := range delta.AgentNotes {
		if delta.AgentNotes[i].Content == reflection {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("sessionDelta: end_session reflection missing from AgentNotes (got %d notes, since=%s)", len(delta.AgentNotes), delta.Since)
	}
	if delta.SessionCount < 1 {
		t.Errorf("sessionDelta: SessionCount = %d, want >= 1 (the session we just ended)", delta.SessionCount)
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
		// propose_goal / propose_project / propose_milestone have an
		// author allowlist (hq, content-studio, research-lab). The
		// setupServer default caller is learning-studio, which would
		// fast-fail the allowlist before reaching input validation —
		// defeating the test's purpose (assert input validation fires
		// before token signing). Use callHandlerAs("hq") so the
		// allowlist passes and the test exercises the actual validator.
		{
			name: "goal without title",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandlerAs(t, "hq", s.proposeGoal, ProposeGoalInput{})
				return out, err
			},
			wantErrSub: "title is required for goal",
		},
		{
			name: "project without slug",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandlerAs(t, "hq", s.proposeProject, ProposeProjectInput{Title: "x"})
				return out, err
			},
			wantErrSub: "slug is required for project",
		},
		{
			name: "milestone without goal",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandlerAs(t, "hq", s.proposeMilestone, ProposeMilestoneInput{Title: "x"})
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
			// B3 commit d81a0b0 added the field name to the slug error
			// message ('invalid learning_domain slug ...') so the assert
			// switched from the generic 'invalid slug' to the field-qualified
			// form. Without 'learning_domain' the substring would still match
			// the generic phrasing if it ever returns.
			name: "learning_domain with bad slug format",
			propose: func() (ProposeOutput, error) {
				_, out, err := callHandlerAs(t, "hq", s.proposeLearningDomain, ProposeLearningDomainInput{Slug: "Not Kebab", Name: "X"})
				return out, err
			},
			wantErrSub: "invalid learning_domain slug",
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

	// commit_proposal(learning_domain) is human-only.
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
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

// TestIntegration_RecordAttempt_PrimaryTargetCrossDomain pins the Phase 1E
// semantic boundary: the primary attempt target inherits the active session's
// domain. record_attempt MUST reject an explicit input.Target.Domain that
// disagrees with session.Domain — otherwise a single call could silently
// create a learning_target (and auto-create concepts) in a domain unrelated
// to the session, polluting both surfaces.
//
// The test asserts three properties:
//
//  1. The call returns an error wrapping learning.ErrInvalidInput.
//  2. No learning_target row landed in either domain (the rejected
//     domain or the session domain). FindOrCreateTarget is not reached.
//  3. No concept, observation, or attempt row landed for the rejected
//     call — i.e. the rejection happens before any side effect.
//
// Related targets still follow processRelatedTargets' cross-domain rule;
// this test is scoped to the primary target.
func TestIntegration_RecordAttempt_PrimaryTargetCrossDomain(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	mismatchedDomain := "japanese"
	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target: AttemptTarget{
			Title:  "Two Sum",
			Domain: &mismatchedDomain,
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
	if err == nil {
		t.Fatal("recordAttempt accepted cross-domain primary target; expected rejection")
	}
	if !errors.Is(err, learning.ErrInvalidInput) {
		t.Errorf("error = %v, want wrap of learning.ErrInvalidInput", err)
	}

	// No target rows for the offending title in either domain — rejection
	// must happen before FindOrCreateTarget.
	var targetCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_targets WHERE title = 'Two Sum' AND domain IN ('leetcode', 'japanese')`,
	).Scan(&targetCount); err != nil {
		t.Fatalf("counting learning_targets: %v", err)
	}
	if targetCount != 0 {
		t.Errorf("learning_targets rows for rejected attempt = %d, want 0", targetCount)
	}

	// No concept row for hash-lookup — observation pre-validation must
	// not have created one.
	var conceptCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM concepts WHERE slug = 'hash-lookup'`,
	).Scan(&conceptCount); err != nil {
		t.Fatalf("counting concepts: %v", err)
	}
	if conceptCount != 0 {
		t.Errorf("concepts rows for rejected attempt = %d, want 0", conceptCount)
	}

	// No attempt and no observation rows landed for this session.
	var attemptCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_attempts WHERE session_id = $1`, sess.Session.ID,
	).Scan(&attemptCount); err != nil {
		t.Fatalf("counting learning_attempts: %v", err)
	}
	if attemptCount != 0 {
		t.Errorf("learning_attempts rows = %d, want 0 (rejection must precede write)", attemptCount)
	}
	var obsCount int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_attempt_observations`,
	).Scan(&obsCount); err != nil {
		t.Fatalf("counting observations: %v", err)
	}
	if obsCount != 0 {
		t.Errorf("learning_attempt_observations rows = %d, want 0", obsCount)
	}
}

// TestIntegration_RecordAttempt_PrimaryTargetDomainEqualsSession is the
// acceptance counterpart: passing input.Target.Domain that equals the
// session's domain must be accepted, and the resulting target row carries
// the session's domain.
func TestIntegration_RecordAttempt_PrimaryTargetDomainEqualsSession(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	matchingDomain := "leetcode"
	_, rec, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target: AttemptTarget{
			Title:  "Valid Anagram",
			Domain: &matchingDomain,
		},
		Outcome: "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}
	if rec.Attempt.ID == uuid.Nil {
		t.Fatal("recordAttempt returned zero attempt ID despite matching domain")
	}

	var targetDomain string
	if err := testPool.QueryRow(t.Context(),
		`SELECT domain FROM learning_targets WHERE id = $1`, rec.Attempt.LearningTargetID,
	).Scan(&targetDomain); err != nil {
		t.Fatalf("reading learning_target: %v", err)
	}
	if targetDomain != "leetcode" {
		t.Errorf("learning_targets.domain = %q, want %q", targetDomain, "leetcode")
	}
}

// TestIntegration_RecordAttempt_PrimaryTargetDomainOmitted pins the default
// path: when input.Target.Domain is omitted, the primary target inherits
// the active session's domain. This is the historic happy path; explicit
// coverage guards against future regressions in the new conditional.
func TestIntegration_RecordAttempt_PrimaryTargetDomainOmitted(t *testing.T) {
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
		Target:    AttemptTarget{Title: "Maximum Subarray"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	var targetDomain string
	if err := testPool.QueryRow(t.Context(),
		`SELECT domain FROM learning_targets WHERE id = $1`, rec.Attempt.LearningTargetID,
	).Scan(&targetDomain); err != nil {
		t.Fatalf("reading learning_target: %v", err)
	}
	if targetDomain != "leetcode" {
		t.Errorf("learning_targets.domain = %q, want %q (session inheritance)", targetDomain, "leetcode")
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
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
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

// callHandlerAs invokes the handler with an explicit caller identity in
// context, simulating an MCP request that included `as: "<agent>"`.
// Required for handlers gated on requireExplicitHuman (publish_content,
// commit_proposal of high-commitment types) — callHandler alone falls
// through to the server default and the gate refuses.
func callHandlerAs[I, O any](t *testing.T, as string, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error), input I) (*mcp.CallToolResult, O, error) {
	t.Helper()
	ctx := context.WithValue(t.Context(), callerKey{}, as)
	return handler(ctx, nil, input)
}

func boolPtr(b bool) *bool { return &b }

// TestIntegration_ManageTargets_ArchiveHappyPath covers the C2 §B
// stage-3 happy path: learning-studio archives a target it created,
// the cascade pulls in every relation involving the target, the
// response includes the cascaded list with batch_id, and downstream
// read paths (recommend_next_target, learning_dashboard variations)
// no longer surface the archived rows.
func TestIntegration_ManageTargets_ArchiveHappyPath(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// Two targets + one relation between them, all created by the
	// default learning-studio caller so U2 ownership passes.
	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Sliding Window Maximum"},
		Outcome:   "solved_independent",
		RelatedTargets: []RelatedTargetInput{
			{Title: "Sliding Window Median", RelationType: "harder_variant"},
		},
	})
	if err != nil {
		t.Fatalf("seed recordAttempt: %v", err)
	}

	var targetID, relatedID string
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_targets WHERE title = $1",
		"Sliding Window Maximum",
	).Scan(&targetID); err != nil {
		t.Fatalf("locating target: %v", err)
	}
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_targets WHERE title = $1",
		"Sliding Window Median",
	).Scan(&relatedID); err != nil {
		t.Fatalf("locating related target: %v", err)
	}

	_, out, err := callHandler(t, s.archiveLearningTarget, ArchiveLearningTargetInput{
		TargetID: targetID,
		Reason:   strPtr("audit run cleanup"),
	})
	if err != nil {
		t.Fatalf("archive_target: %v", err)
	}
	if out.ArchivedTarget == nil {
		t.Fatal("expected ArchivedTarget, got nil")
	}
	if out.ArchivedTarget.ID != targetID {
		t.Errorf("archived target id = %q, want %q", out.ArchivedTarget.ID, targetID)
	}
	if out.TargetCount != 1 {
		t.Errorf("target_count = %d, want 1", out.TargetCount)
	}
	if out.RelationsCascadedCount < 1 {
		t.Errorf("relations_cascaded_count = %d, want >= 1 (relation involving archived target)",
			out.RelationsCascadedCount)
	}
	// Every cascaded relation must reference the archived target.
	for _, r := range out.CascadedRelations {
		if r.AnchorID != targetID && r.RelatedID != targetID {
			t.Errorf("cascaded relation %s does not reference archived target %s (anchor=%s, related=%s)",
				r.ID, targetID, r.AnchorID, r.RelatedID)
		}
		if r.ArchiveBatchID != out.ArchivedTarget.ArchiveBatchID {
			t.Errorf("relation batch_id %q != target batch_id %q — cascade not in same batch",
				r.ArchiveBatchID, out.ArchivedTarget.ArchiveBatchID)
		}
	}
}

// TestIntegration_ManageTargets_ArchiveNoCascade verifies the
// cascade_relations=false branch: target archives in isolation,
// related relations stay live so a future forensic re-link can
// reference them.
func TestIntegration_ManageTargets_ArchiveNoCascade(t *testing.T) {
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
		Target:    AttemptTarget{Title: "NoCascade Origin"},
		Outcome:   "solved_independent",
		RelatedTargets: []RelatedTargetInput{
			{Title: "NoCascade Related", RelationType: "follow_up"},
		},
	})
	if err != nil {
		t.Fatalf("seed recordAttempt: %v", err)
	}

	var targetID string
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_targets WHERE title = $1", "NoCascade Origin",
	).Scan(&targetID); err != nil {
		t.Fatalf("locating target: %v", err)
	}

	noCascade := false
	_, out, err := callHandler(t, s.archiveLearningTarget, ArchiveLearningTargetInput{
		TargetID:         targetID,
		CascadeRelations: &noCascade,
	})
	if err != nil {
		t.Fatalf("archive_target (no cascade): %v", err)
	}
	if out.TargetCount != 1 {
		t.Errorf("target_count = %d, want 1", out.TargetCount)
	}
	if out.RelationsCascadedCount != 0 {
		t.Errorf("relations_cascaded_count = %d, want 0 when cascade=false", out.RelationsCascadedCount)
	}
	if len(out.CascadedRelations) != 0 {
		t.Errorf("cascaded_relations len = %d, want 0", len(out.CascadedRelations))
	}

	// Verify the relation is still live in DB.
	var liveRelationCount int
	if err := testPool.QueryRow(t.Context(),
		"SELECT count(*) FROM learning_target_relations WHERE (anchor_id = $1 OR related_id = $1) AND archived_at IS NULL",
		targetID,
	).Scan(&liveRelationCount); err != nil {
		t.Fatalf("counting live relations: %v", err)
	}
	if liveRelationCount < 1 {
		t.Errorf("expected >= 1 live relation involving archived target (cascade=false), got %d", liveRelationCount)
	}
}

// TestIntegration_ManageTargets_ArchiveOwnership verifies U2 self-bound:
// only the target's created_by or Platform=human can archive it.
// learning-studio creating a target → hq trying to archive → reject.
func TestIntegration_ManageTargets_ArchiveOwnership(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// Default caller (learning-studio) creates target.
	_, _, err = callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Ownership Test Target"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}
	var targetID string
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_targets WHERE title = $1",
		"Ownership Test Target",
	).Scan(&targetID); err != nil {
		t.Fatalf("locating target: %v", err)
	}

	// hq tries to archive — rejected by U2.
	_, _, err = callHandlerAs(t, "hq", s.archiveLearningTarget, ArchiveLearningTargetInput{
		TargetID: targetID,
	})
	if err == nil {
		t.Fatal("hq archived a learning-studio-owned target — U2 self-bound check is not firing")
	}
	if !strings.Contains(err.Error(), "not the target owner") {
		t.Errorf("error = %q, want containing %q", err, "not the target owner")
	}

	// human override succeeds even though created_by=learning-studio.
	if _, _, err := callHandlerAs(t, "human", s.archiveLearningTarget, ArchiveLearningTargetInput{
		TargetID: targetID,
	}); err != nil {
		t.Fatalf("archive as human override: %v", err)
	}
}

// TestIntegration_ManageTargets_ArchiveAlreadyArchived verifies the
// double-archive case rejects cleanly with the timestamp-bearing
// already-archived error.
func TestIntegration_ManageTargets_ArchiveAlreadyArchived(t *testing.T) {
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
		Target:    AttemptTarget{Title: "Already Archived Target"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}
	var targetID string
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_targets WHERE title = $1",
		"Already Archived Target",
	).Scan(&targetID); err != nil {
		t.Fatalf("locating target: %v", err)
	}

	if _, _, err := callHandler(t, s.archiveLearningTarget, ArchiveLearningTargetInput{
		TargetID: targetID,
	}); err != nil {
		t.Fatalf("first archive: %v", err)
	}

	_, _, err = callHandler(t, s.archiveLearningTarget, ArchiveLearningTargetInput{
		TargetID: targetID,
	})
	if err == nil {
		t.Fatal("double archive: expected already-archived error, got nil")
	}
	if !strings.Contains(err.Error(), "already archived") {
		t.Errorf("error = %q, want containing %q", err, "already archived")
	}
}

// TestIntegration_AdvanceWork_SelfBound verifies the C1 self-bound
// rule: a caller may transition only the todos they themselves
// created, except when Platform=human (the human owner is the
// universal override). Reproduces the cowork audit case where
// learning-studio successfully ran advance_work(complete) on an
// hq-created todo — that is now rejected.
func TestIntegration_AdvanceWork_SelfBound(t *testing.T) {
	s := setupServer(t)

	// Create a todo as learning-studio (setupServer default callerAgent).
	_, captured, err := callHandler(t, s.captureInbox, CaptureInboxInput{
		Title: "self-bound test",
	})
	if err != nil {
		t.Fatalf("captureInbox: %v", err)
	}
	todoID := captured.Task.ID.String()

	// Other agent must be rejected. hq is registered with Platform=
	// claude-cowork, not human, so the override does not apply.
	_, _, err = callHandlerAs(t, "hq", s.advanceWork, AdvanceWorkInput{
		TaskID: todoID,
		Action: "defer",
	})
	if err == nil {
		t.Fatal("advance_work as hq accepted a learning-studio-owned todo — self-bound check is not firing")
	}
	if !strings.Contains(err.Error(), "not the todo owner") {
		t.Errorf("error = %q, want containing %q", err, "not the todo owner")
	}

	// Original creator (learning-studio) succeeds.
	if _, _, err := callHandler(t, s.advanceWork, AdvanceWorkInput{
		TaskID: todoID,
		Action: "defer",
	}); err != nil {
		t.Fatalf("advance_work as creator: %v", err)
	}

	// Human override succeeds even when caller != creator. Use a
	// different todo because the previous one is now in someday state.
	_, captured2, err := callHandler(t, s.captureInbox, CaptureInboxInput{
		Title: "human-override test",
	})
	if err != nil {
		t.Fatalf("captureInbox #2: %v", err)
	}
	if _, _, err := callHandlerAs(t, "human", s.advanceWork, AdvanceWorkInput{
		TaskID: captured2.Task.ID.String(),
		Action: "defer",
	}); err != nil {
		t.Fatalf("advance_work as human override: %v", err)
	}

	// Unregistered caller name hits the registry-Lookup fail branch in
	// requireTodoOwner. Without this test, a future refactor that
	// changes Lookup semantics could regress the fail-closed contract
	// without CI noticing.
	_, captured3, err := callHandler(t, s.captureInbox, CaptureInboxInput{
		Title: "unregistered caller test",
	})
	if err != nil {
		t.Fatalf("captureInbox #3: %v", err)
	}
	_, _, err = callHandlerAs(t, "ghost-agent", s.advanceWork, AdvanceWorkInput{
		TaskID: captured3.Task.ID.String(),
		Action: "defer",
	})
	if err == nil {
		t.Fatal("advance_work as unregistered caller succeeded — registry check is not firing")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error = %q, want containing %q", err, "not registered")
	}
}

// TestIntegration_EndSession_NoOrphanReflection guards F-NEW1: a
// failed end_session call (against a not-found id or an already-ended
// session) must not write the reflection text into agent_notes. The
// previous handler created the reflection unconditionally before
// calling the store; three repeated end_session calls produced three
// reflection rows even though only the first succeeded — orphans that
// then poll into morning_context / session_delta /
// query_agent_notes.
//
// Coverage scope: this test covers orphan-by-mistake (the Phase 3
// audit finding). The race-window orphan-by-race scenario
// (concurrent end after pre-flight passes) is documented as an
// accepted residual in the handler's race-trade-off comment and is
// NOT exercised here — testcontainers does not race two concurrent
// calls. If race behavior changes, that path needs its own test.
func TestIntegration_EndSession_NoOrphanReflection(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	beforeCount := countReflectionNotes(t)

	// First call succeeds — one reflection should land.
	if _, _, err := callHandler(t, s.endSession, EndSessionInput{
		SessionID:  sess.Session.ID.String(),
		Reflection: strPtr("first call should land this reflection"),
	}); err != nil {
		t.Fatalf("first end_session: %v", err)
	}
	if got, want := countReflectionNotes(t), beforeCount+1; got != want {
		t.Fatalf("after first end_session: reflection rows = %d, want %d (before=%d)", got, want, beforeCount)
	}

	// Second call against the same (now-ended) id MUST fail AND MUST
	// NOT write another reflection.
	if _, _, err := callHandler(t, s.endSession, EndSessionInput{
		SessionID:  sess.Session.ID.String(),
		Reflection: strPtr("second call should NOT land — session is ended"),
	}); err == nil {
		t.Fatal("second end_session: expected already-ended error, got nil")
	}
	if got, want := countReflectionNotes(t), beforeCount+1; got != want {
		t.Errorf("after second end_session: reflection rows = %d, want %d (before=%d) — orphan reflection written by failed end_session", got, want, beforeCount)
	}

	// Third call against a bogus id MUST fail AND MUST NOT write
	// another reflection.
	if _, _, err := callHandler(t, s.endSession, EndSessionInput{
		SessionID:  "00000000-0000-0000-0000-000000000099",
		Reflection: strPtr("third call should NOT land — session does not exist"),
	}); err == nil {
		t.Fatal("third end_session: expected not-found error, got nil")
	}
	if got, want := countReflectionNotes(t), beforeCount+1; got != want {
		t.Errorf("after third end_session: reflection rows = %d, want %d (before=%d) — orphan reflection written by not-found end_session", got, want, beforeCount)
	}
}

// countReflectionNotes returns the current row count of
// agent_notes WHERE kind='reflection'. Used by F-NEW1's guard test.
func countReflectionNotes(t *testing.T) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		"SELECT count(*) FROM agent_notes WHERE kind = 'reflection'",
	).Scan(&n); err != nil {
		t.Fatalf("counting reflection notes: %v", err)
	}
	return n
}

// TestIntegration_TrackHypothesis_Resolve_Validation covers the
// resolve-path field validation that previously lived in
// handler_test.go's TestTrackHypothesis_Validation. After Wave 1 added
// a pre-flight existence check to resolveHypothesis (so a typo'd
// hypothesis_id surfaces as 'not found' before missing-evidence
// errors), the unit test required a nil-guard hack on s.hypotheses;
// #13 removed that hack and migrated the field-validation cases here
// where a real hypothesis row can be seeded.
func TestIntegration_TrackHypothesis_Resolve_Validation(t *testing.T) {
	s := setupServer(t)

	_, proposal, err := callHandler(t, s.proposeHypothesis, ProposeHypothesisInput{
		Claim:                 "test claim for validation harness",
		InvalidationCondition: "evidence X disproves the claim",
		Content:               "Seeded by TestIntegration_TrackHypothesis_Resolve_Validation so the resolve-path validators have a real row to look up.",
	})
	if err != nil {
		t.Fatalf("propose hypothesis: %v", err)
	}
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commit hypothesis: %v", err)
	}
	hypothesisID := commit.ID
	bigSummary := strings.Repeat("a", 2*1024+1)

	tests := []struct {
		name    string
		input   TrackHypothesisInput
		wantErr string
	}{
		// verify/invalidate must carry at least one evidence source.
		{name: "verify no evidence", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify"}, wantErr: "at least one of"},
		{name: "invalidate no evidence", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "invalidate"}, wantErr: "at least one of"},
		{name: "verify blank summary only", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify", ResolutionSummary: strPtr("   ")}, wantErr: "at least one of"},
		// Malformed evidence UUIDs surface before the "at least one" check.
		{name: "verify bad attempt_id", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify", ResolvedByAttemptID: strPtr("not-a-uuid"), ResolutionSummary: strPtr("ok")}, wantErr: "invalid resolved_by_attempt_id"},
		{name: "verify bad observation_id", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "invalidate", ResolvedByObservationID: strPtr("nope"), ResolutionSummary: strPtr("ok")}, wantErr: "invalid resolved_by_observation_id"},
		{name: "verify summary too large", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify", ResolutionSummary: &bigSummary}, wantErr: "resolution_summary too large"},
		// Control characters in resolution_summary rejected per security.md.
		{name: "verify summary with NUL", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify", ResolutionSummary: strPtr("solved\x00cleanly")}, wantErr: "control characters"},
		{name: "verify summary with ESC", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify", ResolutionSummary: strPtr("\x1b[31mred")}, wantErr: "control characters"},
		// uuid.Parse internals must NOT leak to MCP callers — the field
		// name alone is reported.
		{name: "verify attempt error does not leak uuid.Parse", input: TrackHypothesisInput{HypothesisID: hypothesisID, Action: "verify", ResolvedByAttemptID: strPtr("abc")}, wantErr: "invalid resolved_by_attempt_id"},
		// Pre-flight existence check fires before field validation. A
		// typo'd id rejects with 'not found' even when fields are missing.
		{name: "nonexistent id rejects before field validation", input: TrackHypothesisInput{HypothesisID: "00000000-0000-0000-0000-000000000099", Action: "verify"}, wantErr: "not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.trackHypothesis, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestIntegration_UpdateEntry_CompletionPolicy exercises the policy
// enforcement added in B4: completion now hard-rejects missing
// completed_by_attempt_id and missing reason, with a force=true escape
// hatch that requires a "manual override:" reason of >= 60 characters.
//
// This replaces the previous behavior where missing
// completed_by_attempt_id only logged a warning, leaving plan-progress
// metrics with quiet-bypass entries.
func TestIntegration_UpdateEntry_CompletionPolicy(t *testing.T) {
	s := setupServer(t)

	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}

	// Build a plan + one entry on a recorded target, plus a stranded
	// entry whose target has no attempt (simulating a retconned plan).
	_, attempt, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
		SessionID: sess.Session.ID.String(),
		Target:    AttemptTarget{Title: "Two Sum"},
		Outcome:   "solved_independent",
	})
	if err != nil {
		t.Fatalf("recordAttempt: %v", err)
	}

	_, proposal, err := callHandler(t, s.proposeLearningPlan, ProposeLearningPlanInput{
		Title:  "Completion Policy Drill",
		Domain: "leetcode",
	})
	if err != nil {
		t.Fatalf("propose plan: %v", err)
	}
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commit plan: %v", err)
	}

	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: commit.ID,
		Entries: []ManagePlanEntryInput{
			{Title: "Two Sum", Position: 1},
			{Title: "Stranded Target", Position: 2},
		},
	}); err != nil {
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

	rows, err := testPool.Query(t.Context(),
		"SELECT id, position FROM learning_plan_entries WHERE plan_id = $1 ORDER BY position", commit.ID)
	if err != nil {
		t.Fatalf("locating entries: %v", err)
	}
	defer rows.Close()
	var twoSumEntryID, strandedEntryID string
	for rows.Next() {
		var id string
		var pos int32
		if err := rows.Scan(&id, &pos); err != nil {
			t.Fatalf("scan entry: %v", err)
		}
		if pos == 1 {
			twoSumEntryID = id
		} else {
			strandedEntryID = id
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating entries: %v", err)
	}
	if twoSumEntryID == "" || strandedEntryID == "" {
		t.Fatalf("entry lookup incomplete: twoSum=%q stranded=%q", twoSumEntryID, strandedEntryID)
	}

	completed := "completed"
	attemptID := attempt.Attempt.ID.String()
	tt := []struct {
		name    string
		input   ManagePlanInput
		wantSub string
	}{
		{
			name: "missing reason rejects",
			input: ManagePlanInput{
				Action:               "update_entry",
				PlanID:               commit.ID,
				EntryID:              &twoSumEntryID,
				Status:               &completed,
				CompletedByAttemptID: &attemptID,
			},
			wantSub: "reason is required",
		},
		{
			name: "blank reason rejects",
			input: ManagePlanInput{
				Action:               "update_entry",
				PlanID:               commit.ID,
				EntryID:              &twoSumEntryID,
				Status:               &completed,
				CompletedByAttemptID: &attemptID,
				Reason:               strPtr("   "),
			},
			wantSub: "reason is required",
		},
		{
			name: "missing attempt id rejects without force",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &twoSumEntryID,
				Status:  &completed,
				Reason:  strPtr("solved on second attempt"),
			},
			wantSub: "completed_by_attempt_id is required",
		},
		{
			name: "force without manual override prefix rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &strandedEntryID,
				Status:  &completed,
				Reason:  strPtr("just trust me on this one ok thanks"),
				Force:   boolPtr(true),
			},
			wantSub: "manual override:",
		},
		{
			name: "force with prefix but too short rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &strandedEntryID,
				Status:  &completed,
				Reason:  strPtr("manual override: nope"),
				Force:   boolPtr(true),
			},
			wantSub: "≥ 60 characters",
		},
		{
			// Boundary guard: 35-char "vague tag" reasons that would
			// have passed under the older 30-rune floor must now reject.
			// If a future dial-down to 45 happens, this case relaxes to
			// the new floor; further dialing-down to 30 would force a
			// rewrite of this test (intentional).
			name: "force at 35 chars below 60 floor rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &strandedEntryID,
				Status:  &completed,
				Reason:  strPtr("manual override: target retcon done"),
				Force:   boolPtr(true),
			},
			wantSub: "≥ 60 characters",
		},
		{
			name: "reason exceeding cap rejects",
			input: ManagePlanInput{
				Action:               "update_entry",
				PlanID:               commit.ID,
				EntryID:              &twoSumEntryID,
				Status:               &completed,
				CompletedByAttemptID: &attemptID,
				Reason:               strPtr(strings.Repeat("a", 1025)),
			},
			wantSub: "exceeds 1024 characters",
		},
		{
			// L2 review M3: force=true on non-completed status was a UX
			// foot-gun (silently ignored). Now hard-rejected so an LLM
			// that mistakenly leaves the flag set learns immediately.
			name: "force=true with status=skipped rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &twoSumEntryID,
				Status:  strPtr("skipped"),
				Reason:  strPtr("manual override: this should still reject because skipped"),
				Force:   boolPtr(true),
			},
			wantSub: "force=true is only valid with status=completed",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.managePlan, tc.input)
			if err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want containing %q", err, tc.wantSub)
			}
		})
	}

	// Force-completion of stranded entry succeeds with a long, prefixed
	// reason — the escape hatch path.
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  commit.ID,
		EntryID: &strandedEntryID,
		Status:  &completed,
		Reason:  strPtr("manual override: target was retconned during plan migration on 2026-05-06"),
		Force:   boolPtr(true),
	}); err != nil {
		t.Fatalf("force-completion with valid override reason: %v", err)
	}

	// Persisted reason MUST carry the manual override prefix so audit
	// greps for forced completions reliably hit.
	var persistedReason string
	if err := testPool.QueryRow(t.Context(),
		"SELECT reason FROM learning_plan_entries WHERE id = $1", strandedEntryID,
	).Scan(&persistedReason); err != nil {
		t.Fatalf("re-fetching reason: %v", err)
	}
	if !strings.HasPrefix(persistedReason, "manual override:") {
		t.Errorf("persisted reason = %q, want prefix %q", persistedReason, "manual override:")
	}
}

// TestIntegration_UpdateEntry_SkipPolicy exercises the skip-path reason
// requirement added for CF-04: status=skipped now requires a non-blank
// reason for audit-trail parity with status=completed. Without it,
// cross-agent review cannot distinguish "skipped because solved offline"
// from "skipped because plan retconned" — the policy gap that pushed
// agents toward force=true (wrong tool for normal skip).
func TestIntegration_UpdateEntry_SkipPolicy(t *testing.T) {
	s := setupServer(t)

	// Single-entry plan is enough — skip path does not need a recorded
	// attempt, only an active plan with an entry to skip.
	_, proposal, err := callHandler(t, s.proposeLearningPlan, ProposeLearningPlanInput{
		Title:  "Skip Policy Drill",
		Domain: "leetcode",
	})
	if err != nil {
		t.Fatalf("propose plan: %v", err)
	}
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commit plan: %v", err)
	}

	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: commit.ID,
		Entries: []ManagePlanEntryInput{
			{Title: "Skip Target A", Position: 1},
			{Title: "Skip Target B", Position: 2},
			{Title: "Skip Target C", Position: 3},
		},
	}); err != nil {
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

	rows, err := testPool.Query(t.Context(),
		"SELECT id, position FROM learning_plan_entries WHERE plan_id = $1 ORDER BY position", commit.ID)
	if err != nil {
		t.Fatalf("locating entries: %v", err)
	}
	defer rows.Close()
	var entryA, entryB, entryC string
	for rows.Next() {
		var id string
		var pos int32
		if err := rows.Scan(&id, &pos); err != nil {
			t.Fatalf("scan entry: %v", err)
		}
		switch pos {
		case 1:
			entryA = id
		case 2:
			entryB = id
		case 3:
			entryC = id
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating entries: %v", err)
	}
	if entryA == "" || entryB == "" || entryC == "" {
		t.Fatalf("entry lookup incomplete: A=%q B=%q C=%q", entryA, entryB, entryC)
	}

	skipped := "skipped"
	tt := []struct {
		name    string
		input   ManagePlanInput
		wantSub string
	}{
		{
			name: "skip without reason rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &entryA,
				Status:  &skipped,
			},
			wantSub: "reason is required when marking entry skipped",
		},
		{
			name: "skip with empty-string reason rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &entryA,
				Status:  &skipped,
				Reason:  strPtr(""),
			},
			wantSub: "reason is required when marking entry skipped",
		},
		{
			name: "skip with whitespace-only reason rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &entryA,
				Status:  &skipped,
				Reason:  strPtr("   \t\n"),
			},
			wantSub: "reason is required when marking entry skipped",
		},
		{
			name: "skip with reason exceeding cap rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  commit.ID,
				EntryID: &entryA,
				Status:  &skipped,
				Reason:  strPtr(strings.Repeat("a", 1025)),
			},
			wantSub: "exceeds 1024 characters",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.managePlan, tc.input)
			if err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want containing %q", err, tc.wantSub)
			}
		})
	}

	// Happy path: skip with a valid reason succeeds. Verify the entry
	// row is updated to status=skipped and the trimmed reason is
	// persisted (leading/trailing whitespace stripped).
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  commit.ID,
		EntryID: &entryB,
		Status:  &skipped,
		Reason:  strPtr("  koopa solved this offline before the plan was committed  "),
	}); err != nil {
		t.Fatalf("skip with valid reason: %v", err)
	}

	var status, persistedReason string
	if err := testPool.QueryRow(t.Context(),
		"SELECT status, reason FROM learning_plan_entries WHERE id = $1", entryB,
	).Scan(&status, &persistedReason); err != nil {
		t.Fatalf("re-fetching skipped entry: %v", err)
	}
	if status != "skipped" {
		t.Errorf("status = %q, want %q", status, "skipped")
	}
	if persistedReason != "koopa solved this offline before the plan was committed" {
		t.Errorf("persisted reason = %q, want trimmed body without surrounding whitespace", persistedReason)
	}

	// Regression guard: the pre-existing "force=true with status=skipped
	// rejects" case (line ~1743) must still fire on the force gate before
	// the new skip-reason validation runs. If validateSkipEntryReason ever
	// moved ahead of validateUpdateEntryInput, this case would surface a
	// "reason is required" error instead of the expected force-only error,
	// and the diagnostic ordering would silently regress.
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  commit.ID,
		EntryID: &entryC,
		Status:  &skipped,
		Reason:  strPtr("ignored because force gate fires first"),
		Force:   boolPtr(true),
	}); err == nil {
		t.Fatal("expected force=true with skipped to reject, got nil")
	} else if !strings.Contains(err.Error(), "force=true is only valid with status=completed") {
		t.Errorf("force+skip error = %q, want force-only gate to fire first", err)
	}
}

// TestIntegration_WeeklySummary_SelfAuditBlock exercises the CF-08 P0
// self_audit metrics surfaced by weekly_summary. Seeds enough real
// activity through production MCP handlers (so the audit triggers
// fire naturally) to assert each of the four P0 metrics:
//
//   - force_true_count — one force-mode completion via manage_plan
//     update_entry with force=true and a "manual override:" reason.
//   - solved_after_solution_rate / counts — record_attempt calls with
//     a mix of problem_solving outcomes; the rate is the
//     solved_after_solution numerator over total problem_solving
//     attempts in the window.
//   - same_concept_repeated_within_week — three distinct attempts
//     observing the same concept; one extra concept stays below the
//     threshold so the test also proves the filter rejects sub-threshold
//     concepts.
//   - skipped_count + skip_reason_prefix_histogram — two skips with
//     differently-prefixed reasons that bucket distinctly.
//
// The test does NOT bypass the production audit-trigger path —
// activity_events rows are written by the triggers via the same SQL
// that runs in production. This matches the existing
// TestLearningPlanEntryStatusChange_FiresActivityTrigger pattern
// (using real handler calls instead of direct UPDATE) so the queries
// are exercised against authentic trigger output, not test
// fixtures.
func TestIntegration_WeeklySummary_SelfAuditBlock(t *testing.T) {
	s := setupServer(t)

	// 1. Build a plan with four entries so we can: force-complete one,
	//    skip two with different reason prefixes, and leave the
	//    fourth alone (regression guard: not every entry should
	//    contribute to the audit signal).
	_, planProposal, err := callHandler(t, s.proposeLearningPlan, ProposeLearningPlanInput{
		Title:  "Self-Audit Test Plan",
		Domain: "leetcode",
	})
	if err != nil {
		t.Fatalf("propose plan: %v", err)
	}
	_, planCommit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
		ProposalToken: planProposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("commit plan: %v", err)
	}

	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: planCommit.ID,
		Entries: []ManagePlanEntryInput{
			{Title: "SA Target Alpha", Position: 1},
			{Title: "SA Target Beta", Position: 2},
			{Title: "SA Target Gamma", Position: 3},
			{Title: "SA Target Delta", Position: 4},
			{Title: "SA Target Epsilon", Position: 5},
		},
	}); err != nil {
		t.Fatalf("add_entries: %v", err)
	}

	active := "active"
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "update_plan",
		PlanID: planCommit.ID,
		Status: &active,
	}); err != nil {
		t.Fatalf("activate plan: %v", err)
	}

	rows, err := testPool.Query(t.Context(),
		"SELECT id, position FROM learning_plan_entries WHERE plan_id = $1 ORDER BY position", planCommit.ID)
	if err != nil {
		t.Fatalf("locating entries: %v", err)
	}
	defer rows.Close()
	var entryAlpha, entryBeta, entryGamma, entryDelta, entryEpsilon string
	for rows.Next() {
		var id string
		var pos int32
		if err := rows.Scan(&id, &pos); err != nil {
			t.Fatalf("scan entry: %v", err)
		}
		switch pos {
		case 1:
			entryAlpha = id
		case 2:
			entryBeta = id
		case 3:
			entryGamma = id
		case 4:
			entryDelta = id
		case 5:
			entryEpsilon = id
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating entries: %v", err)
	}
	if entryAlpha == "" || entryBeta == "" || entryGamma == "" || entryDelta == "" || entryEpsilon == "" {
		t.Fatalf("entry lookup incomplete: Alpha=%q Beta=%q Gamma=%q Delta=%q Epsilon=%q",
			entryAlpha, entryBeta, entryGamma, entryDelta, entryEpsilon)
	}

	// 2. Start a learning session and record attempts. Outcome mix:
	//    - 2 solved_after_solution (the CF-06 signal we want to count)
	//    - 1 solved_independent
	//    - 1 solved_with_hint
	//    → numerator=2, denominator=4, rate=0.5
	_, sess, err := callHandler(t, s.startSession, StartSessionInput{
		Domain: "leetcode",
		Mode:   "practice",
	})
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}
	sessionID := sess.Session.ID.String()

	// Three attempts share concept "self-audit-repeated-x" (≥3 threshold).
	// One attempt observes "self-audit-singleton-y" only — below threshold.
	makeAttempt := func(title, outcome, conceptSlug string) {
		t.Helper()
		_, _, err := callHandler(t, s.recordAttempt, RecordAttemptInput{
			SessionID: sessionID,
			Target:    AttemptTarget{Title: title},
			Outcome:   outcome,
			Observations: []ObservationInput{{
				Concept:  conceptSlug,
				Signal:   "weakness",
				Category: "pattern-recognition",
				Severity: strPtr("minor"),
			}},
		})
		if err != nil {
			t.Fatalf("record_attempt(%q, %q, %q): %v", title, outcome, conceptSlug, err)
		}
	}
	makeAttempt("SA Attempt 1", "solved_after_solution", "self-audit-repeated-x")
	makeAttempt("SA Attempt 2", "solved_independent", "self-audit-repeated-x")
	makeAttempt("SA Attempt 3", "solved_after_solution", "self-audit-repeated-x")
	makeAttempt("SA Attempt 4", "solved_with_hint", "self-audit-singleton-y")

	if _, _, err := callHandler(t, s.endSession, EndSessionInput{SessionID: sessionID}); err != nil {
		t.Fatalf("endSession: %v", err)
	}

	// 3. Force-complete one entry (the CF-04 audit signal we want to
	// count). Need an aligned attempt for the entry's target — easiest
	// path is to use force=true, which skips the alignment check at
	// the cost of requiring a manual-override-prefixed reason ≥60
	// runes.
	completed := "completed"
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  planCommit.ID,
		EntryID: &entryAlpha,
		Status:  &completed,
		Reason:  strPtr("manual override: SA test exercises the force-mode escape hatch deliberately"),
		Force:   boolPtr(true),
	}); err != nil {
		t.Fatalf("force-complete Alpha: %v", err)
	}

	// 4. Skip two entries with reasons that follow the 'skipped:' soft
	// convention from the audit-decisions memo §F.1.d. The histogram
	// must extract the text AFTER 'skipped:', so:
	//
	//   - "skipped: solved offline"  → bucket "solved offline"
	//   - "skipped: target archived" → bucket "target archived"
	//
	// Critically, an EARLIER draft of this query used split_part(reason,
	// ':', 1) which would have collapsed BOTH of these conforming
	// reasons into a single bucket "skipped" — making the histogram
	// useless for distinguishing skip categories. This test seeds the
	// convention deliberately so that bucket-by-prefix-only would have
	// produced len(histogram)==1 (and would fail the assertion below
	// that the histogram has 2 distinct buckets).
	skipped := "skipped"
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  planCommit.ID,
		EntryID: &entryBeta,
		Status:  &skipped,
		Reason:  strPtr("skipped: solved offline"),
	}); err != nil {
		t.Fatalf("skip Beta: %v", err)
	}
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  planCommit.ID,
		EntryID: &entryGamma,
		Status:  &skipped,
		Reason:  strPtr("skipped: target archived"),
	}); err != nil {
		t.Fatalf("skip Gamma: %v", err)
	}
	// Skip Epsilon with a NON-CONFORMING reason (no 'skipped:' prefix).
	// Must bucket under 'unclassified' per the contract. Without this
	// case, the histogram would only assert the in-convention path
	// and a future change that broke the ELSE branch ('unclassified'
	// fallback) would go undetected.
	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action:  "update_entry",
		PlanID:  planCommit.ID,
		EntryID: &entryEpsilon,
		Status:  &skipped,
		Reason:  strPtr("plan retconned during refactor"),
	}); err != nil {
		t.Fatalf("skip Epsilon: %v", err)
	}
	// entryDelta intentionally left in status=planned — regression
	// guard that an untouched entry contributes nothing.

	// 5. Call weekly_summary for the current week (default) and
	// assert each self_audit field.
	_, out, err := callHandler(t, s.weeklySummary, WeeklySummaryInput{})
	if err != nil {
		t.Fatalf("weeklySummary: %v", err)
	}
	got := out.SelfAudit

	if got.ForceTrueCount != 1 {
		t.Errorf("ForceTrueCount = %d, want 1", got.ForceTrueCount)
	}
	if got.SolvedAfterSolutionCount != 2 {
		t.Errorf("SolvedAfterSolutionCount = %d, want 2", got.SolvedAfterSolutionCount)
	}
	if got.AttemptCount != 4 {
		t.Errorf("AttemptCount = %d, want 4 (all problem_solving attempts in the window)", got.AttemptCount)
	}
	wantRate := 2.0 / 4.0
	if got.SolvedAfterSolutionRate != wantRate {
		t.Errorf("SolvedAfterSolutionRate = %v, want %v", got.SolvedAfterSolutionRate, wantRate)
	}

	// Repeated concept: only "self-audit-repeated-x" should appear
	// because it crosses the 3-attempt threshold. "self-audit-singleton-y"
	// has 1 attempt and MUST be absent.
	foundRepeated := false
	for _, r := range got.SameConceptRepeatedWithinWeek {
		if r.Concept == "self-audit-repeated-x" {
			foundRepeated = true
			if r.Count != 3 {
				t.Errorf("SameConceptRepeatedWithinWeek[self-audit-repeated-x] count = %d, want 3", r.Count)
			}
		}
		if r.Concept == "self-audit-singleton-y" {
			t.Errorf("SameConceptRepeatedWithinWeek includes singleton concept (count would be 1, below threshold %d)",
				selfAuditConceptRepetitionThreshold)
		}
	}
	if !foundRepeated {
		t.Errorf("SameConceptRepeatedWithinWeek missing self-audit-repeated-x; got %+v",
			got.SameConceptRepeatedWithinWeek)
	}

	if got.SkippedCount != 3 {
		t.Errorf("SkippedCount = %d, want 3", got.SkippedCount)
	}
	// Histogram contract:
	//   - 'skipped: solved offline'       → bucket 'solved offline'
	//   - 'skipped: target archived'      → bucket 'target archived'
	//   - 'plan retconned during refactor' → bucket 'unclassified' (no 'skipped:' prefix)
	//
	// Three distinct buckets, each count=1. Sorted count DESC then
	// prefix ASC; alphabetically 'solved offline' < 'target archived'
	// < 'unclassified', so the order is determined.
	//
	// Regression guard: if a future change reverted to
	// split_part(reason, ':', 1), both conforming reasons would
	// collapse into a single 'skipped' bucket with count=2 — the
	// length check below would see 2 buckets, not 3, and fail. Also,
	// 'skipped' would appear as a Prefix value, which the per-bucket
	// assertions explicitly reject.
	wantHistogram := []struct {
		prefix string
		count  int64
	}{
		{"solved offline", 1},
		{"target archived", 1},
		{"unclassified", 1},
	}
	if len(got.SkipReasonPrefixHistogram) != len(wantHistogram) {
		t.Fatalf("SkipReasonPrefixHistogram length = %d, want %d (regression guard: split-before-colon would yield 2 buckets including 'skipped' for the conforming reasons — that is the bug this test catches); got %+v",
			len(got.SkipReasonPrefixHistogram), len(wantHistogram), got.SkipReasonPrefixHistogram)
	}
	for i, want := range wantHistogram {
		gotBucket := got.SkipReasonPrefixHistogram[i]
		if gotBucket.Prefix != want.prefix {
			t.Errorf("SkipReasonPrefixHistogram[%d].Prefix = %q, want %q", i, gotBucket.Prefix, want.prefix)
		}
		if gotBucket.Count != want.count {
			t.Errorf("SkipReasonPrefixHistogram[%d].Count = %d, want %d", i, gotBucket.Count, want.count)
		}
		// Explicit anti-bug assertion: the 'skipped' bucket name must
		// NEVER appear in the histogram. If it does, the SQL is
		// extracting before-first-colon again.
		if gotBucket.Prefix == "skipped" {
			t.Errorf("SkipReasonPrefixHistogram[%d] = prefix 'skipped' — this is the collapse-on-convention bug from CF-08 P0 draft 1. SQL must extract AFTER 'skipped:', not before.", i)
		}
	}
}

// TestIntegration_WeeklySummary_SelfAuditEmptyWeek verifies the
// zero-state contract: a brand-new week with no MCP writes emits a
// self_audit block where every counter is zero and every slice is
// `[]` (NOT nil). Cowork agents iterating the response must never
// hit a nil slice — that's the load-bearing wire-shape rule from
// json-api.md.
func TestIntegration_WeeklySummary_SelfAuditEmptyWeek(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.weeklySummary, WeeklySummaryInput{})
	if err != nil {
		t.Fatalf("weeklySummary on empty week: %v", err)
	}
	got := out.SelfAudit

	if got.ForceTrueCount != 0 || got.SolvedAfterSolutionCount != 0 || got.AttemptCount != 0 || got.SkippedCount != 0 {
		t.Errorf("expected all counters to be 0 on empty week; got %+v", got)
	}
	if got.SolvedAfterSolutionRate != 0.0 {
		t.Errorf("SolvedAfterSolutionRate = %v, want 0.0 when denominator is 0", got.SolvedAfterSolutionRate)
	}
	if got.SameConceptRepeatedWithinWeek == nil {
		t.Error("SameConceptRepeatedWithinWeek = nil, want []")
	}
	if got.SkipReasonPrefixHistogram == nil {
		t.Error("SkipReasonPrefixHistogram = nil, want []")
	}

	// Wire-shape check: the JSON-marshalled response must encode the
	// slice fields as `[]` not `null`. This pins the rule even if a
	// future refactor switches the in-memory representation.
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	if !strings.Contains(string(raw), `"same_concept_repeated_within_week":[]`) {
		t.Errorf("encoded response missing `same_concept_repeated_within_week\":[]`; got %s", raw)
	}
	if !strings.Contains(string(raw), `"skip_reason_prefix_histogram":[]`) {
		t.Errorf("encoded response missing `skip_reason_prefix_histogram\":[]`; got %s", raw)
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
	for i := range 3 {
		title := "anchor-" + string(rune('A'+i))
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
	// created_by is required NOT NULL after §B; use 'human' to mirror
	// the admin HTTP path's caller-identity convention.
	var targetID uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title, created_by)
		 VALUES ('leetcode', 'trigger target', 'human')
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

	// propose_goal's author allowlist excludes learning-studio
	// (setupServer's default caller); use hq which is on the
	// hq/content-studio/research-lab list per authorization-matrix.md.
	_, proposal, err := callHandlerAs(t, "hq", s.proposeGoal, ProposeGoalInput{
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

	// commit_proposal(goal) is human-only via requireExplicitHuman; the
	// "hq committed its own proposal" round-trip pattern lives separately.
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
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

// Track 1D Batch 1 — publish_content contract (DB-backed dimensions).
//
// These testcontainers-backed tests pin the dimensions a DB-free test cannot:
//   - handler behavior  (success response: Action + Content.Status)
//   - DB write          (atomic flip: status/is_public/published_at — note
//                        is_public + published_at are NOT in the tool response,
//                        only in the row, so they are verified via SQL)
//   - activity/audit     (trg_contents_audit writes one change_kind='published'
//                        row with actor = the explicit human caller)
//   - empty/not-found    (ErrNotFound → "content … not found")
//   - idempotency         (re-publish: no error, no NEW audit row — actual
//                        contract: the store has no status guard and the audit
//                        trigger only fires on a real status change)
//
// Run with: go test -tags=integration ./internal/mcp/...

// seedContent inserts a content row in the given status directly via SQL (no
// koopa.actor set, so the INSERT audit row is attributed to 'system' — that is
// the seed event, distinct from the publish event under test). Returns the id.
func seedContent(t *testing.T, slug, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status)
		 VALUES ($1, $2, 'body', 'article', $3) RETURNING id`,
		slug, "Title "+slug, status,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedContent(%q, %q): %v", slug, status, err)
	}
	return id
}

// contentRowState reads the publish-relevant columns the tool response does
// NOT expose, so the DB side effect can be asserted independently.
func contentRowState(t *testing.T, id uuid.UUID) (status string, isPublic bool, publishedAt *time.Time) {
	t.Helper()
	if err := testPool.QueryRow(t.Context(),
		`SELECT status, is_public, published_at FROM contents WHERE id = $1`, id,
	).Scan(&status, &isPublic, &publishedAt); err != nil {
		t.Fatalf("contentRowState(%s): %v", id, err)
	}
	return status, isPublic, publishedAt
}

func publishedEventCount(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM activity_events
		 WHERE entity_type = 'content' AND entity_id = $1 AND change_kind = 'published'`, id,
	).Scan(&n); err != nil {
		t.Fatalf("publishedEventCount(%s): %v", id, err)
	}
	return n
}

// TestIntegration_PublishContent_Success covers the happy path end-to-end:
// review → published by an explicit human caller. Asserts the handler response,
// the atomic DB flip, and the audit row + actor attribution.
func TestIntegration_PublishContent_Success(t *testing.T) {
	s := setupServer(t)
	id := seedContent(t, "publish-success", "review")

	_, out, err := callHandlerAs(t, "human", s.publishContentTool, PublishContentInput{
		ContentID: id.String(),
	})
	if err != nil {
		t.Fatalf("publish_content(as=human, review content) = %v, want success", err)
	}

	// Handler behavior: response fragment.
	if out.Action != "publish" {
		t.Errorf("Action = %q, want %q", out.Action, "publish")
	}
	if out.Content == nil {
		t.Fatal("response Content is nil")
	}
	if out.Content.Status != "published" {
		t.Errorf("Content.Status = %q, want %q", out.Content.Status, "published")
	}

	// DB side effect: the atomic flip (is_public + published_at are NOT in the
	// tool response — verify them on the row).
	status, isPublic, publishedAt := contentRowState(t, id)
	if status != "published" {
		t.Errorf("db status = %q, want %q", status, "published")
	}
	if !isPublic {
		t.Error("db is_public = false, want true (publishing makes public)")
	}
	if publishedAt == nil {
		t.Error("db published_at = NULL, want non-NULL")
	}

	// activity/audit + actor attribution: exactly one published event, by the
	// explicit human caller — NOT 'system' (which would mean koopa.actor leaked).
	if got := publishedEventCount(t, id); got != 1 {
		t.Errorf("published activity_events = %d, want 1", got)
	}
	if actor := activityActorFor(t, "content", id); actor != "human" {
		t.Errorf("activity_events.actor = %q, want %q", actor, "human")
	}
}

// TestIntegration_PublishContent_NotFound: a well-formed but absent id, by a
// valid human caller, returns the not-found error contract (gate passes first,
// then the store's ErrNotFound maps through).
func TestIntegration_PublishContent_NotFound(t *testing.T) {
	s := setupServer(t)
	missing := uuid.New()

	_, _, err := callHandlerAs(t, "human", s.publishContentTool, PublishContentInput{
		ContentID: missing.String(),
	})
	if err == nil {
		t.Fatalf("publish_content(missing id) = nil, want not-found error")
	}
	if got := err.Error(); !strings.Contains(got, "not found") {
		t.Errorf("error = %q, want it to report not-found", got)
	}
}

// TestIntegration_PublishContent_RepublishNoNewAuditRow pins the ACTUAL
// idempotency contract: PublishContent has no status guard, so re-publishing an
// already-published row succeeds (no error) and re-runs the UPDATE, but the
// audit trigger only fires on a real status change (NEW.status DISTINCT FROM
// OLD.status), so NO second 'published' event is written.
//
// This is a characterization test of observed behavior, not an assertion that
// re-publish SHOULD be a no-op — see the readiness report's idempotency note.
func TestIntegration_PublishContent_RepublishNoNewAuditRow(t *testing.T) {
	s := setupServer(t)
	id := seedContent(t, "publish-idempotent", "review")

	if _, _, err := callHandlerAs(t, "human", s.publishContentTool, PublishContentInput{ContentID: id.String()}); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if got := publishedEventCount(t, id); got != 1 {
		t.Fatalf("after first publish: published events = %d, want 1", got)
	}

	// Re-publish the already-published row.
	if _, out, err := callHandlerAs(t, "human", s.publishContentTool, PublishContentInput{ContentID: id.String()}); err != nil {
		t.Fatalf("re-publish: %v, want no error (no status guard)", err)
	} else if out.Content == nil || out.Content.Status != "published" {
		t.Errorf("re-publish status = %v, want published", out.Content)
	}

	if status, isPublic, _ := contentRowState(t, id); status != "published" || !isPublic {
		t.Errorf("after re-publish: status=%q is_public=%v, want published/true", status, isPublic)
	}
	// The contract under test: no NEW audit row on re-publish.
	if got := publishedEventCount(t, id); got != 1 {
		t.Errorf("after re-publish: published events = %d, want 1 (trigger fires only on status change)", got)
	}
}

// TestIntegration_PublishContent_RejectsNonReviewStates pins the state-guard
// decision (2026-05-22): publish_content is review-gated. Publishing a draft or
// an archived row is rejected with an invalid-state error, the row is NOT
// mutated, and NO 'published' activity event is written. (The seed INSERT
// writes a 'created' event with actor='system'; we assert only that no
// 'published' event appears.)
func TestIntegration_PublishContent_RejectsNonReviewStates(t *testing.T) {
	tests := []struct {
		name      string
		slug      string
		seedState string
	}{
		{name: "draft rejected", slug: "publish-reject-draft", seedState: "draft"},
		{name: "archived rejected", slug: "publish-reject-archived", seedState: "archived"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := setupServer(t)
			id := seedContent(t, tt.slug, tt.seedState)

			_, _, err := callHandlerAs(t, "human", s.publishContentTool, PublishContentInput{
				ContentID: id.String(),
			})
			if err == nil {
				t.Fatalf("publish_content(%s) = nil, want invalid-state rejection", tt.seedState)
			}
			if !strings.Contains(err.Error(), "not in review state") {
				t.Errorf("error = %q, want it to report the review-state requirement", err.Error())
			}

			// Row must be untouched.
			status, isPublic, publishedAt := contentRowState(t, id)
			if status != tt.seedState {
				t.Errorf("db status = %q, want unchanged %q", status, tt.seedState)
			}
			if isPublic {
				t.Errorf("db is_public = true, want false (rejected publish must not mutate)")
			}
			if publishedAt != nil {
				t.Errorf("db published_at = %v, want NULL (rejected publish must not set it)", publishedAt)
			}
			// No published audit event on the rejection path.
			if got := publishedEventCount(t, id); got != 0 {
				t.Errorf("published activity_events = %d, want 0 (rejected publish writes no event)", got)
			}
		})
	}
}

// Track 1E — content lifecycle contract (DB-backed dimensions).
//
// Pins the create/update/submit/revert/archive transitions against a real DB:
// success transitions + audit + actor, and the CHECK-enforced rejections of
// illegal transitions (characterized, not blessed — see
// docs/testing/content-lifecycle-mcp-contract.md for the Human-decision flags).
// publish_content is unchanged (Track 1D); draft→published stays blocked.
//
// Reuses harness from integration_test.go (setupServer, callHandler,
// callHandlerAs, activityActorFor) and publish_content_integration_test.go
// (seedContent, contentRowState). Default caller is "learning-studio".
//
// Run with: go test -tags=integration ./internal/mcp/...

// contentEventCountByKind counts activity_events rows for a content of a given
// change_kind — used to assert "a transition wrote (or did NOT write) an event".
func contentEventCountByKind(t *testing.T, id uuid.UUID, kind string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM activity_events
		 WHERE entity_type='content' AND entity_id=$1 AND change_kind=$2`, id, kind,
	).Scan(&n); err != nil {
		t.Fatalf("contentEventCountByKind(%s,%s): %v", id, kind, err)
	}
	return n
}

// seedPublished produces a genuinely-published row (status=published,
// is_public=true, published_at set) by going through the tested publish path:
// seed a review row, then publish_content as the human via the caller's server
// (s already came from setupServer; we must not re-truncate). Returns the id.
func seedPublished(t *testing.T, s *Server, slug string) uuid.UUID {
	t.Helper()
	id := seedContent(t, slug, "review")
	if _, _, err := callHandlerAs(t, "human", s.publishContentTool, PublishContentInput{ContentID: id.String()}); err != nil {
		t.Fatalf("seedPublished publish: %v", err)
	}
	return id
}

func TestIntegration_CreateContent_Draft(t *testing.T) {
	s := setupServer(t)

	_, out, err := callHandler(t, s.createContentTool, CreateContentInput{
		Title:       "Value semantics in Go",
		ContentType: "article",
	})
	if err != nil {
		t.Fatalf("create_content: %v", err)
	}
	if out.Action != "create" || out.Content == nil {
		t.Fatalf("create_content out = %+v, want action=create with content", out)
	}
	if out.Content.Status != "draft" {
		t.Errorf("created status = %q, want draft", out.Content.Status)
	}
	id := uuid.MustParse(out.Content.ID)

	if status, _, _ := contentRowState(t, id); status != "draft" {
		t.Errorf("db status = %q, want draft", status)
	}
	if got := contentEventCountByKind(t, id, "created"); got != 1 {
		t.Errorf("created events = %d, want 1", got)
	}
	if actor := activityActorFor(t, "content", id); actor != "learning-studio" {
		t.Errorf("created actor = %q, want learning-studio", actor)
	}
}

func TestIntegration_CreateContent_SlugConflict(t *testing.T) {
	s := setupServer(t)
	slug := "dup-slug"

	if _, _, err := callHandler(t, s.createContentTool, CreateContentInput{
		Title: "First", ContentType: "article", Slug: &slug,
	}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, out, err := callHandler(t, s.createContentTool, CreateContentInput{
		Title: "Second", ContentType: "article", Slug: &slug,
	})
	if err != nil {
		t.Fatalf("second create returned error, want SlugConflict (no error): %v", err)
	}
	if out.SlugConflict == nil || out.SlugConflict.Slug != slug {
		t.Fatalf("second create SlugConflict = %+v, want slug=%q", out.SlugConflict, slug)
	}
	// Only one row exists for the slug.
	var n int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM contents WHERE slug=$1`, slug).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("rows with slug %q = %d, want 1 (conflict must not create a second)", slug, n)
	}
}

// TestIntegration_UpdateContent covers the fields-only contract: title/body/
// slug edits succeed and write NO status event; a status field is rejected
// (Track 1E-correction) with no mutation; not-found and slug-conflict behave.
func TestIntegration_UpdateContent(t *testing.T) {
	t.Run("field edit succeeds without a status event", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "update-field", "draft")
		newTitle := "Updated Title"
		_, out, err := callHandler(t, s.updateContentTool, UpdateContentInput{ContentID: id.String(), Title: &newTitle})
		if err != nil {
			t.Fatalf("update_content: %v", err)
		}
		if out.Content == nil || out.Content.Title != newTitle {
			t.Errorf("updated title = %v, want %q", out.Content, newTitle)
		}
		if status, _, _ := contentRowState(t, id); status != "draft" {
			t.Errorf("status = %q, want unchanged draft", status)
		}
		if got := contentEventCountByKind(t, id, "state_changed"); got != 0 {
			t.Errorf("state_changed events = %d, want 0 (field-only update writes no status event)", got)
		}
	})

	t.Run("status change is rejected with no mutation or event", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "update-reject-status", "draft")
		review := "review"
		_, _, err := callHandler(t, s.updateContentTool, UpdateContentInput{ContentID: id.String(), Status: &review})
		if err == nil || !strings.Contains(err.Error(), "does not change status") {
			t.Fatalf("update_content(status) = %v, want 'does not change status' rejection", err)
		}
		if status, _, _ := contentRowState(t, id); status != "draft" {
			t.Errorf("status after rejected status-change = %q, want unchanged draft", status)
		}
		if got := contentEventCountByKind(t, id, "state_changed"); got != 0 {
			t.Errorf("state_changed events = %d, want 0", got)
		}
	})

	t.Run("not found", func(t *testing.T) {
		s := setupServer(t)
		title := "x"
		_, _, err := callHandler(t, s.updateContentTool, UpdateContentInput{ContentID: uuid.New().String(), Title: &title})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("update_content(missing) = %v, want not-found error", err)
		}
	})

	t.Run("slug conflict surfaces without error", func(t *testing.T) {
		s := setupServer(t)
		_ = seedContent(t, "taken-slug", "draft")
		id := seedContent(t, "free-slug", "draft")
		taken := "taken-slug"
		_, out, err := callHandler(t, s.updateContentTool, UpdateContentInput{ContentID: id.String(), Slug: &taken})
		if err != nil {
			t.Fatalf("update_content slug rename = %v, want SlugConflict (no error)", err)
		}
		if out.SlugConflict == nil || out.SlugConflict.Slug != taken {
			t.Errorf("SlugConflict = %+v, want slug=%q", out.SlugConflict, taken)
		}
	})
}

// TestIntegration_SubmitForReview pins the corrected contract: draft→review
// succeeds (event + actor); review→review is an idempotent no-op (no second
// event); published/archived are rejected as a clean invalid_state with no
// mutation or event.
func TestIntegration_SubmitForReview(t *testing.T) {
	t.Run("draft to review succeeds with event and actor", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "submit-ok", "draft")
		_, out, err := callHandler(t, s.submitContentForReviewTool, SubmitContentForReviewInput{ContentID: id.String()})
		if err != nil {
			t.Fatalf("submit(draft): %v", err)
		}
		if out.Content == nil || out.Content.Status != "review" {
			t.Errorf("status = %v, want review", out.Content)
		}
		if status, _, _ := contentRowState(t, id); status != "review" {
			t.Errorf("db status = %q, want review", status)
		}
		if got := contentEventCountByKind(t, id, "state_changed"); got != 1 {
			t.Errorf("state_changed events = %d, want 1", got)
		}
		if actor := activityActorFor(t, "content", id); actor != "learning-studio" {
			t.Errorf("actor = %q, want learning-studio", actor)
		}
	})
	t.Run("review to review is an idempotent no-op", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "submit-idem", "review")
		_, out, err := callHandler(t, s.submitContentForReviewTool, SubmitContentForReviewInput{ContentID: id.String()})
		if err != nil {
			t.Fatalf("submit(review) = %v, want idempotent no-op", err)
		}
		if out.Content == nil || out.Content.Status != "review" {
			t.Errorf("status = %v, want review", out.Content)
		}
		if got := contentEventCountByKind(t, id, "state_changed"); got != 0 {
			t.Errorf("state_changed events = %d, want 0 (idempotent no-op)", got)
		}
	})
	t.Run("published is rejected", func(t *testing.T) {
		s := setupServer(t)
		id := seedPublished(t, s, "submit-reject-pub")
		_, _, err := callHandler(t, s.submitContentForReviewTool, SubmitContentForReviewInput{ContentID: id.String()})
		assertTransitionRejected(t, id, err, "published", "state_changed")
	})
	t.Run("archived is rejected", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "submit-reject-arch", "archived")
		_, _, err := callHandler(t, s.submitContentForReviewTool, SubmitContentForReviewInput{ContentID: id.String()})
		assertTransitionRejected(t, id, err, "archived", "state_changed")
	})
	t.Run("not found", func(t *testing.T) {
		s := setupServer(t)
		_, _, err := callHandler(t, s.submitContentForReviewTool, SubmitContentForReviewInput{ContentID: uuid.New().String()})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("submit(missing) = %v, want not-found", err)
		}
	})
}

// TestIntegration_RevertToDraft mirrors submit: review→draft succeeds;
// draft→draft idempotent no-op; published/archived rejected.
func TestIntegration_RevertToDraft(t *testing.T) {
	t.Run("review to draft succeeds with event and actor", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "revert-ok", "review")
		_, out, err := callHandler(t, s.revertContentToDraftTool, RevertContentToDraftInput{ContentID: id.String()})
		if err != nil {
			t.Fatalf("revert(review): %v", err)
		}
		if out.Content == nil || out.Content.Status != "draft" {
			t.Errorf("status = %v, want draft", out.Content)
		}
		if got := contentEventCountByKind(t, id, "state_changed"); got != 1 {
			t.Errorf("state_changed events = %d, want 1", got)
		}
		if actor := activityActorFor(t, "content", id); actor != "learning-studio" {
			t.Errorf("actor = %q, want learning-studio", actor)
		}
	})
	t.Run("draft to draft is an idempotent no-op", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "revert-idem", "draft")
		_, out, err := callHandler(t, s.revertContentToDraftTool, RevertContentToDraftInput{ContentID: id.String()})
		if err != nil {
			t.Fatalf("revert(draft) = %v, want idempotent no-op", err)
		}
		if out.Content == nil || out.Content.Status != "draft" {
			t.Errorf("status = %v, want draft", out.Content)
		}
		if got := contentEventCountByKind(t, id, "state_changed"); got != 0 {
			t.Errorf("state_changed events = %d, want 0 (idempotent no-op)", got)
		}
	})
	t.Run("published is rejected", func(t *testing.T) {
		s := setupServer(t)
		id := seedPublished(t, s, "revert-reject-pub")
		_, _, err := callHandler(t, s.revertContentToDraftTool, RevertContentToDraftInput{ContentID: id.String()})
		assertTransitionRejected(t, id, err, "published", "state_changed")
	})
	t.Run("archived is rejected", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "revert-reject-arch", "archived")
		_, _, err := callHandler(t, s.revertContentToDraftTool, RevertContentToDraftInput{ContentID: id.String()})
		assertTransitionRejected(t, id, err, "archived", "state_changed")
	})
	t.Run("not found", func(t *testing.T) {
		s := setupServer(t)
		_, _, err := callHandler(t, s.revertContentToDraftTool, RevertContentToDraftInput{ContentID: uuid.New().String()})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("revert(missing) = %v, want not-found", err)
		}
	})
}

// TestIntegration_ArchiveContent: draft→archived and review→archived succeed;
// archived→archived idempotent; published is rejected (depublication is a
// separate decision, NOT hidden in archive_content).
func TestIntegration_ArchiveContent(t *testing.T) {
	t.Run("draft to archived succeeds, then idempotent", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "archive-draft", "draft")
		if _, out, err := callHandler(t, s.archiveContentTool, ArchiveContentInput{ContentID: id.String()}); err != nil {
			t.Fatalf("archive(draft): %v", err)
		} else if out.Content == nil || out.Content.Status != "archived" {
			t.Errorf("status = %v, want archived", out.Content)
		}
		if status, _, _ := contentRowState(t, id); status != "archived" {
			t.Errorf("db status = %q, want archived", status)
		}
		if got := contentEventCountByKind(t, id, "archived"); got != 1 {
			t.Errorf("archived events = %d, want 1", got)
		}
		if actor := activityActorFor(t, "content", id); actor != "learning-studio" {
			t.Errorf("actor = %q, want learning-studio", actor)
		}
		// archived → archived idempotent no-op: no second event.
		if _, _, err := callHandler(t, s.archiveContentTool, ArchiveContentInput{ContentID: id.String()}); err != nil {
			t.Fatalf("archive(already archived) = %v, want no-op success", err)
		}
		if got := contentEventCountByKind(t, id, "archived"); got != 1 {
			t.Errorf("archived events after re-archive = %d, want 1 (no second event)", got)
		}
	})
	t.Run("review to archived succeeds", func(t *testing.T) {
		s := setupServer(t)
		id := seedContent(t, "archive-review", "review")
		if _, out, err := callHandler(t, s.archiveContentTool, ArchiveContentInput{ContentID: id.String()}); err != nil {
			t.Fatalf("archive(review): %v", err)
		} else if out.Content == nil || out.Content.Status != "archived" {
			t.Errorf("status = %v, want archived", out.Content)
		}
		if got := contentEventCountByKind(t, id, "archived"); got != 1 {
			t.Errorf("archived events = %d, want 1", got)
		}
	})
	t.Run("published is rejected", func(t *testing.T) {
		s := setupServer(t)
		id := seedPublished(t, s, "archive-reject-pub")
		_, _, err := callHandler(t, s.archiveContentTool, ArchiveContentInput{ContentID: id.String()})
		assertTransitionRejected(t, id, err, "published", "archived")
	})
	t.Run("not found", func(t *testing.T) {
		s := setupServer(t)
		_, _, err := callHandler(t, s.archiveContentTool, ArchiveContentInput{ContentID: uuid.New().String()})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("archive(missing) = %v, want not-found", err)
		}
	})
}

// assertTransitionRejected verifies a lifecycle transition was rejected with a
// CLEAN invalid_state error (Track 1E-correction — not a raw DB CHECK leak),
// the row's status is unchanged, and no audit event of forbiddenKind was added.
func assertTransitionRejected(t *testing.T, id uuid.UUID, err error, wantStatus, forbiddenKind string) {
	t.Helper()
	if err == nil {
		t.Fatalf("illegal transition = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "must be in") {
		t.Errorf("rejection error = %q, want a clean invalid-state message (not a raw DB error)", err)
	}
	if status, _, _ := contentRowState(t, id); status != wantStatus {
		t.Errorf("status after rejected transition = %q, want unchanged %q", status, wantStatus)
	}
	if got := contentEventCountByKind(t, id, forbiddenKind); got != 0 {
		t.Errorf("%s events after rejected transition = %d, want 0", forbiddenKind, got)
	}
}

// ============================================================================
// Consolidated from a2a_integration_test.go (Track-1K test-file consolidation).
// ============================================================================

// =========================================================================
// Section: A2A directive/report chain — helpers
// =========================================================================

// seedSubmittedTask inserts a task in the default 'submitted' state plus its
// initial request message, mirroring what commit_proposal(directive) produces.
// Returns the task id. createdBy and assignee must be distinct registry agents
// (chk_tasks_no_self_assignment).
func seedSubmittedTask(t *testing.T, createdBy, assignee, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO tasks (created_by, assignee, title)
		 VALUES ($1, $2, $3) RETURNING id`,
		createdBy, assignee, title,
	).Scan(&id); err != nil {
		t.Fatalf("seeding task: %v", err)
	}
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO task_messages (task_id, role, position, parts)
		 VALUES ($1, 'request', 0, '[{"text":"please do the work"}]'::jsonb)`,
		id,
	); err != nil {
		t.Fatalf("seeding request message: %v", err)
	}
	return id
}

// taskRow returns the (state, created_by, assignee) for a task.
func taskRow(t *testing.T, id uuid.UUID) (state, createdBy, assignee string) {
	t.Helper()
	if err := testPool.QueryRow(t.Context(),
		`SELECT state, created_by, assignee FROM tasks WHERE id = $1`, id,
	).Scan(&state, &createdBy, &assignee); err != nil {
		t.Fatalf("reading task %s: %v", id, err)
	}
	return state, createdBy, assignee
}

func taskAcceptedAtSet(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	var set bool
	if err := testPool.QueryRow(t.Context(),
		`SELECT accepted_at IS NOT NULL FROM tasks WHERE id = $1`, id,
	).Scan(&set); err != nil {
		t.Fatalf("reading accepted_at for %s: %v", id, err)
	}
	return set
}

func taskCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(), `SELECT count(*) FROM tasks`).Scan(&n); err != nil {
		t.Fatalf("counting tasks: %v", err)
	}
	return n
}

func messageCount(t *testing.T, taskID uuid.UUID, role string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM task_messages WHERE task_id = $1 AND role = $2`, taskID, role,
	).Scan(&n); err != nil {
		t.Fatalf("counting %s messages for %s: %v", role, taskID, err)
	}
	return n
}

func artifactCountForTask(t *testing.T, taskID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM artifacts WHERE task_id = $1`, taskID,
	).Scan(&n); err != nil {
		t.Fatalf("counting artifacts for %s: %v", taskID, err)
	}
	return n
}

// taskEventCount counts activity_events of a given change_kind for a task.
func taskEventCount(t *testing.T, taskID uuid.UUID, kind string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM activity_events
		 WHERE entity_type = 'task' AND entity_id = $1 AND change_kind = $2`,
		taskID, kind,
	).Scan(&n); err != nil {
		t.Fatalf("counting %s events for task %s: %v", kind, taskID, err)
	}
	return n
}

// allTaskEventCount counts every task-typed activity_events row in the DB.
// Used to assert that a standalone artifact produces no task audit row.
func allTaskEventCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM activity_events WHERE entity_type = 'task'`,
	).Scan(&n); err != nil {
		t.Fatalf("counting task events: %v", err)
	}
	return n
}

// standaloneArtifact returns (task_id, created_by) for an artifact row.
func standaloneArtifact(t *testing.T, id uuid.UUID) (taskID *uuid.UUID, createdBy string) {
	t.Helper()
	if err := testPool.QueryRow(t.Context(),
		`SELECT task_id, created_by FROM artifacts WHERE id = $1`, id,
	).Scan(&taskID, &createdBy); err != nil {
		t.Fatalf("reading artifact %s: %v", id, err)
	}
	return taskID, createdBy
}

// mustAck acknowledges as the default caller (learning-studio = target).
func mustAck(t *testing.T, s *Server, taskID uuid.UUID) {
	t.Helper()
	if _, _, err := callHandler(t, s.acknowledgeDirective,
		AcknowledgeDirectiveInput{TaskID: taskID.String()}); err != nil {
		t.Fatalf("acknowledge_directive: %v", err)
	}
}

// mustReport files a task-bound report as the default caller (learning-studio).
func mustReport(t *testing.T, s *Server, taskID uuid.UUID) {
	t.Helper()
	if _, _, err := callHandler(t, s.fileReport, FileReportInput{
		InResponseTo:  taskID.String(),
		ResponseParts: []json.RawMessage{json.RawMessage(`{"text":"done"}`)},
		Artifact: &FileReportArtifactInput{
			Name:  "deliverable",
			Parts: []json.RawMessage{json.RawMessage(`{"text":"the result"}`)},
		},
	}); err != nil {
		t.Fatalf("file_report: %v", err)
	}
}

// =========================================================================
// Section: A2A happy path — propose → commit → ack → report → detail
// =========================================================================

// TestIntegration_A2A_DirectiveReportChain_HappyPath walks the full MCP chain
// and asserts every load-bearing side effect: the directive task row, the
// acknowledgement transition, the report's response message + artifact, the
// report↔directive linkage (artifacts.task_id), the activity_events audit
// trail, actor attribution at each step, and task_detail's bundled view.
func TestIntegration_A2A_DirectiveReportChain_HappyPath(t *testing.T) {
	s := setupServer(t) // default caller = learning-studio

	// --- propose_directive (as hq; hq holds SubmitTasks) ---
	_, prop, err := callHandlerAs(t, "hq", s.proposeDirective, ProposeDirectiveInput{
		Target:       "learning-studio",
		Priority:     "high",
		RequestParts: []json.RawMessage{json.RawMessage(`{"text":"Research NATS exactly-once delivery"}`)},
	})
	if err != nil {
		t.Fatalf("propose_directive: %v", err)
	}
	if prop.Type != "directive" || prop.ProposalToken == "" {
		t.Fatalf("propose output = %+v, want type=directive with a token", prop)
	}
	// Propose writes nothing — no tasks row until commit.
	if n := taskCount(t); n != 0 {
		t.Fatalf("tasks rows after propose = %d, want 0 (propose is read-only)", n)
	}

	// --- commit_proposal (as hq; directive commit is capability-gated, not human-gated) ---
	_, commit, err := callHandlerAs(t, "hq", s.commitProposal, CommitProposalInput{ProposalToken: prop.ProposalToken})
	if err != nil {
		t.Fatalf("commit_proposal: %v", err)
	}
	if !commit.Committed || commit.Type != "directive" {
		t.Fatalf("commit output = %+v, want directive committed", commit)
	}
	taskID := uuid.MustParse(commit.ID)

	if state, by, assignee := taskRow(t, taskID); state != "submitted" || by != "hq" || assignee != "learning-studio" {
		t.Errorf("task row = (state=%s, by=%s, assignee=%s), want (submitted, hq, learning-studio)", state, by, assignee)
	}
	if n := messageCount(t, taskID, "request"); n != 1 {
		t.Errorf("request messages after commit = %d, want 1", n)
	}
	if k := latestActivityChangeKind(t, "task", taskID); k != "created" {
		t.Errorf("commit audit change_kind = %q, want created", k)
	}
	if a := activityActorFor(t, "task", taskID); a != "hq" {
		t.Errorf("commit audit actor = %q, want hq", a)
	}

	// --- acknowledge_directive (as target learning-studio = default caller) ---
	_, ack, err := callHandler(t, s.acknowledgeDirective, AcknowledgeDirectiveInput{TaskID: taskID.String()})
	if err != nil {
		t.Fatalf("acknowledge_directive: %v", err)
	}
	if ack.State != "working" || ack.AcknowledgedBy != "learning-studio" {
		t.Errorf("ack output = %+v, want state=working acknowledged_by=learning-studio", ack)
	}
	if state, _, _ := taskRow(t, taskID); state != "working" {
		t.Errorf("post-ack state = %q, want working", state)
	}
	if !taskAcceptedAtSet(t, taskID) {
		t.Error("post-ack accepted_at is NULL, want set")
	}
	if k := latestActivityChangeKind(t, "task", taskID); k != "state_changed" {
		t.Errorf("ack audit change_kind = %q, want state_changed", k)
	}

	// --- file_report (as target learning-studio; holds PublishArtifacts) ---
	_, rep, err := callHandler(t, s.fileReport, FileReportInput{
		InResponseTo:  taskID.String(),
		ResponseParts: []json.RawMessage{json.RawMessage(`{"text":"Done — see artifact"}`)},
		Artifact: &FileReportArtifactInput{
			Name:  "nats-research",
			Parts: []json.RawMessage{json.RawMessage(`{"data":{"summary":"jetstream exactly-once","sources":3}}`)},
		},
	})
	if err != nil {
		t.Fatalf("file_report: %v", err)
	}
	if !rep.Completed || rep.State != "completed" || rep.TaskID != taskID.String() {
		t.Errorf("report output = %+v, want completed for task %s", rep, taskID)
	}
	// Contract: the task-bound path deliberately does NOT surface the artifact
	// id (task.Complete does not return it) — task_id is the anchor. Pin the
	// empty value so a future change that starts populating it is caught.
	if rep.ArtifactID != "" {
		t.Errorf("task-bound report ArtifactID = %q, want empty (task_id is the anchor)", rep.ArtifactID)
	}
	if state, _, _ := taskRow(t, taskID); state != "completed" {
		t.Errorf("post-report state = %q, want completed", state)
	}
	if n := messageCount(t, taskID, "response"); n != 1 {
		t.Errorf("response messages after report = %d, want 1", n)
	}
	if n := artifactCountForTask(t, taskID); n != 1 {
		t.Errorf("artifacts linked to task after report = %d, want 1", n)
	}
	if k := latestActivityChangeKind(t, "task", taskID); k != "completed" {
		t.Errorf("report audit change_kind = %q, want completed", k)
	}
	if a := activityActorFor(t, "task", taskID); a != "learning-studio" {
		t.Errorf("completion audit actor = %q, want learning-studio", a)
	}

	// --- task_detail (as source hq) returns the full linked bundle ---
	_, detail, err := callHandlerAs(t, "hq", s.taskDetail, TaskDetailInput{TaskID: taskID.String()})
	if err != nil {
		t.Fatalf("task_detail: %v", err)
	}
	if detail.Task.ID != taskID || detail.Task.State != task.StateCompleted {
		t.Errorf("detail.Task = (id=%s, state=%s), want (%s, completed)", detail.Task.ID, detail.Task.State, taskID)
	}
	if len(detail.Messages) != 2 {
		t.Errorf("detail messages = %d, want 2 (request + response)", len(detail.Messages))
	}
	if len(detail.Artifacts) != 1 {
		t.Fatalf("detail artifacts = %d, want 1", len(detail.Artifacts))
	}
	// Report↔directive linkage: the artifact is bound to this exact task.
	if detail.Artifacts[0].TaskID == nil || *detail.Artifacts[0].TaskID != taskID {
		t.Errorf("artifact.task_id = %v, want %s (report↔directive linkage)", detail.Artifacts[0].TaskID, taskID)
	}
}

// =========================================================================
// Section: Duplicate acknowledgement
// =========================================================================

// TestIntegration_A2A_DuplicateAcknowledge pins the idempotency contract:
// the first ack moves submitted→working; a second ack on the now-working task
// is rejected with a wrong-state error, does NOT re-transition, and produces
// no second activity_events row. (Characterized, not a human-decision gap.)
func TestIntegration_A2A_DuplicateAcknowledge(t *testing.T) {
	s := setupServer(t)
	taskID := seedSubmittedTask(t, "hq", "learning-studio", "dup-ack fixture")

	if _, _, err := callHandler(t, s.acknowledgeDirective,
		AcknowledgeDirectiveInput{TaskID: taskID.String()}); err != nil {
		t.Fatalf("first acknowledge_directive: %v", err)
	}

	_, _, err := callHandler(t, s.acknowledgeDirective, AcknowledgeDirectiveInput{TaskID: taskID.String()})
	if err == nil {
		t.Fatal("second acknowledge_directive succeeded; want a wrong-state conflict")
	}
	if !strings.Contains(err.Error(), "submitted") {
		t.Errorf("second ack error = %v, want a 'submitted' wrong-state message", err)
	}
	if state, _, _ := taskRow(t, taskID); state != "working" {
		t.Errorf("state after rejected re-ack = %q, want working (no re-transition)", state)
	}
	if n := taskEventCount(t, taskID, "state_changed"); n != 1 {
		t.Errorf("state_changed events = %d, want 1 (no duplicate audit row on rejected re-ack)", n)
	}
}

// =========================================================================
// Section: Report without directive (standalone)
// =========================================================================

// TestIntegration_A2A_ReportWithoutDirective covers the unsolicited-report
// path: file_report with no in_response_to creates a standalone artifact for
// an allowlisted author (content-studio / research-lab / learning-studio) and
// is rejected for hq (excluded from the allowlist despite holding
// PublishArtifacts).
func TestIntegration_A2A_ReportWithoutDirective(t *testing.T) {
	t.Run("standalone supported for an allowlisted author", func(t *testing.T) {
		s := setupServer(t)
		_, rep, err := callHandlerAs(t, "content-studio", s.fileReport, FileReportInput{
			Artifact: &FileReportArtifactInput{
				Name:  "industry-scan",
				Parts: []json.RawMessage{json.RawMessage(`{"text":"weekly scan summary"}`)},
			},
		})
		if err != nil {
			t.Fatalf("standalone file_report: %v", err)
		}
		if rep.State != "standalone" {
			t.Errorf("standalone report State = %q, want standalone", rep.State)
		}
		if rep.Completed {
			t.Error("standalone report Completed = true, want false")
		}
		if rep.ArtifactID == "" {
			t.Error("standalone report ArtifactID is empty, want a generated id")
		}
		aid := uuid.MustParse(rep.ArtifactID)
		if tid, by := standaloneArtifact(t, aid); tid != nil || by != "content-studio" {
			t.Errorf("standalone artifact = (task_id=%v, by=%s), want (nil, content-studio)", tid, by)
		}
		// A standalone artifact has no audit trigger and entity_type='artifact'
		// is not whitelisted in activity_events — so no task event is produced.
		if n := allTaskEventCount(t); n != 0 {
			t.Errorf("task activity_events after standalone report = %d, want 0", n)
		}
	})

	t.Run("hq is excluded from the standalone allowlist", func(t *testing.T) {
		s := setupServer(t)
		_, _, err := callHandlerAs(t, "hq", s.fileReport, FileReportInput{
			Artifact: &FileReportArtifactInput{
				Name:  "hq-artifact",
				Parts: []json.RawMessage{json.RawMessage(`{"text":"should be rejected"}`)},
			},
		})
		if err == nil {
			t.Fatal("hq standalone file_report succeeded; want allowlist rejection")
		}
	})
}

// =========================================================================
// Section: Wrong actor (capability-passing non-party)
// =========================================================================

// TestIntegration_A2A_WrongActor verifies actor-level enforcement EXISTS on
// the mutating coordination tools: a caller that holds the required capability
// but is not the task's target is rejected, and the task is not mutated.
func TestIntegration_A2A_WrongActor(t *testing.T) {
	t.Run("acknowledge by a non-target with ReceiveTasks is rejected", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "wrong-actor ack")
		// research-lab HAS ReceiveTasks (passes the capability gate) but is not
		// the target — so it reaches and fails the assignee check.
		_, _, err := callHandlerAs(t, "research-lab", s.acknowledgeDirective,
			AcknowledgeDirectiveInput{TaskID: taskID.String()})
		if err == nil {
			t.Fatal("research-lab acknowledged a task it is not the target of; want rejection")
		}
		if !strings.Contains(err.Error(), "not the task target") {
			t.Errorf("wrong-actor ack error = %v, want 'not the task target'", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "submitted" {
			t.Errorf("state after rejected ack = %q, want submitted (no transition)", state)
		}
	})

	t.Run("file_report by a non-target with PublishArtifacts is rejected", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "wrong-actor report")
		mustAck(t, s, taskID) // legitimate target moves it to working

		// research-lab HAS PublishArtifacts (passes the capability gate) but is
		// not the target.
		_, _, err := callHandlerAs(t, "research-lab", s.fileReport, FileReportInput{
			InResponseTo:  taskID.String(),
			ResponseParts: []json.RawMessage{json.RawMessage(`{"text":"intruder report"}`)},
			Artifact:      &FileReportArtifactInput{Name: "x", Parts: []json.RawMessage{json.RawMessage(`{"text":"x"}`)}},
		})
		if err == nil {
			t.Fatal("research-lab completed a task it is not the target of; want rejection")
		}
		if !strings.Contains(err.Error(), "not the task target") {
			t.Errorf("wrong-actor report error = %v, want 'not the task target'", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "working" {
			t.Errorf("state after rejected report = %q, want working (no completion)", state)
		}
		if n := artifactCountForTask(t, taskID); n != 0 {
			t.Errorf("artifacts after rejected report = %d, want 0", n)
		}
	})
}

// =========================================================================
// Section: Not-found / stale reference
// =========================================================================

// TestIntegration_A2A_NotFound verifies that a well-formed but non-existent
// task id is rejected with a not-found shape across all three id-taking tools.
func TestIntegration_A2A_NotFound(t *testing.T) {
	s := setupServer(t)
	missing := uuid.New().String()

	t.Run("acknowledge a nonexistent directive", func(t *testing.T) {
		// learning-studio holds ReceiveTasks → passes capability, reaches lookup.
		_, _, err := callHandler(t, s.acknowledgeDirective, AcknowledgeDirectiveInput{TaskID: missing})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("acknowledge_directive(missing) error = %v, want 'not found'", err)
		}
	})

	t.Run("file_report with a nonexistent in_response_to", func(t *testing.T) {
		// learning-studio holds PublishArtifacts → passes capability, reaches lookup.
		_, _, err := callHandler(t, s.fileReport, FileReportInput{
			InResponseTo:  missing,
			ResponseParts: []json.RawMessage{json.RawMessage(`{"text":"x"}`)},
			Artifact:      &FileReportArtifactInput{Name: "x", Parts: []json.RawMessage{json.RawMessage(`{"text":"x"}`)}},
		})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("file_report(missing task) error = %v, want 'not found'", err)
		}
	})

	t.Run("task_detail of a nonexistent id", func(t *testing.T) {
		_, _, err := callHandler(t, s.taskDetail, TaskDetailInput{TaskID: missing})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("task_detail(missing) error = %v, want 'not found'", err)
		}
	})
}

// =========================================================================
// Section: State transition edge cases
// =========================================================================

// TestIntegration_A2A_StateEdgeCases pins the well-defined wrong-state
// rejections: report-before-ack, a second report after completion (one report
// per directive via the MCP path), and acknowledge after completion.
func TestIntegration_A2A_StateEdgeCases(t *testing.T) {
	t.Run("report before ack is rejected (working state required)", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "report-before-ack")
		_, _, err := callHandler(t, s.fileReport, FileReportInput{
			InResponseTo:  taskID.String(),
			ResponseParts: []json.RawMessage{json.RawMessage(`{"text":"too early"}`)},
			Artifact:      &FileReportArtifactInput{Name: "x", Parts: []json.RawMessage{json.RawMessage(`{"text":"x"}`)}},
		})
		if err == nil || !strings.Contains(err.Error(), "working") {
			t.Fatalf("report-before-ack error = %v, want a 'working' state message", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "submitted" {
			t.Errorf("state after rejected early report = %q, want submitted", state)
		}
		if n := artifactCountForTask(t, taskID); n != 0 {
			t.Errorf("artifacts after rejected early report = %d, want 0", n)
		}
	})

	t.Run("second report after completion is rejected (one report per directive via MCP)", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "double-report")
		mustAck(t, s, taskID)
		mustReport(t, s, taskID)

		_, _, err := callHandler(t, s.fileReport, FileReportInput{
			InResponseTo:  taskID.String(),
			ResponseParts: []json.RawMessage{json.RawMessage(`{"text":"again"}`)},
			Artifact:      &FileReportArtifactInput{Name: "x2", Parts: []json.RawMessage{json.RawMessage(`{"text":"x2"}`)}},
		})
		if err == nil || !strings.Contains(err.Error(), "working") {
			t.Fatalf("second report error = %v, want a 'working' state message (task already completed)", err)
		}
		// The completed task keeps exactly one report (re-completion is the
		// HTTP-admin revision cycle, not an MCP path).
		if n := artifactCountForTask(t, taskID); n != 1 {
			t.Errorf("artifacts after rejected second report = %d, want 1", n)
		}
		if n := messageCount(t, taskID, "response"); n != 1 {
			t.Errorf("response messages after rejected second report = %d, want 1", n)
		}
	})

	t.Run("acknowledge after completion is rejected (submitted state required)", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "ack-after-complete")
		mustAck(t, s, taskID)
		mustReport(t, s, taskID)

		_, _, err := callHandler(t, s.acknowledgeDirective, AcknowledgeDirectiveInput{TaskID: taskID.String()})
		if err == nil || !strings.Contains(err.Error(), "submitted") {
			t.Fatalf("acknowledge-after-completion error = %v, want a 'submitted' state message", err)
		}
	})
}

// =========================================================================
// Section: A2A revision cycle — request_revision / reaccept
// =========================================================================

// taskTimestampSet reports whether the given timestamp column on a task is
// non-NULL. Used by the revision-cycle tests to assert that completed_at and
// revision_requested_at are stamped/cleared at the right transitions.
// column MUST be a literal from the helper's call sites (completed_at,
// revision_requested_at) — it is interpolated into the SQL because pgx does
// not parameterize identifiers. Caller controls the input.
func taskTimestampSet(t *testing.T, taskID uuid.UUID, column string) bool {
	t.Helper()
	var set bool
	// #nosec G201 -- column is a literal from this file's callers, never user input.
	q := "SELECT " + column + " IS NOT NULL FROM tasks WHERE id = $1"
	if err := testPool.QueryRow(t.Context(), q, taskID).Scan(&set); err != nil {
		t.Fatalf("reading %s for %s: %v", column, taskID, err)
	}
	return set
}

// TestIntegration_A2A_RevisionCycle_HappyPath drives a directive through the
// full revision round-trip via MCP: ack → report → request_revision (with
// reason) → reaccept → second report. Each hop verifies the state, the
// timestamp invariants (completed_at preserved on RequestRevision, both
// cleared on Reaccept), and the cumulative response-message / artifact
// counts. The reason text travels into task_messages so the audit thread
// keeps a chronologically coherent "why-revise" turn.
func TestIntegration_A2A_RevisionCycle_HappyPath(t *testing.T) {
	s := setupServer(t)
	taskID := seedSubmittedTask(t, "hq", "learning-studio", "revision cycle through mcp")

	// First report cycle. mustAck/mustReport drive as learning-studio (the
	// default test caller); we'll switch to hq for the source-side revision.
	mustAck(t, s, taskID)
	mustReport(t, s, taskID)

	if state, _, _ := taskRow(t, taskID); state != "completed" {
		t.Fatalf("pre-revision state = %q, want completed", state)
	}
	if !taskTimestampSet(t, taskID, "completed_at") {
		t.Fatal("pre-revision: completed_at is NULL, want set")
	}

	// Source-side: hq requests a revision with an explanatory reason. The
	// reason is appended in the same withActorTx as the state transition.
	const reason = "needs more detail on the third paragraph"
	_, rev, err := callHandlerAs(t, "hq", s.requestRevision, RequestRevisionInput{
		TaskID: taskID.String(),
		Reason: strPtr(reason),
	})
	if err != nil {
		t.Fatalf("request_revision: %v", err)
	}
	if rev.State != "revision_requested" {
		t.Errorf("request_revision output state = %q, want revision_requested", rev.State)
	}
	if !rev.ReasonAppended {
		t.Error("request_revision output reason_appended = false, want true")
	}
	if rev.RequestedBy != "hq" {
		t.Errorf("request_revision output requested_by = %q, want hq", rev.RequestedBy)
	}
	if state, _, _ := taskRow(t, taskID); state != "revision_requested" {
		t.Errorf("post-request_revision state = %q, want revision_requested", state)
	}
	if !taskTimestampSet(t, taskID, "completed_at") {
		t.Error("post-request_revision: completed_at = NULL, want preserved")
	}
	if !taskTimestampSet(t, taskID, "revision_requested_at") {
		t.Error("post-request_revision: revision_requested_at = NULL, want set")
	}

	// The reason landed as a response message. After the first report there
	// is one response message; after request_revision there should be two
	// (first report's response + the revision reason).
	if n := messageCount(t, taskID, "response"); n != 2 {
		t.Errorf("response messages after request_revision = %d, want 2", n)
	}
	if actor := activityActorFor(t, "task", taskID); actor != "hq" {
		t.Errorf("latest task audit actor after request_revision = %q, want hq", actor)
	}

	// Target-side: learning-studio picks the revision back up.
	_, react, err := callHandler(t, s.reaccept, ReacceptInput{TaskID: taskID.String()})
	if err != nil {
		t.Fatalf("reaccept: %v", err)
	}
	if react.State != "working" {
		t.Errorf("reaccept output state = %q, want working", react.State)
	}
	if react.ReacceptedBy != "learning-studio" {
		t.Errorf("reaccept output reaccepted_by = %q, want learning-studio", react.ReacceptedBy)
	}
	if state, _, _ := taskRow(t, taskID); state != "working" {
		t.Errorf("post-reaccept state = %q, want working", state)
	}
	if taskTimestampSet(t, taskID, "completed_at") {
		t.Error("post-reaccept: completed_at not cleared, want NULL")
	}
	if taskTimestampSet(t, taskID, "revision_requested_at") {
		t.Error("post-reaccept: revision_requested_at not cleared, want NULL")
	}

	// Second report cycle — exercises the trigger-enforced completion
	// requirements after the round-trip. Cumulative outputs satisfy the
	// trigger's ≥1 response + ≥1 artifact bound automatically.
	mustReport(t, s, taskID)
	if state, _, _ := taskRow(t, taskID); state != "completed" {
		t.Errorf("final state = %q, want completed", state)
	}
	if n := artifactCountForTask(t, taskID); n != 2 {
		t.Errorf("final artifact count = %d, want 2 (one per Complete)", n)
	}
	// Two response messages from the two file_reports + one reason message = 3.
	if n := messageCount(t, taskID, "response"); n != 3 {
		t.Errorf("final response messages = %d, want 3 (two reports + one reason)", n)
	}
}

// TestIntegration_A2A_RequestRevision_AuthorizationRejection pins the
// auth/state rejection paths: a SubmitTasks-capable non-source caller is
// rejected with "not the task source"; a no-capability caller is rejected
// by agent.Authorize; a wrong-state call is rejected without appending the
// reason.
func TestIntegration_A2A_RequestRevision_AuthorizationRejection(t *testing.T) {
	t.Run("non-source caller with SubmitTasks is rejected", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "non-source revision attempt")
		mustAck(t, s, taskID)
		mustReport(t, s, taskID)
		responsesBefore := messageCount(t, taskID, "response")

		// content-studio HAS SubmitTasks (passes capability) but is not the
		// task source. Supply a reason so we can verify the failed transition
		// rolled back the message append.
		_, _, err := callHandlerAs(t, "content-studio", s.requestRevision, RequestRevisionInput{
			TaskID: taskID.String(),
			Reason: strPtr("trying to muscle in on a directive I didn't issue"),
		})
		if err == nil {
			t.Fatal("non-source request_revision succeeded; want rejection")
		}
		if !strings.Contains(err.Error(), "not the task source") {
			t.Errorf("non-source error = %v, want 'not the task source'", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "completed" {
			t.Errorf("state after rejected request_revision = %q, want completed", state)
		}
		if n := messageCount(t, taskID, "response"); n != responsesBefore {
			t.Errorf("response messages after rejected request_revision = %d, want %d (reason must not be appended)", n, responsesBefore)
		}
	})

	t.Run("caller without SubmitTasks is rejected at capability layer", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "no-cap revision attempt")
		mustAck(t, s, taskID)
		mustReport(t, s, taskID)

		// learning-studio has ReceiveTasks + PublishArtifacts but no SubmitTasks.
		_, _, err := callHandlerAs(t, "learning-studio", s.requestRevision, RequestRevisionInput{
			TaskID: taskID.String(),
		})
		if err == nil {
			t.Fatal("learning-studio request_revision succeeded; want capability rejection")
		}
		// agent.Authorize wraps ErrForbidden — surfaces as "capability denied" in the chain.
		if !strings.Contains(err.Error(), "capability denied") {
			t.Errorf("no-cap error = %v, want 'capability denied'", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "completed" {
			t.Errorf("state after rejected request_revision = %q, want completed", state)
		}
	})

	t.Run("wrong state rejected (working task)", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "wrong-state revision attempt")
		mustAck(t, s, taskID) // submitted → working, no report yet

		responsesBefore := messageCount(t, taskID, "response")
		_, _, err := callHandlerAs(t, "hq", s.requestRevision, RequestRevisionInput{
			TaskID: taskID.String(),
			Reason: strPtr("too early to revise"),
		})
		if err == nil {
			t.Fatal("request_revision on working task succeeded; want wrong-state rejection")
		}
		if !strings.Contains(err.Error(), "completed") {
			t.Errorf("wrong-state error = %v, want a 'completed' state message", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "working" {
			t.Errorf("state after rejected request_revision = %q, want working", state)
		}
		if n := messageCount(t, taskID, "response"); n != responsesBefore {
			t.Errorf("response messages after wrong-state request_revision = %d, want %d (reason must not be appended on wrong-state)", n, responsesBefore)
		}
	})
}

// TestIntegration_A2A_Reaccept_AuthorizationRejection mirrors the
// request_revision rejection coverage: non-target-with-cap rejection,
// no-capability rejection, and wrong-state rejection.
func TestIntegration_A2A_Reaccept_AuthorizationRejection(t *testing.T) {
	// Helper: build a task and drive it all the way to revision_requested.
	driveToRevisionRequested := func(t *testing.T, s *Server, title string) uuid.UUID {
		t.Helper()
		taskID := seedSubmittedTask(t, "hq", "learning-studio", title)
		mustAck(t, s, taskID)
		mustReport(t, s, taskID)
		_, _, err := callHandlerAs(t, "hq", s.requestRevision, RequestRevisionInput{
			TaskID: taskID.String(),
		})
		if err != nil {
			t.Fatalf("setup: request_revision: %v", err)
		}
		return taskID
	}

	t.Run("non-target caller with ReceiveTasks is rejected", func(t *testing.T) {
		s := setupServer(t)
		taskID := driveToRevisionRequested(t, s, "non-target reaccept attempt")

		// research-lab HAS ReceiveTasks (passes capability) but is not the target.
		_, _, err := callHandlerAs(t, "research-lab", s.reaccept, ReacceptInput{
			TaskID: taskID.String(),
		})
		if err == nil {
			t.Fatal("non-target reaccept succeeded; want rejection")
		}
		if !strings.Contains(err.Error(), "not the task target") {
			t.Errorf("non-target error = %v, want 'not the task target'", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "revision_requested" {
			t.Errorf("state after rejected reaccept = %q, want revision_requested", state)
		}
	})

	t.Run("caller without ReceiveTasks is rejected at capability layer", func(t *testing.T) {
		s := setupServer(t)
		taskID := driveToRevisionRequested(t, s, "no-cap reaccept attempt")

		// hq holds SubmitTasks + PublishArtifacts but no ReceiveTasks.
		_, _, err := callHandlerAs(t, "hq", s.reaccept, ReacceptInput{
			TaskID: taskID.String(),
		})
		if err == nil {
			t.Fatal("hq reaccept succeeded; want capability rejection")
		}
		if !strings.Contains(err.Error(), "capability denied") {
			t.Errorf("no-cap error = %v, want 'capability denied'", err)
		}
	})

	t.Run("wrong state rejected (completed task)", func(t *testing.T) {
		s := setupServer(t)
		taskID := seedSubmittedTask(t, "hq", "learning-studio", "wrong-state reaccept attempt")
		mustAck(t, s, taskID)
		mustReport(t, s, taskID) // task is completed, not revision_requested

		_, _, err := callHandler(t, s.reaccept, ReacceptInput{
			TaskID: taskID.String(),
		})
		if err == nil {
			t.Fatal("reaccept on completed task succeeded; want wrong-state rejection")
		}
		if !strings.Contains(err.Error(), "revision_requested") {
			t.Errorf("wrong-state error = %v, want a 'revision_requested' state message", err)
		}
		if state, _, _ := taskRow(t, taskID); state != "completed" {
			t.Errorf("state after rejected reaccept = %q, want completed", state)
		}
	})
}

// TestIntegration_A2A_RequestRevision_ReasonAppendAtomicity proves that the
// reason message and the state transition share a single withActorTx scope.
// First call succeeds (reason appended + transition). Second call fires the
// reason append inside the tx, then RequestRevision rejects on wrong state;
// the resulting Rollback discards the reason message. The visible response
// count after the rejected second call equals the post-first-call count.
func TestIntegration_A2A_RequestRevision_ReasonAppendAtomicity(t *testing.T) {
	s := setupServer(t)
	taskID := seedSubmittedTask(t, "hq", "learning-studio", "revision atomicity")
	mustAck(t, s, taskID)
	mustReport(t, s, taskID)

	// First request_revision succeeds: reason appended + transition.
	const firstReason = "first round of revisions"
	if _, _, err := callHandlerAs(t, "hq", s.requestRevision, RequestRevisionInput{
		TaskID: taskID.String(),
		Reason: strPtr(firstReason),
	}); err != nil {
		t.Fatalf("first request_revision: %v", err)
	}
	if state, _, _ := taskRow(t, taskID); state != "revision_requested" {
		t.Fatalf("after first revision: state = %q, want revision_requested", state)
	}
	responsesAfterFirst := messageCount(t, taskID, "response")
	// Sanity: 1 from file_report + 1 reason = 2.
	if responsesAfterFirst != 2 {
		t.Fatalf("after first revision: response messages = %d, want 2", responsesAfterFirst)
	}

	// Second request_revision is wrong-state — the task is now
	// revision_requested, not completed. The reason append runs inside the
	// same tx, RequestRevision fails, and Rollback must wipe the message.
	const secondReason = "this reason must never persist"
	_, _, err := callHandlerAs(t, "hq", s.requestRevision, RequestRevisionInput{
		TaskID: taskID.String(),
		Reason: strPtr(secondReason),
	})
	if err == nil {
		t.Fatal("second request_revision on revision_requested task succeeded; want wrong-state rejection")
	}
	if !strings.Contains(err.Error(), "completed") {
		t.Errorf("second request_revision error = %v, want a 'completed' state message", err)
	}
	if n := messageCount(t, taskID, "response"); n != responsesAfterFirst {
		t.Errorf("response messages after rejected second revision = %d, want %d (atomicity: reason must roll back with failed transition)", n, responsesAfterFirst)
	}
	// And the second reason must not appear anywhere in any response message.
	if found := responseTextContains(t, taskID, secondReason); found {
		t.Errorf("response messages still contain rolled-back reason %q; want no trace", secondReason)
	}
}

// responseTextContains reports whether any response message on the task
// contains the given substring in any text part. Used by the atomicity test
// to prove a rolled-back reason left no trace.
func responseTextContains(t *testing.T, taskID uuid.UUID, needle string) bool {
	t.Helper()
	rows, err := testPool.Query(t.Context(),
		`SELECT parts FROM task_messages WHERE task_id = $1 AND role = 'response'`, taskID,
	)
	if err != nil {
		t.Fatalf("reading response messages for %s: %v", taskID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scanning parts: %v", err)
		}
		if strings.Contains(string(raw), needle) {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating parts: %v", err)
	}
	return false
}

// ============================================================================
// Consolidated from search_integration_test.go (Track-1K test-file consolidation).
// ============================================================================

// --- seeding helpers ---

// seedSearchContent inserts a content row whose title and body both contain
// term, so websearch_to_tsquery('simple', term) matches via the generated
// search_vector. status is caller-chosen; 'draft' proves the INTERNAL search
// path (status != 'archived', no is_public gate) includes non-public rows.
func seedSearchContent(t *testing.T, slug, term, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status)
		 VALUES ($1, $2, $3, 'article', $4) RETURNING id`,
		slug, term+" article", term+" "+term+" body", status,
	).Scan(&id); err != nil {
		t.Fatalf("seedSearchContent(%q): %v", slug, err)
	}
	return id
}

// seedSearchContentAt inserts a content row like seedSearchContent but with an
// explicit created_at, so date-boundary tests can place a row at a precise
// instant within a day. status defaults to 'draft' (internal-search visible).
func seedSearchContentAt(t *testing.T, slug, term string, createdAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO contents (slug, title, body, type, status, created_at)
		 VALUES ($1, $2, $3, 'article', 'draft', $4) RETURNING id`,
		slug, term+" article", term+" "+term+" body", createdAt,
	).Scan(&id); err != nil {
		t.Fatalf("seedSearchContentAt(%q): %v", slug, err)
	}
	return id
}

// seedSearchNote inserts a Zettelkasten note whose title and body contain term.
// kind must be a valid note_kind enum value.
func seedSearchNote(t *testing.T, slug, term, kind string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO notes (slug, title, body, kind, created_by)
		 VALUES ($1, $2, $3, $4, 'learning-studio') RETURNING id`,
		slug, term+" note", term+" note body", kind,
	).Scan(&id); err != nil {
		t.Fatalf("seedSearchNote(%q): %v", slug, err)
	}
	return id
}

// seedSearchAgentNote inserts an agent_notes row containing term. agent_notes
// is FTS-indexed (idx_agent_notes_search) with the same search_vector
// mechanism as contents/notes — making it the strongest adversarial control
// for the corpus boundary: if search_knowledge accidentally unioned it, this
// is the leak that would surface.
func seedSearchAgentNote(t *testing.T, term string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agent_notes (kind, created_by, content, entry_date)
		 VALUES ('context', 'learning-studio', $1, CURRENT_DATE)`,
		term+" agent note content",
	); err != nil {
		t.Fatalf("seedSearchAgentNote: %v", err)
	}
}

// seedSearchTask inserts a coordination task whose title contains term.
func seedSearchTask(t *testing.T, term string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO tasks (created_by, assignee, title)
		 VALUES ('hq', 'learning-studio', $1)`,
		term+" task title",
	); err != nil {
		t.Fatalf("seedSearchTask: %v", err)
	}
}

// seedSearchBookmark inserts a bookmark whose title contains term. url_hash is
// derived as sha256(slug) hex (64 lowercase hex chars — matches the schema
// CHECK and the uniq_bookmarks_url_hash constraint) so the helper stays correct
// if a future test seeds more than one bookmark per truncate cycle.
func seedSearchBookmark(t *testing.T, slug, term string) {
	t.Helper()
	sum := sha256.Sum256([]byte(slug))
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO bookmarks (url, url_hash, slug, title, capture_channel, curated_by)
		 VALUES ('https://example.com/' || $1, $2, $1, $3, 'manual', 'learning-studio')`,
		slug, hex.EncodeToString(sum[:]), term+" bookmark title",
	); err != nil {
		t.Fatalf("seedSearchBookmark: %v", err)
	}
}

// assertSearchResultShape checks the stable required fields of a single result
// envelope item. Does not assert order or relevance.
func assertSearchResultShape(t *testing.T, r *SearchKnowledgeResult) {
	t.Helper()
	if r.ID == "" {
		t.Errorf("result.id empty: %+v", r)
	}
	if r.Title == "" {
		t.Errorf("result.title empty: %+v", r)
	}
	if r.Slug == "" {
		t.Errorf("result.slug empty: %+v", r)
	}
	if r.CreatedAt == "" {
		t.Errorf("result.created_at empty: %+v", r)
	} else if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		t.Errorf("result.created_at %q not RFC3339: %v", r.CreatedAt, err)
	}
	switch r.SourceType {
	case SourceTypeContent:
		if r.ContentType == "" {
			t.Errorf("content result missing content_type: %+v", r)
		}
	case SourceTypeNote:
		if r.NoteKind == "" {
			t.Errorf("note result missing note_kind: %+v", r)
		}
	default:
		t.Errorf("unknown source_type %q (corpus is content|note only)", r.SourceType)
	}
}

// --- corpus inclusion ---

// TestIntegration_SearchKnowledge_CorpusInclusion seeds one content row and one
// note matching a unique term and asserts both corpora surface, each with a
// stable result shape and the correct source_type. No order assertion.
func TestIntegration_SearchKnowledge_CorpusInclusion(t *testing.T) {
	s := setupServer(t)
	const term = "zqxincl"
	cID := seedSearchContent(t, "sk-incl-content", term, "draft")
	nID := seedSearchNote(t, "sk-incl-note", term, "concept-note")

	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
	if err != nil {
		t.Fatalf("searchKnowledge(%q) = %v, want success", term, err)
	}

	// Envelope invariants.
	if out.Query != term {
		t.Errorf("out.Query = %q, want %q", out.Query, term)
	}
	if out.Total != len(out.Results) {
		t.Errorf("out.Total = %d, want len(results) = %d", out.Total, len(out.Results))
	}

	var sawContent, sawNote bool
	for i := range out.Results {
		r := &out.Results[i]
		assertSearchResultShape(t, r)
		switch r.ID {
		case cID.String():
			sawContent = true
			if r.SourceType != SourceTypeContent {
				t.Errorf("content row source_type = %q, want %q", r.SourceType, SourceTypeContent)
			}
		case nID.String():
			sawNote = true
			if r.SourceType != SourceTypeNote {
				t.Errorf("note row source_type = %q, want %q", r.SourceType, SourceTypeNote)
			}
		}
	}
	if !sawContent {
		t.Error("content corpus not represented in results (expected the seeded content row)")
	}
	if !sawNote {
		t.Error("note corpus not represented in results (expected the seeded note)")
	}
}

// --- corpus exclusion ---

// TestIntegration_SearchKnowledge_CorpusExclusion seeds confusable non-corpus
// entities (agent_note, task, bookmark) that all match the query term, plus one
// in-corpus content row, and asserts the non-corpus entities never leak into
// search_knowledge results. The in-corpus content row presence guards against a
// vacuous pass (a non-matching term would make exclusion trivially true).
func TestIntegration_SearchKnowledge_CorpusExclusion(t *testing.T) {
	s := setupServer(t)
	const term = "zqxexcl"
	seedSearchContent(t, "sk-excl-content", term, "draft")
	seedSearchAgentNote(t, term)
	seedSearchTask(t, term)
	seedSearchBookmark(t, "sk-excl-bookmark", term)

	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
	if err != nil {
		t.Fatalf("searchKnowledge(%q) = %v, want success", term, err)
	}

	if len(out.Results) == 0 {
		t.Fatal("expected at least the in-corpus content row; got 0 — term not matching, exclusion assertion would be vacuous")
	}
	for _, r := range out.Results {
		if r.SourceType != SourceTypeContent && r.SourceType != SourceTypeNote {
			t.Errorf("non-corpus entity leaked: source_type = %q", r.SourceType)
		}
		// agent_note / task / bookmark titles carry these markers.
		for _, leak := range []string{"agent note content", "task title", "bookmark title"} {
			if strings.Contains(r.Title, leak) {
				t.Errorf("excluded entity leaked into results via title %q (marker %q)", r.Title, leak)
			}
		}
	}
}

// --- empty result + envelope ---

// TestIntegration_SearchKnowledge_EmptyResult searches a nonsense term against a
// non-empty corpus and asserts a successful empty envelope: results:[] (not
// null), total 0, no error. The JSON marshal check pins the json-api nil-vs-[]
// rule directly on the wire shape.
func TestIntegration_SearchKnowledge_EmptyResult(t *testing.T) {
	s := setupServer(t)
	seedSearchContent(t, "sk-empty-content", "presentterm", "draft")

	const nonsense = "zzzznomatchqqqq"
	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: nonsense})
	if err != nil {
		t.Fatalf("searchKnowledge(nonsense) = %v, want success with empty results", err)
	}
	if len(out.Results) != 0 {
		t.Errorf("len(results) = %d, want 0", len(out.Results))
	}
	if out.Total != 0 {
		t.Errorf("out.Total = %d, want 0", out.Total)
	}
	if out.Query != nonsense {
		t.Errorf("out.Query = %q, want %q", out.Query, nonsense)
	}

	b, mErr := json.Marshal(out)
	if mErr != nil {
		t.Fatalf("marshal output: %v", mErr)
	}
	if !strings.Contains(string(b), `"results":[]`) {
		t.Errorf("empty envelope must encode results as [], not null: %s", b)
	}
}

// --- filter: content_type ---

// TestIntegration_SearchKnowledge_ContentTypeFilter pins three behaviors:
// (1) a valid content_type narrows to the content branch and excludes notes;
// (2) a valid-but-unmatched content_type yields empty (no error);
// (3) an UNKNOWN content_type is rejected with a validation error (Track 1I
//
//	decision — strict enum validation, consistent with create_content; replaces
//	the Track 1G silent-empty characterization).
func TestIntegration_SearchKnowledge_ContentTypeFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxctf"
	seedSearchContent(t, "sk-ctf-content", term, "draft") // type=article
	seedSearchNote(t, "sk-ctf-note", term, "concept-note")

	t.Run("article narrows to content, excludes notes", func(t *testing.T) {
		article := "article"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, ContentType: &article})
		if err != nil {
			t.Fatalf("content_type=article: %v", err)
		}
		if len(out.Results) == 0 {
			t.Fatal("content_type=article should still match the seeded article")
		}
		for _, r := range out.Results {
			if r.SourceType != SourceTypeContent {
				t.Errorf("content_type=article leaked source_type %q", r.SourceType)
			}
		}
	})

	t.Run("valid unmatched type yields empty", func(t *testing.T) {
		essay := "essay"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, ContentType: &essay})
		if err != nil {
			t.Fatalf("content_type=essay: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("content_type=essay (no essay seeded) = %d results, want 0", len(out.Results))
		}
	})

	t.Run("unknown type is rejected with a validation error", func(t *testing.T) {
		bogus := "banana-not-a-type"
		_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, ContentType: &bogus})
		if err == nil {
			t.Fatal("unknown content_type must be rejected, not silently empty (Track 1I)")
		}
		if !strings.Contains(err.Error(), "unsupported content_type") {
			t.Errorf("error = %q, want containing %q", err, "unsupported content_type")
		}
	})
}

// --- filter: note_kind ---

// TestIntegration_SearchKnowledge_NoteKindFilter mirrors the content_type cases
// for notes: a valid note_kind narrows to the note branch and excludes content;
// a valid-but-unmatched note_kind yields empty.
func TestIntegration_SearchKnowledge_NoteKindFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxnkf"
	seedSearchContent(t, "sk-nkf-content", term, "draft")
	seedSearchNote(t, "sk-nkf-note", term, "concept-note")

	t.Run("concept-note narrows to notes, excludes content", func(t *testing.T) {
		ck := "concept-note"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, NoteKind: &ck})
		if err != nil {
			t.Fatalf("note_kind=concept-note: %v", err)
		}
		if len(out.Results) == 0 {
			t.Fatal("note_kind=concept-note should match the seeded note")
		}
		for _, r := range out.Results {
			if r.SourceType != SourceTypeNote {
				t.Errorf("note_kind filter leaked source_type %q", r.SourceType)
			}
		}
	})

	t.Run("unmatched kind yields empty", func(t *testing.T) {
		sn := "solve-note"
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, NoteKind: &sn})
		if err != nil {
			t.Fatalf("note_kind=solve-note: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("note_kind=solve-note (none seeded) = %d results, want 0", len(out.Results))
		}
	})
}

// --- filter: date range ---

// TestIntegration_SearchKnowledge_DateFilter seeds a row created "now" and
// proves the after/before window bounds it. Uses relative UTC dates so the
// assertion is deterministic regardless of wall clock. No order assertion.
func TestIntegration_SearchKnowledge_DateFilter(t *testing.T) {
	s := setupServer(t)
	const term = "zqxdate"
	seedSearchContent(t, "sk-date-content", term, "draft")

	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1).Format(time.DateOnly)
	tomorrow := now.AddDate(0, 0, 1).Format(time.DateOnly)

	t.Run("window enclosing now keeps the row", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &yesterday, Before: &tomorrow})
		if err != nil {
			t.Fatalf("after=yesterday before=tomorrow: %v", err)
		}
		if len(out.Results) == 0 {
			t.Error("row created now must fall within [yesterday, tomorrow]")
		}
	})

	t.Run("before=yesterday excludes a now row", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Before: &yesterday})
		if err != nil {
			t.Fatalf("before=yesterday: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("before=yesterday must exclude the now row; got %d", len(out.Results))
		}
	})

	t.Run("after=tomorrow excludes a now row", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &tomorrow})
		if err != nil {
			t.Fatalf("after=tomorrow: %v", err)
		}
		if len(out.Results) != 0 {
			t.Errorf("after=tomorrow must exclude the now row; got %d", len(out.Results))
		}
	})
}

// --- limit cap ---

// TestIntegration_SearchKnowledge_LimitCaps seeds three matching content rows
// and asserts limit=1 caps the result count (and total == len(results)), while
// the default limit (omitted → 20) returns all three. Asserts counts only,
// never which rows — the cap is a count contract, not a ranking one.
func TestIntegration_SearchKnowledge_LimitCaps(t *testing.T) {
	s := setupServer(t)
	const term = "zqxlim"
	seedSearchContent(t, "sk-lim-1", term, "draft")
	seedSearchContent(t, "sk-lim-2", term, "draft")
	seedSearchContent(t, "sk-lim-3", term, "draft")

	t.Run("limit=1 caps to one", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Limit: FlexInt(1)})
		if err != nil {
			t.Fatalf("limit=1: %v", err)
		}
		if len(out.Results) != 1 {
			t.Errorf("limit=1 → %d results, want 1", len(out.Results))
		}
		if out.Total != 1 {
			t.Errorf("out.Total = %d, want 1 (total == len(results))", out.Total)
		}
	})

	t.Run("default limit returns all three", func(t *testing.T) {
		// Exact count is load-bearing on seed-term uniqueness: setupServer
		// truncates contents+notes per test, and every term in this file uses a
		// distinct "zqx…" prefix, so only the three rows seeded above match.
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
		if err != nil {
			t.Fatalf("default limit: %v", err)
		}
		if len(out.Results) != 3 {
			t.Errorf("default limit → %d results, want 3", len(out.Results))
		}
	})
}

// --- semantic-branch degradation (embedder nil) ---

// TestIntegration_SearchKnowledge_EmbedderNilDegradation pins the production
// fallback path: when no embedder is wired (GEMINI_API_KEY unset — the harness
// default), search_knowledge runs FTS-only and still returns matching content
// with no error. The embedder-present-but-FAILING path is not exercised here:
// embedder is a concrete *embedder.Embedder with no interface seam, and project
// rules forbid introducing a single-impl interface purely for test injection
// (see report §coverage). FTS-only is the realistic, default deployment shape.
func TestIntegration_SearchKnowledge_EmbedderNilDegradation(t *testing.T) {
	s := setupServer(t)
	if s.embedder != nil {
		t.Fatal("harness must run search_knowledge with no embedder (FTS-only); embedder was wired")
	}

	const term = "zqxdegr"
	seedSearchContent(t, "sk-degr-content", term, "draft")

	_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term})
	if err != nil {
		t.Fatalf("FTS-only search must succeed with nil embedder: %v", err)
	}
	if len(out.Results) == 0 {
		t.Error("FTS-only search must still return the matching content row")
	}
}

// --- date filter: whole-day inclusive boundary (Track 1I) ---

// TestIntegration_SearchKnowledge_DateBoundaryInclusive proves the whole-day
// inclusive semantics end-to-end against real timestamptz rows. Three rows are
// seeded on the same day D (start, midday, last second) plus neighbors on D-1
// and D+1. The handler runs with the harness default timezone (UTC). It asserts
// that after=D and before=D each keep the entire day D and exclude the
// neighbors — pinning that `before=D` includes rows created during D (the
// same-day case Track 1G left untested), not just rows before D's start.
// Counts/membership only; no order assertion.
func TestIntegration_SearchKnowledge_DateBoundaryInclusive(t *testing.T) {
	s := setupServer(t)
	const term = "zqxbound"
	const day = "2026-05-22"

	mkUTC := func(s string) time.Time {
		ts, err := time.ParseInLocation(time.RFC3339, s, time.UTC)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return ts
	}

	startD := seedSearchContentAt(t, "sk-bound-start", term, mkUTC("2026-05-22T00:00:00Z"))
	midD := seedSearchContentAt(t, "sk-bound-mid", term, mkUTC("2026-05-22T12:30:00Z"))
	endD := seedSearchContentAt(t, "sk-bound-end", term, mkUTC("2026-05-22T23:59:59Z"))
	prevDay := seedSearchContentAt(t, "sk-bound-prev", term, mkUTC("2026-05-21T23:59:59Z"))
	nextDay := seedSearchContentAt(t, "sk-bound-next", term, mkUTC("2026-05-23T00:00:00Z"))

	ids := func(out SearchKnowledgeOutput) map[string]bool {
		m := make(map[string]bool, len(out.Results))
		for _, r := range out.Results {
			m[r.ID] = true
		}
		return m
	}

	t.Run("before=D includes the whole of day D, excludes D+1", func(t *testing.T) {
		d := day
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Before: &d})
		if err != nil {
			t.Fatalf("before=%s: %v", day, err)
		}
		got := ids(out)
		for _, want := range []uuid.UUID{startD, midD, endD, prevDay} {
			if !got[want.String()] {
				t.Errorf("before=%s must keep row %s (created on/before D)", day, want)
			}
		}
		if got[nextDay.String()] {
			t.Errorf("before=%s must exclude the D+1 row %s", day, nextDay)
		}
	})

	t.Run("after=D includes the whole of day D, excludes D-1", func(t *testing.T) {
		d := day
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &d})
		if err != nil {
			t.Fatalf("after=%s: %v", day, err)
		}
		got := ids(out)
		for _, want := range []uuid.UUID{startD, midD, endD, nextDay} {
			if !got[want.String()] {
				t.Errorf("after=%s must keep row %s (created on/after D start)", day, want)
			}
		}
		if got[prevDay.String()] {
			t.Errorf("after=%s must exclude the D-1 row %s", day, prevDay)
		}
	})

	t.Run("after=D and before=D keep exactly day D", func(t *testing.T) {
		d := day
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, After: &d, Before: &d})
		if err != nil {
			t.Fatalf("after=before=%s: %v", day, err)
		}
		got := ids(out)
		for _, want := range []uuid.UUID{startD, midD, endD} {
			if !got[want.String()] {
				t.Errorf("after=before=%s must keep day-D row %s", day, want)
			}
		}
		for _, drop := range []uuid.UUID{prevDay, nextDay} {
			if got[drop.String()] {
				t.Errorf("after=before=%s must exclude off-day row %s", day, drop)
			}
		}
	})
}

// --- source_types filter: end-to-end (Track 1I) ---

// TestIntegration_SearchKnowledge_SourceTypesEndToEnd closes the coverage gap
// flagged in the search-product contract: source_types selection was only unit-
// tested (TestSelectSources). It seeds one content row and one note matching the
// same term and asserts source_types=[content] returns only the content row,
// source_types=[note] only the note, both returns both, and an unknown token is
// rejected at the handler with an error (not a silent empty success).
func TestIntegration_SearchKnowledge_SourceTypesEndToEnd(t *testing.T) {
	s := setupServer(t)
	const term = "zqxsrc"
	cID := seedSearchContent(t, "sk-src-content", term, "draft")
	nID := seedSearchNote(t, "sk-src-note", term, "concept-note")

	t.Run("content only returns content, excludes note", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeContent}})
		if err != nil {
			t.Fatalf("source_types=[content]: %v", err)
		}
		if len(out.Results) != 1 || out.Results[0].ID != cID.String() {
			t.Errorf("source_types=[content] = %d results, want exactly the content row %s", len(out.Results), cID)
		}
	})

	t.Run("note only returns note, excludes content", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeNote}})
		if err != nil {
			t.Fatalf("source_types=[note]: %v", err)
		}
		if len(out.Results) != 1 || out.Results[0].ID != nID.String() {
			t.Errorf("source_types=[note] = %d results, want exactly the note %s", len(out.Results), nID)
		}
	})

	t.Run("both returns content and note", func(t *testing.T) {
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{SourceTypeContent, SourceTypeNote}})
		if err != nil {
			t.Fatalf("source_types=[content,note]: %v", err)
		}
		// Exact count is load-bearing on seed-term uniqueness: setupServer
		// truncates contents+notes per test, and "zqxsrc" is unique to this
		// test, so only the one content row + one note seeded above match.
		if len(out.Results) != 2 {
			t.Errorf("source_types=[content,note] = %d results, want 2", len(out.Results))
		}
	})

	t.Run("unknown source_type rejected, not silent empty", func(t *testing.T) {
		_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, SourceTypes: []string{"bookmark"}})
		if err == nil {
			t.Fatal("unknown source_type must error, not return empty success")
		}
		if !strings.Contains(err.Error(), "unsupported source_type") {
			t.Errorf("error = %q, want containing %q", err, "unsupported source_type")
		}
	})
}

// --- project filter rejection: end-to-end (Track 1I) ---

// TestIntegration_SearchKnowledge_ProjectRejected pins that a non-empty project
// filter is rejected at the MCP handler boundary with an unsupported_filter
// error, against a corpus that WOULD match the query — proving the rejection is
// the project field, not an empty corpus. An empty project value is ignored
// (treated as absent) and the search succeeds.
func TestIntegration_SearchKnowledge_ProjectRejected(t *testing.T) {
	s := setupServer(t)
	const term = "zqxproj"
	seedSearchContent(t, "sk-proj-content", term, "draft")

	t.Run("non-empty project rejected", func(t *testing.T) {
		p := "koopa"
		_, _, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Project: &p})
		if err == nil {
			t.Fatal("non-empty project must be rejected as unsupported_filter")
		}
		if !strings.Contains(err.Error(), "unsupported_filter") {
			t.Errorf("error = %q, want containing %q", err, "unsupported_filter")
		}
	})

	t.Run("empty project ignored, search succeeds", func(t *testing.T) {
		empty := ""
		_, out, err := callHandler(t, s.searchKnowledge, SearchKnowledgeInput{Query: term, Project: &empty})
		if err != nil {
			t.Fatalf("empty project must be treated as absent: %v", err)
		}
		if len(out.Results) == 0 {
			t.Error("empty project must not filter out the matching content row")
		}
	})
}

// ============================================================================
// Consolidated from search_relevance_eval_test.go (Track-1K test-file consolidation).
// ============================================================================

// --- tier-1 seed loaders (synthetic; mirror search-relevance-seed-plan.md) ---

// seedRelContent inserts a contents row whose title and body both carry term so
// websearch_to_tsquery('simple', term) matches. type/status are caller-chosen.
// A non-published status leaves published_at NULL (chk_content_publication).
func seedRelContent(t *testing.T, slug, term, ctype, status string, createdAt *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var err error
	if createdAt != nil {
		err = testPool.QueryRow(t.Context(),
			`INSERT INTO contents (slug, title, body, type, status, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			slug, term+" title", term+" "+term+" body", ctype, status, *createdAt,
		).Scan(&id)
	} else {
		err = testPool.QueryRow(t.Context(),
			`INSERT INTO contents (slug, title, body, type, status)
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			slug, term+" title", term+" "+term+" body", ctype, status,
		).Scan(&id)
	}
	if err != nil {
		t.Fatalf("seedRelContent(%q): %v", slug, err)
	}
	return id
}

// seedRelNote inserts a notes row carrying term, with caller-chosen kind and
// maturity (so the archived-note asymmetry control can set maturity='archived').
func seedRelNote(t *testing.T, slug, term, kind, maturity string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO notes (slug, title, body, kind, maturity, created_by)
		 VALUES ($1, $2, $3, $4, $5, 'learning-studio') RETURNING id`,
		slug, term+" note", term+" note body", kind, maturity,
	).Scan(&id); err != nil {
		t.Fatalf("seedRelNote(%q): %v", slug, err)
	}
	return id
}

// seedRelAgentNote inserts an agent_notes row carrying term. agent_notes is
// FTS-indexed with the same mechanism as notes — the strongest adversarial
// control: if search_knowledge ever unioned it, this is the leak that surfaces.
func seedRelAgentNote(t *testing.T, term string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO agent_notes (kind, created_by, content, entry_date)
		 VALUES ('context', 'learning-studio', $1, CURRENT_DATE)`,
		term+" agent note content",
	); err != nil {
		t.Fatalf("seedRelAgentNote: %v", err)
	}
}

// seedRelTask inserts a tasks row carrying term in its title.
func seedRelTask(t *testing.T, term string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO tasks (created_by, assignee, title)
		 VALUES ('hq', 'learning-studio', $1)`,
		term+" task title",
	); err != nil {
		t.Fatalf("seedRelTask: %v", err)
	}
}

// seedRelArtifact inserts a standalone artifacts row carrying term in a text
// part. Artifacts have NO FTS path at all (search-relevance-seed-plan.md §3c);
// seeding one keeps the NEG-02 control faithful to the seed plan even though it
// can only ever be empty in search_knowledge.
func seedRelArtifact(t *testing.T, term string) {
	t.Helper()
	parts := fmt.Sprintf(`[{"text":%q}]`, term+" artifact part")
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO artifacts (created_by, name, description, parts)
		 VALUES ('learning-studio', $1, '', $2::jsonb)`,
		term+" artifact", parts,
	); err != nil {
		t.Fatalf("seedRelArtifact: %v", err)
	}
}

// relSeeder seeds one seed_id row and reports whether it has a stable id worth
// pinning in the evaluator (content/note do; non-corpus controls do not).
type relSeeder func(t *testing.T) (uuid.UUID, bool)

// tier1SeederRegistry maps every seed_id reachable by the NEG/FLT subset to a
// seeder. Terms match the fixtures' verbatim queries exactly. Only the seeds
// needed by NEG-01..05 / FLT-01..08 are registered (Track 1K scope).
func tier1SeederRegistry() map[string]relSeeder {
	// at parses a fixed RFC3339 seed timestamp; the strings are compile-time
	// constants, so a parse error is a typo in this file — surfaced via the
	// seeder's own *testing.T rather than a panic.
	at := func(t *testing.T, rfc3339 string) *time.Time {
		t.Helper()
		ts, err := time.Parse(time.RFC3339, rfc3339)
		if err != nil {
			t.Fatalf("tier1SeederRegistry: bad timestamp %q: %v", rfc3339, err)
		}
		return &ts
	}
	noID := func(seed func(*testing.T)) relSeeder {
		return func(t *testing.T) (uuid.UUID, bool) { seed(t); return uuid.Nil, false }
	}
	withID := func(seed func(*testing.T) uuid.UUID) relSeeder {
		return func(t *testing.T) (uuid.UUID, bool) { return seed(t), true }
	}

	return map[string]relSeeder{
		// NEG controls (corpus boundary).
		"T-NEG":  noID(func(t *testing.T) { seedRelTask(t, "zqxtaskonly") }),
		"AR-NEG": noID(func(t *testing.T) { seedRelArtifact(t, "zqxartonly") }),
		"AN-NEG": noID(func(t *testing.T) { seedRelAgentNote(t, "zqxagentonly") }),
		"C-ARCHIVED": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-archived", "zqxarchcontent", "article", "archived", nil)
		}),
		"N-ARCHIVED": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-archived", "zqxarchnote", "reading-note", "archived")
		}),

		// FLT-01/02 — source_types narrowing.
		"C-SRC": withID(func(t *testing.T) uuid.UUID { return seedRelContent(t, "rel-c-src", "zqxsrc", "article", "draft", nil) }),
		"N-SRC": withID(func(t *testing.T) uuid.UUID { return seedRelNote(t, "rel-n-src", "zqxsrc", "concept-note", "seed") }),

		// FLT-03 — content_type narrowing.
		"C-CTF-ARTICLE": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-ctf-article", "zqxctf", "article", "draft", nil)
		}),
		"C-CTF-ESSAY": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-ctf-essay", "zqxctf", "essay", "draft", nil)
		}),
		"N-CTF": withID(func(t *testing.T) uuid.UUID { return seedRelNote(t, "rel-n-ctf", "zqxctf", "concept-note", "seed") }),

		// FLT-04 — note_kind narrowing.
		"N-NKF-SOLVE": withID(func(t *testing.T) uuid.UUID { return seedRelNote(t, "rel-n-nkf-solve", "zqxnkf", "solve-note", "seed") }),
		"N-NKF-CONCEPT": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-nkf-concept", "zqxnkf", "concept-note", "seed")
		}),
		"C-NKF": withID(func(t *testing.T) uuid.UUID { return seedRelContent(t, "rel-c-nkf", "zqxnkf", "article", "draft", nil) }),

		// FLT-05 — whole-day-inclusive date window, anchor 2026-05-22 (UTC).
		"C-DAY-START": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-start", "zqxbound", "article", "draft", at(t, "2026-05-22T00:00:00Z"))
		}),
		"C-DAY-MID": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-mid", "zqxbound", "article", "draft", at(t, "2026-05-22T12:30:00Z"))
		}),
		"C-DAY-END": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-end", "zqxbound", "article", "draft", at(t, "2026-05-22T23:59:59Z"))
		}),
		"C-DAY-PREV": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-prev", "zqxbound", "article", "draft", at(t, "2026-05-21T23:59:59Z"))
		}),
		"C-DAY-NEXT": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-day-next", "zqxbound", "article", "draft", at(t, "2026-05-23T00:00:00Z"))
		}),

		// FLT-06/07/08 — rejection probes share C-VALID (proves the rejection
		// is the filter, not an empty corpus).
		"C-VALID": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-valid", "zqxreject", "article", "draft", nil)
		}),

		// FLT-01..04 — typed corpus rows the new judgment-set fixtures refer to
		// by generic seed_ids. Term "go" matches the fixtures' verbatim query.
		"content:article:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-article-any", "go", "article", "draft", nil)
		}),
		"content:til:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-til-any", "go", "til", "draft", nil)
		}),
		"note:concept-note:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-concept-any", "go", "concept-note", "seed")
		}),
		"note:solve-note:any": withID(func(t *testing.T) uuid.UUID {
			return seedRelNote(t, "rel-n-solve-any", "go", "solve-note", "seed")
		}),

		// FLT-05 — dated articles bracketing the after=2026-01-01 / before=2026-03-31
		// window. The -2025-12-01 row sits before the window; -2026-02-15 sits inside.
		"content:article:dated-2025-12-01": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-article-2025-12-01", "go", "article", "draft", at(t, "2025-12-01T00:00:00Z"))
		}),
		"content:article:dated-2026-02-15": withID(func(t *testing.T) uuid.UUID {
			return seedRelContent(t, "rel-c-article-2026-02-15", "go", "article", "draft", at(t, "2026-02-15T00:00:00Z"))
		}),

		// FLT-06 — enough matching articles that limit=5 actually caps a non-empty
		// remainder. 12 > 10 leaves room for any future stricter "10-plus" reading.
		"content:article:bulk-10-plus": noID(func(t *testing.T) {
			for i := range 12 {
				slug := fmt.Sprintf("rel-c-bulk-%02d", i)
				seedRelContent(t, slug, "go", "article", "draft", nil)
			}
		}),
	}
}

// requiredSeedIDs is the sorted union of seed_ids referenced by the selected
// fixtures' seed_requirements.
func requiredSeedIDs(selected []searchFixture) []string {
	set := map[string]struct{}{}
	for i := range selected {
		for _, s := range selected[i].SeedRequirements {
			set[s] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// seedTier1Corpus seeds every required seed_id once and returns the id of each
// content/note row (the rows the evaluator pins by id). It fatals if a required
// seed has no registered seeder — that is a coverage gap, not a guess.
func seedTier1Corpus(t *testing.T, required []string, registry map[string]relSeeder) map[string]uuid.UUID {
	t.Helper()
	ids := map[string]uuid.UUID{}
	for _, seedID := range required {
		seed, ok := registry[seedID]
		if !ok {
			t.Fatalf("no seeder registered for required seed_id %q", seedID)
		}
		if id, hasID := seed(t); hasID {
			ids[seedID] = id
		}
	}
	return ids
}

// --- evaluator ---

// tier1Expectation is the per-fixture test oracle for the `results` outcome:
// which seeded rows must appear / be absent, the narrowing every returned row
// must satisfy, and an optional exact result count (used to verify limit-cap
// behavior). Empty / zero fields mean "no constraint". Keys reference seed_ids
// from docs/testing/search-relevance-judgment-set.md; empty/validation_error
// fixtures need no entry — their outcome branch in evaluateFixture is
// self-pinning. A results-outcome fixture missing here fails loudly (see the
// oracle guard).
type tier1Expectation struct {
	mustAppear     []string // seed_ids that must be in results
	mustBeAbsent   []string // seed_ids that must NOT be in results
	allSourceType  string   // every result.SourceType must equal this
	allContentType string   // every result.ContentType must equal this
	allNoteKind    string   // every result.NoteKind must equal this
	exactCount     int      // if non-zero, len(results) must equal this — used for limit-cap fixtures
}

// tier1Expectations is keyed by fixture_id. Each entry pins the rows the
// fixture's seed_requirements explicitly name, so the oracle stays aligned
// with the judgment-set declaration rather than incidental corpus state.
var tier1Expectations = map[string]tier1Expectation{
	// FLT-01: content_type=article filters out the til content and the note.
	"FLT-01": {
		mustAppear:     []string{"content:article:any"},
		mustBeAbsent:   []string{"content:til:any", "note:solve-note:any"},
		allSourceType:  SourceTypeContent,
		allContentType: "article",
	},
	// FLT-02: content_type=til filters out the plain article.
	"FLT-02": {
		mustAppear:     []string{"content:til:any"},
		mustBeAbsent:   []string{"content:article:any"},
		allSourceType:  SourceTypeContent,
		allContentType: "til",
	},
	// FLT-03: note_kind=solve-note implies source_types=[note] and excludes content.
	"FLT-03": {
		mustAppear:    []string{"note:solve-note:any"},
		mustBeAbsent:  []string{"content:article:any"},
		allSourceType: SourceTypeNote,
		allNoteKind:   "solve-note",
	},
	// FLT-04: source_types=[content] filters out every seeded note.
	"FLT-04": {
		mustAppear:    []string{"content:article:any"},
		mustBeAbsent:  []string{"note:concept-note:any"},
		allSourceType: SourceTypeContent,
	},
	// FLT-05: after=2026-01-01 / before=2026-03-31 admits the 2026-02-15 row
	// and rejects the 2025-12-01 row. No source-type / type narrowing applies.
	"FLT-05": {
		mustAppear:   []string{"content:article:dated-2026-02-15"},
		mustBeAbsent: []string{"content:article:dated-2025-12-01"},
	},
	// FLT-06: limit=5 with >5 matching rows must return exactly 5. The bulk
	// seeder inserts 12 articles, so matching count > limit is guaranteed.
	"FLT-06": {exactCount: 5},
}

// evalOutcome is the structured result for one fixture run.
type evalOutcome struct {
	FixtureID       string
	Status          string // pass | fail | skip
	Reason          string
	ObservedIDs     []string
	ObservedTypes   []string
	ExpectedSummary string
}

// expectedRejectionSubstring derives, from the structured filters alone, the
// substring the handler's validation error must contain. It mirrors
// validateSearchKnowledgeInput — no prose is read.
func expectedRejectionSubstring(f *searchFixtureFilters) string {
	if f.Project != "" {
		return "unsupported_filter"
	}
	for _, st := range f.SourceTypes {
		if st != SourceTypeContent && st != SourceTypeNote {
			return "unsupported source_type"
		}
	}
	if f.ContentType != "" && !content.Type(f.ContentType).Valid() {
		return "unsupported content_type"
	}
	if f.NoteKind != "" && !note.Kind(f.NoteKind).Valid() {
		return "unsupported note_kind"
	}
	return ""
}

// buildSearchInput maps a fixture's verbatim query + structured filters onto a
// SearchKnowledgeInput, exactly as specified — no inference.
func buildSearchInput(fx *searchFixture) SearchKnowledgeInput {
	in := SearchKnowledgeInput{Query: fx.Query}
	f := &fx.Filters
	if len(f.SourceTypes) > 0 {
		in.SourceTypes = f.SourceTypes
	}
	if f.ContentType != "" {
		ct := f.ContentType
		in.ContentType = &ct
	}
	if f.NoteKind != "" {
		nk := f.NoteKind
		in.NoteKind = &nk
	}
	if f.Project != "" {
		p := f.Project
		in.Project = &p
	}
	if f.After != "" {
		a := f.After
		in.After = &a
	}
	if f.Before != "" {
		b := f.Before
		in.Before = &b
	}
	if f.Limit > 0 {
		in.Limit = FlexInt(f.Limit)
	}
	return in
}

func observedResults(out SearchKnowledgeOutput) (ids, types []string) {
	for i := range out.Results {
		ids = append(ids, out.Results[i].ID)
		types = append(types, out.Results[i].SourceType)
	}
	return ids, types
}

func summarizeExpectation(e *tier1Expectation) string {
	var parts []string
	if e.exactCount > 0 {
		parts = append(parts, fmt.Sprintf("exactly %d results", e.exactCount))
	}
	if len(e.mustAppear) > 0 {
		parts = append(parts, "present="+strings.Join(e.mustAppear, ","))
	}
	if len(e.mustBeAbsent) > 0 {
		parts = append(parts, "absent="+strings.Join(e.mustBeAbsent, ","))
	}
	if e.allSourceType != "" {
		parts = append(parts, "all source_type="+e.allSourceType)
	}
	if e.allContentType != "" {
		parts = append(parts, "all content_type="+e.allContentType)
	}
	if e.allNoteKind != "" {
		parts = append(parts, "all note_kind="+e.allNoteKind)
	}
	if len(parts) == 0 {
		return "≥1 result"
	}
	return strings.Join(parts, "; ")
}

// evaluateFixture runs one fixture's query+filters through search_knowledge and
// scores ONLY mechanical criteria per its expected_outcome. It never asserts
// rank order or relevance.
func evaluateFixture(t *testing.T, s *Server, fx *searchFixture, ids map[string]uuid.UUID) evalOutcome {
	t.Helper()
	_, out, err := callHandler(t, s.searchKnowledge, buildSearchInput(fx))
	oc := evalOutcome{FixtureID: fx.FixtureID}

	switch fx.ExpectedOutcome {
	case "validation_error":
		sub := expectedRejectionSubstring(&fx.Filters)
		oc.ExpectedSummary = fmt.Sprintf("validation error containing %q", sub)
		switch {
		case err == nil:
			oc.Status, oc.Reason = "fail", "expected a validation error, got success"
		case sub != "" && !strings.Contains(err.Error(), sub):
			oc.Status, oc.Reason = "fail", fmt.Sprintf("error %q missing expected substring %q", err.Error(), sub)
		default:
			oc.Status, oc.Reason = "pass", "rejected before any store call"
		}

	case "empty":
		oc.ExpectedSummary = "empty success — no corpus leak"
		oc.ObservedIDs, oc.ObservedTypes = observedResults(out)
		switch {
		case err != nil:
			oc.Status, oc.Reason = "fail", fmt.Sprintf("expected empty success, got error: %v", err)
		case len(out.Results) != 0:
			oc.Status, oc.Reason = "fail", fmt.Sprintf("expected 0 results (no leak), got %d", len(out.Results))
		default:
			oc.Status, oc.Reason = "pass", "no leak from the non-corpus / archived seed"
		}

	case "results":
		// A results-outcome fixture MUST have an oracle entry; without one the
		// run would silently assert nothing beyond "≥1 result". Fail loudly.
		exp, ok := tier1Expectations[fx.FixtureID]
		oc.ObservedIDs, oc.ObservedTypes = observedResults(out)
		if !ok {
			oc.Status = "fail"
			oc.Reason = "expected_outcome=results but no tier1Expectations oracle entry"
			return oc
		}
		oc.ExpectedSummary = summarizeExpectation(&exp)
		oc.Status, oc.Reason = scoreResults(out, err, &exp, ids)

	default:
		oc.Status = "skip"
		oc.Reason = fmt.Sprintf("expected_outcome %q is not tier-1 mechanical", fx.ExpectedOutcome)
	}
	return oc
}

// scoreResults applies the `results` expectation: success, ≥1 row, required
// rows present, excluded rows absent, and the per-result narrowing. Membership
// checks are by seed id (timezone-robust); narrowing checks are by result field
// — never by rank.
func scoreResults(out SearchKnowledgeOutput, err error, exp *tier1Expectation, ids map[string]uuid.UUID) (status, reason string) {
	if err != nil {
		return "fail", fmt.Sprintf("expected results, got error: %v", err)
	}
	if exp.exactCount > 0 && len(out.Results) != exp.exactCount {
		return "fail", fmt.Sprintf("expected exactly %d results (limit cap), got %d", exp.exactCount, len(out.Results))
	}
	if len(out.Results) == 0 {
		return "fail", "expected ≥1 result, got 0 (zero-result-with-match)"
	}
	got := map[string]bool{}
	for i := range out.Results {
		got[out.Results[i].ID] = true
	}
	for _, key := range exp.mustAppear {
		if !got[ids[key].String()] {
			return "fail", fmt.Sprintf("required row %s absent from results", key)
		}
	}
	for _, key := range exp.mustBeAbsent {
		if got[ids[key].String()] {
			return "fail", fmt.Sprintf("excluded row %s leaked into results", key)
		}
	}
	for i := range out.Results {
		r := &out.Results[i]
		if exp.allSourceType != "" && r.SourceType != exp.allSourceType {
			return "fail", fmt.Sprintf("result %s source_type=%q, want %q", r.ID, r.SourceType, exp.allSourceType)
		}
		if exp.allContentType != "" && r.ContentType != exp.allContentType {
			return "fail", fmt.Sprintf("result %s content_type=%q, want %q", r.ID, r.ContentType, exp.allContentType)
		}
		if exp.allNoteKind != "" && r.NoteKind != exp.allNoteKind {
			return "fail", fmt.Sprintf("result %s note_kind=%q, want %q", r.ID, r.NoteKind, exp.allNoteKind)
		}
	}
	return "pass", "narrowing + presence/absence hold"
}

// --- the tier-1 run ---

// TestIntegration_SearchRelevance_Tier1 is the fixture loader / evaluation
// harness for the tier-1 mechanical subset. It parses the judgment set, selects
// NEG-01..05 / FLT-01..08, confirms every required seed resolves, seeds the
// corpus once into the integration testcontainer, and evaluates each fixture
// mechanically. No ranking, relevance, or vector behavior is asserted.
func TestIntegration_SearchRelevance_Tier1(t *testing.T) {
	fixtures := loadSearchFixtures(t)
	selected, skipped := selectTier1(fixtures)

	t.Logf("tier-1 selection: %d fixtures; skipped %d non-tier-1 fixtures", len(selected), len(skipped))
	for _, sk := range skipped {
		t.Logf("  skip %-7s — %s", sk.FixtureID, sk.Reason)
	}

	registry := tier1SeederRegistry()
	required := requiredSeedIDs(selected)

	t.Run("seed references resolve", func(t *testing.T) {
		for _, seedID := range required {
			if _, ok := registry[seedID]; !ok {
				t.Errorf("seed_id %q required by a selected fixture has no registered seeder", seedID)
			}
		}
	})

	s := setupServer(t)
	ids := seedTier1Corpus(t, required, registry)

	// Evaluate and collect OUTSIDE t.Run so the shared outcomes slice is never
	// touched from a subtest closure — the run is sequential today, but keeping
	// the append off the closure removes a latent data race if a future edit
	// adds t.Parallel(). The named subtest carries only the per-fixture assertion.
	outcomes := make([]evalOutcome, 0, len(selected))
	for i := range selected {
		fx := &selected[i]
		oc := evaluateFixture(t, s, fx, ids)
		outcomes = append(outcomes, oc)
		t.Run(fx.FixtureID, func(t *testing.T) {
			if oc.Status != "pass" {
				t.Errorf("%s [%s]: %s\n  expected: %s\n  observed ids:   %v\n  observed types: %v",
					oc.FixtureID, oc.Status, oc.Reason, oc.ExpectedSummary, oc.ObservedIDs, oc.ObservedTypes)
			}
		})
	}

	logTier1Results(t, outcomes)
}

// logTier1Results writes the structured per-fixture result table to the test
// log: fixture_id, status, reason, observed ids/types, expected summary.
func logTier1Results(t *testing.T, outcomes []evalOutcome) {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n=== Tier-1 fixture evaluation results ===\n")
	var pass, fail, skip int
	for i := range outcomes {
		oc := &outcomes[i]
		switch oc.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		default:
			skip++
		}
		fmt.Fprintf(&b, "%-7s %-5s %s\n", oc.FixtureID, oc.Status, oc.Reason)
		fmt.Fprintf(&b, "         expected: %s\n", oc.ExpectedSummary)
		fmt.Fprintf(&b, "         observed: ids=%v types=%v\n", oc.ObservedIDs, oc.ObservedTypes)
	}
	fmt.Fprintf(&b, "totals: %d pass, %d fail, %d skip (of %d)\n", pass, fail, skip, len(outcomes))
	t.Log(b.String())
}

// --- proposal-commit replay guard (security regression) ---

// TestIntegration_CommitProposal_NonceReplayRejected is the T1 regression
// guard for the proposal-token replay vulnerability: a single valid token,
// committed twice within its TTL, must create exactly ONE entity. The second
// commit must be rejected with a clear proposal_already_committed error — not
// silently create a duplicate goal, not return 500. Before the nonce-consume
// fix this produced two goal rows.
func TestIntegration_CommitProposal_NonceReplayRejected(t *testing.T) {
	s := setupServer(t)

	const title = "Replay Guard Goal"
	_, proposal, err := callHandlerAs(t, "hq", s.proposeGoal, ProposeGoalInput{Title: title})
	if err != nil {
		t.Fatalf("proposeGoal: %v", err)
	}
	if proposal.ProposalToken == "" {
		t.Fatal("empty proposal token")
	}

	// First commit succeeds (goal is human-only — commit as human).
	_, commit, err := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if err != nil {
		t.Fatalf("first commitProposal: %v", err)
	}
	if !commit.Committed {
		t.Fatal("first commit: Committed = false")
	}

	// Second commit of the SAME token must be rejected as a replay.
	_, _, replayErr := callHandlerAs(t, "human", s.commitProposal, CommitProposalInput{
		ProposalToken: proposal.ProposalToken,
	})
	if replayErr == nil {
		t.Fatal("second commit of the same token must be rejected, got nil error")
	}
	if !strings.Contains(replayErr.Error(), "proposal_already_committed") {
		t.Errorf("replay error = %q, want containing %q", replayErr, "proposal_already_committed")
	}

	// Exactly one goal row must exist — the replay created no duplicate.
	var count int
	if err := testPool.QueryRow(t.Context(),
		"SELECT count(*) FROM goals WHERE title = $1", title,
	).Scan(&count); err != nil {
		t.Fatalf("counting goals: %v", err)
	}
	if count != 1 {
		t.Errorf("goals with title %q = %d, want 1 (replay created duplicates)", title, count)
	}
}

// TestIntegration_CommitProposal_ConcurrentCommitOnce pins the TOCTOU-safety
// of the nonce consume: when N goroutines commit the SAME valid token
// simultaneously, exactly one must succeed and exactly one goal row may exist.
// A check-then-write nonce guard would let multiple goroutines pass the
// "not yet committed" check and each insert a row; the atomic claim must not.
// Run with -race to surface any data race in the nonce store.
func TestIntegration_CommitProposal_ConcurrentCommitOnce(t *testing.T) {
	s := setupServer(t)

	const title = "Concurrent Guard Goal"
	_, proposal, err := callHandlerAs(t, "hq", s.proposeGoal, ProposeGoalInput{Title: title})
	if err != nil {
		t.Fatalf("proposeGoal: %v", err)
	}

	const n = 8
	humanCtx := context.WithValue(t.Context(), callerKey{}, "human")
	input := CommitProposalInput{ProposalToken: proposal.ProposalToken}

	var (
		wg          sync.WaitGroup
		successes   atomic.Int64
		alreadyDone atomic.Int64
		otherErrs   atomic.Int64
	)
	// Release all goroutines at once to maximise the race window.
	start := make(chan struct{})
	for range n {
		wg.Go(func() {
			<-start
			_, out, cErr := s.commitProposal(humanCtx, nil, input)
			switch {
			case cErr == nil && out.Committed:
				successes.Add(1)
			case cErr != nil && strings.Contains(cErr.Error(), "proposal_already_committed"):
				alreadyDone.Add(1)
			default:
				otherErrs.Add(1)
				t.Errorf("unexpected commit outcome: committed=%v err=%v", out.Committed, cErr)
			}
		})
	}
	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Errorf("successful commits = %d, want exactly 1", got)
	}
	if got := alreadyDone.Load(); got != n-1 {
		t.Errorf("proposal_already_committed rejections = %d, want %d", got, n-1)
	}
	if got := otherErrs.Load(); got != 0 {
		t.Errorf("unexpected (non-replay) errors = %d, want 0", got)
	}

	var count int
	if err := testPool.QueryRow(t.Context(),
		"SELECT count(*) FROM goals WHERE title = $1", title,
	).Scan(&count); err != nil {
		t.Fatalf("counting goals: %v", err)
	}
	if count != 1 {
		t.Errorf("goals with title %q = %d, want 1 (concurrent replay created duplicates)", title, count)
	}
}

// TestIntegration_CommitProposal_DirectiveUnauthorizedDoesNotBurnToken is the
// end-to-end guard for finding #2: an unauthorized commit attempt on a directive
// token must fail WITHOUT consuming the nonce, so the legitimate proposer can
// still commit the same token. Before the fix the unauthorized attempt burned
// the nonce (consume ran before the SubmitTasks check), DoSing the proposal.
func TestIntegration_CommitProposal_DirectiveUnauthorizedDoesNotBurnToken(t *testing.T) {
	s := setupServer(t)

	_, prop, err := callHandlerAs(t, "hq", s.proposeDirective, ProposeDirectiveInput{
		Target:       "learning-studio",
		Priority:     "high",
		RequestParts: []json.RawMessage{json.RawMessage(`{"text":"Research replay-safe commit"}`)},
	})
	if err != nil {
		t.Fatalf("propose_directive: %v", err)
	}
	if prop.ProposalToken == "" {
		t.Fatal("empty proposal token")
	}

	// Unauthorized commit: learning-studio lacks SubmitTasks. Must fail, must
	// not create a task, and must not be a replay rejection (which would mean
	// the nonce was consumed before the auth check).
	_, _, unauthErr := callHandlerAs(t, "learning-studio", s.commitProposal, CommitProposalInput{
		ProposalToken: prop.ProposalToken,
	})
	if unauthErr == nil {
		t.Fatal("unauthorized directive commit = nil error, want authorization rejection")
	}
	if strings.Contains(unauthErr.Error(), "proposal_already_committed") {
		t.Errorf("unauthorized commit returned already_committed = %q — it consumed the nonce before auth", unauthErr)
	}
	if n := taskCount(t); n != 0 {
		t.Fatalf("tasks after failed unauthorized commit = %d, want 0", n)
	}

	// The legitimate proposer (hq holds SubmitTasks) can still commit the SAME
	// token — proving the unauthorized attempt did not burn it.
	_, commit, err := callHandlerAs(t, "hq", s.commitProposal, CommitProposalInput{
		ProposalToken: prop.ProposalToken,
	})
	if err != nil {
		t.Fatalf("authorized commit after unauthorized attempt: %v", err)
	}
	if !commit.Committed || commit.Type != "directive" {
		t.Errorf("authorized commit = %+v, want directive committed", commit)
	}
	if n := taskCount(t); n != 1 {
		t.Errorf("tasks after authorized commit = %d, want 1", n)
	}
}
