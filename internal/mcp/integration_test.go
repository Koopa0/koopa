// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles every testcontainers-backed test for the
// mcp package. Coverage is grouped into three concerns, each marked
// with a section banner below:
//
//  1. Cold-start workflow — capture_inbox / start_session /
//     commit_proposal(learning_plan) / record_attempt / end_session /
//     proposal validator / recommend_next_target.
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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/agent"
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

// seedLearningPlan inserts a learning_plans row in draft status directly via
// SQL — the replacement for the removed propose_learning_plan/commit_proposal
// fixture path. It creates only the plan shell (no entries); REPOINT tests add
// entries themselves via manage_plan. Returns the plan ID as a string for the
// ManagePlanInput.PlanID field.
func seedLearningPlan(t *testing.T, domain string, goalID *uuid.UUID, createdBy string) string {
	t.Helper()
	var planID string
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_plans (title, description, domain, goal_id, status, target_count, plan_config, created_by)
		 VALUES ($1, $2, $3, $4, 'draft', NULL, '{}', $5)
		 RETURNING id`,
		"Seeded Plan", "", domain, goalID, createdBy,
	).Scan(&planID)
	if err != nil {
		t.Fatalf("seedLearningPlan: %v", err)
	}
	return planID
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
		"contents",
		"notes",
		"milestones",
		"goals",
		"projects",
		"learning_hypotheses",
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
// was unset and the fallback 'system' wasn't in agents. With the registry
// seed and the withActorTx wrapper in place, this must write both the todo
// and the audit row with actor = learning-studio.
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
// were never seeded. With the domain seed in place this must resolve the
// FK and create the row.
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

// --- 4. record_attempt with auto-create concept ---

// TestIntegration_ColdStart_RecordAttempt covers two invariants. First, the
// attempt row writes its audit event with the correct actor — the
// learning_attempts table is covered by audit_learning_attempts. Second, the
// observation references a concept slug that doesn't exist yet; record_attempt
// is allowed to auto-create leaf concepts in the session's domain, and the
// concept must be resolvable by the concepts.domain FK to learning_domains
// (covered by the builtin domain seed).
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
// response surfaces concepts[] and related_targets_resolved[] so the coach
// can chain mastery reads without re-resolving slugs.
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
// is the literal 'system'. The builtin registry registers that agent
// specifically so the FK resolves — if anyone removes it, this test fails
// and tells them why.
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

// TestIntegration_RecordAttempt_PrimaryTargetCrossDomain pins the cross-domain
// primary-target rule: the primary attempt target inherits the active session's
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
	planID := seedLearningPlan(t, "leetcode", nil, "human")

	_, _, err = callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: planID,
		Entries: []ManagePlanEntryInput{
			{Title: "Two Sum", Position: 1},
		},
	})
	if err != nil {
		t.Fatalf("add_entries: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		"UPDATE learning_plans SET status = 'active', updated_at = now() WHERE id = $1", planID); err != nil {
		t.Fatalf("activate plan: %v", err)
	}

	// Find the entry id we just added.
	var entryID string
	if err := testPool.QueryRow(t.Context(),
		"SELECT id FROM learning_plan_entries WHERE plan_id = $1",
		planID,
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
		PlanID:               planID,
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
		PlanID:               planID,
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
// Required for handlers gated on requireAuthor / requireRegisteredCaller —
// callHandler alone falls through to the zero-privilege server default and
// the gate refuses.
func callHandlerAs[I, O any](t *testing.T, as string, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error), input I) (*mcp.CallToolResult, O, error) {
	t.Helper()
	ctx := context.WithValue(t.Context(), callerKey{}, as)
	return handler(ctx, nil, input)
}

func boolPtr(b bool) *bool { return &b }

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

	planID := seedLearningPlan(t, "leetcode", nil, "human")

	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: planID,
		Entries: []ManagePlanEntryInput{
			{Title: "Two Sum", Position: 1},
			{Title: "Stranded Target", Position: 2},
		},
	}); err != nil {
		t.Fatalf("add_entries: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		"UPDATE learning_plans SET status = 'active', updated_at = now() WHERE id = $1", planID); err != nil {
		t.Fatalf("activate plan: %v", err)
	}

	rows, err := testPool.Query(t.Context(),
		"SELECT id, position FROM learning_plan_entries WHERE plan_id = $1 ORDER BY position", planID)
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
				PlanID:               planID,
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
				PlanID:               planID,
				EntryID:              &twoSumEntryID,
				Status:               &completed,
				CompletedByAttemptID: &attemptID,
				Reason:               new("   "),
			},
			wantSub: "reason is required",
		},
		{
			name: "missing attempt id rejects without force",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  planID,
				EntryID: &twoSumEntryID,
				Status:  &completed,
				Reason:  new("solved on second attempt"),
			},
			wantSub: "completed_by_attempt_id is required",
		},
		{
			name: "force without manual override prefix rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  planID,
				EntryID: &strandedEntryID,
				Status:  &completed,
				Reason:  new("just trust me on this one ok thanks"),
				Force:   boolPtr(true),
			},
			wantSub: "manual override:",
		},
		{
			name: "force with prefix but too short rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  planID,
				EntryID: &strandedEntryID,
				Status:  &completed,
				Reason:  new("manual override: nope"),
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
				PlanID:  planID,
				EntryID: &strandedEntryID,
				Status:  &completed,
				Reason:  new("manual override: target retcon done"),
				Force:   boolPtr(true),
			},
			wantSub: "≥ 60 characters",
		},
		{
			name: "reason exceeding cap rejects",
			input: ManagePlanInput{
				Action:               "update_entry",
				PlanID:               planID,
				EntryID:              &twoSumEntryID,
				Status:               &completed,
				CompletedByAttemptID: &attemptID,
				Reason:               new(strings.Repeat("a", 1025)),
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
				PlanID:  planID,
				EntryID: &twoSumEntryID,
				Status:  new("skipped"),
				Reason:  new("manual override: this should still reject because skipped"),
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
		PlanID:  planID,
		EntryID: &strandedEntryID,
		Status:  &completed,
		Reason:  new("manual override: target was retconned during plan migration on 2026-05-06"),
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
// requirement: status=skipped requires a non-blank reason for audit-trail
// parity with status=completed. Without it,
// cross-agent review cannot distinguish "skipped because solved offline"
// from "skipped because plan retconned" — the policy gap that pushed
// agents toward force=true (wrong tool for normal skip).
func TestIntegration_UpdateEntry_SkipPolicy(t *testing.T) {
	s := setupServer(t)

	// Single-entry plan is enough — skip path does not need a recorded
	// attempt, only an active plan with an entry to skip.
	planID := seedLearningPlan(t, "leetcode", nil, "human")

	if _, _, err := callHandler(t, s.managePlan, ManagePlanInput{
		Action: "add_entries",
		PlanID: planID,
		Entries: []ManagePlanEntryInput{
			{Title: "Skip Target A", Position: 1},
			{Title: "Skip Target B", Position: 2},
			{Title: "Skip Target C", Position: 3},
		},
	}); err != nil {
		t.Fatalf("add_entries: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		"UPDATE learning_plans SET status = 'active', updated_at = now() WHERE id = $1", planID); err != nil {
		t.Fatalf("activate plan: %v", err)
	}

	rows, err := testPool.Query(t.Context(),
		"SELECT id, position FROM learning_plan_entries WHERE plan_id = $1 ORDER BY position", planID)
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
				PlanID:  planID,
				EntryID: &entryA,
				Status:  &skipped,
			},
			wantSub: "reason is required when marking entry skipped",
		},
		{
			name: "skip with empty-string reason rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  planID,
				EntryID: &entryA,
				Status:  &skipped,
				Reason:  new(""),
			},
			wantSub: "reason is required when marking entry skipped",
		},
		{
			name: "skip with whitespace-only reason rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  planID,
				EntryID: &entryA,
				Status:  &skipped,
				Reason:  new("   \t\n"),
			},
			wantSub: "reason is required when marking entry skipped",
		},
		{
			name: "skip with reason exceeding cap rejects",
			input: ManagePlanInput{
				Action:  "update_entry",
				PlanID:  planID,
				EntryID: &entryA,
				Status:  &skipped,
				Reason:  new(strings.Repeat("a", 1025)),
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
		PlanID:  planID,
		EntryID: &entryB,
		Status:  &skipped,
		Reason:  new("  koopa solved this offline before the plan was committed  "),
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
		PlanID:  planID,
		EntryID: &entryC,
		Status:  &skipped,
		Reason:  new("ignored because force gate fires first"),
		Force:   boolPtr(true),
	}); err == nil {
		t.Fatal("expected force=true with skipped to reject, got nil")
	} else if !strings.Contains(err.Error(), "force=true is only valid with status=completed") {
		t.Errorf("force+skip error = %q, want force-only gate to fire first", err)
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
	sessID := sess.Session.ID.String()
	_, out, err := callHandler(t, s.learningRead, LearningReadInput{
		View:      "next_target",
		SessionID: &sessID,
	})
	if err != nil {
		t.Fatalf("learningRead next_target: %v", err)
	}
	if out.NextTarget == nil {
		t.Fatal("learningRead next_target: NextTarget payload is nil")
	}
	rec := out.NextTarget
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

	sessID := sess.Session.ID.String()
	_, out, err := callHandler(t, s.learningRead, LearningReadInput{
		View:      "next_target",
		SessionID: &sessID,
	})
	if err != nil {
		t.Fatalf("learningRead next_target: %v", err)
	}
	if out.NextTarget == nil {
		t.Fatal("learningRead next_target: NextTarget payload is nil")
	}
	rec := out.NextTarget
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

	unknownSession := uuid.New().String()
	if _, _, err := callHandler(t, s.learningRead, LearningReadInput{
		View:      "next_target",
		SessionID: &unknownSession,
	}); err == nil {
		t.Error("learningRead next_target accepted unknown session; should error")
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

// =========================================================================
// Section 3: DB audit trigger regressions
// =========================================================================
//
// Integration coverage for the audit triggers in
// migrations/001_initial.up.sql:
//
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

	_, read, err := callHandler(t, s.learningRead, LearningReadInput{View: "session_progress"})
	if err != nil {
		t.Fatalf("learningRead session_progress: %v", err)
	}
	if read.SessionProgress == nil {
		t.Fatal("learningRead session_progress: SessionProgress payload is nil")
	}
	out := read.SessionProgress

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

	_, read, err := callHandler(t, s.learningRead, LearningReadInput{View: "session_progress"})
	if err != nil {
		t.Fatalf("learningRead session_progress: %v", err)
	}
	if read.SessionProgress == nil {
		t.Fatal("learningRead session_progress: SessionProgress payload is nil")
	}
	out := read.SessionProgress

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

	_, read, err := callHandler(t, s.learningRead, LearningReadInput{View: "session_progress"})
	if err != nil {
		t.Fatalf("learningRead session_progress: %v", err)
	}
	if read.SessionProgress == nil {
		t.Fatal("learningRead session_progress: SessionProgress payload is nil")
	}
	out := read.SessionProgress

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

	_, read, err := callHandler(t, s.learningRead, LearningReadInput{View: "session_progress"})
	if err != nil {
		t.Fatalf("learningRead session_progress: %v", err)
	}
	if read.SessionProgress == nil {
		t.Fatal("learningRead session_progress: SessionProgress payload is nil")
	}
	out := read.SessionProgress

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
	_, read, err := callHandler(t, s.learningRead, LearningReadInput{
		View:   "attempts",
		Target: &AttemptHistoryTargetRef{Title: "Two Sum"},
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("learningRead attempts target: %v", err)
	}
	if read.Attempts == nil {
		t.Fatal("learningRead attempts: Attempts payload is nil")
	}
	out := read.Attempts
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

	_, read, err := callHandler(t, s.learningRead, LearningReadInput{
		View:        "attempts",
		ConceptSlug: new("sliding-window-variable"),
	})
	if err != nil {
		t.Fatalf("learningRead attempts concept: %v", err)
	}
	if read.Attempts == nil {
		t.Fatal("learningRead attempts: Attempts payload is nil")
	}
	out := read.Attempts
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

	_, read, err := callHandler(t, s.learningRead, LearningReadInput{
		View:      "attempts",
		SessionID: new(sess.Session.ID.String()),
	})
	if err != nil {
		t.Fatalf("learningRead attempts session: %v", err)
	}
	if read.Attempts == nil {
		t.Fatal("learningRead attempts: Attempts payload is nil")
	}
	out := read.Attempts
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
	_, readTarget, err := callHandler(t, s.learningRead, LearningReadInput{
		View:                "attempts",
		Target:              &AttemptHistoryTargetRef{Title: "Valid Parentheses"},
		IncludeObservations: &includeFalse,
	})
	if err != nil {
		t.Fatalf("learningRead attempts target include=false: %v", err)
	}
	if readTarget.Attempts == nil {
		t.Fatal("learningRead attempts target: Attempts payload is nil")
	}
	outTarget := readTarget.Attempts
	if len(outTarget.Attempts) != 1 {
		t.Fatalf("target attempts len = %d, want 1", len(outTarget.Attempts))
	}
	if len(outTarget.Attempts[0].Observations) != 0 {
		t.Errorf("target include=false: Observations len = %d, want 0", len(outTarget.Attempts[0].Observations))
	}

	// concept mode — observations empty, but matched_observation_id MUST
	// stay populated because the query match info comes from the primary
	// SQL query, not the secondary observation fetch.
	_, readConcept, err := callHandler(t, s.learningRead, LearningReadInput{
		View:                "attempts",
		ConceptSlug:         new("stack-matching"),
		IncludeObservations: &includeFalse,
	})
	if err != nil {
		t.Fatalf("learningRead attempts concept include=false: %v", err)
	}
	if readConcept.Attempts == nil {
		t.Fatal("learningRead attempts concept: Attempts payload is nil")
	}
	outConcept := readConcept.Attempts
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

	_, targetRead, err := callHandler(t, s.learningRead, LearningReadInput{
		View:   "attempts",
		Target: &AttemptHistoryTargetRef{Title: "Climbing Stairs"},
	})
	if err != nil {
		t.Fatalf("learningRead attempts target: %v", err)
	}
	if targetRead.Attempts == nil {
		t.Fatal("learningRead attempts target: Attempts payload is nil")
	}
	targetOut := targetRead.Attempts
	if len(targetOut.Attempts) != 3 {
		t.Fatalf("target attempts = %d, want 3", len(targetOut.Attempts))
	}
	// AttemptNumber increments monotonically (1, 2, 3); DESC means [3, 2, 1].
	for i, wantNum := range []int32{3, 2, 1} {
		if targetOut.Attempts[i].AttemptNumber != wantNum {
			t.Errorf("target mode DESC: Attempts[%d].AttemptNumber = %d, want %d", i, targetOut.Attempts[i].AttemptNumber, wantNum)
		}
	}

	_, sessionRead, err := callHandler(t, s.learningRead, LearningReadInput{
		View:      "attempts",
		SessionID: new(sess.Session.ID.String()),
	})
	if err != nil {
		t.Fatalf("learningRead attempts session: %v", err)
	}
	if sessionRead.Attempts == nil {
		t.Fatal("learningRead attempts session: Attempts payload is nil")
	}
	sessionOut := sessionRead.Attempts
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

func TestIntegration_ToolsListAdvertisesEnums(t *testing.T) {
	s := setupServer(t)

	// The MCP server's internal registry of tool schemas is not directly
	// exposed, but s.registeredNames + ops.All() gives the same pairing.
	// Walk the ops catalog, find tools with FieldEnums, and assert that
	// the generated schema (via the same jsonschema.ForType path) has
	// the expected enums. A lightweight proxy for what tools/list emits.
	s.logger.Info("integration_test: enum advertising probe", "registered", len(s.registeredNames))
	foundRecord, foundLearningRead := false, false
	for _, m := range ops.All() {
		if m.Name == "record_attempt" && len(m.FieldEnums["outcome"]) > 0 {
			foundRecord = true
		}
		if m.Name == "learning_read" && len(m.FieldEnums["view"]) > 0 {
			foundLearningRead = true
		}
	}
	if !foundRecord {
		t.Error("record_attempt.FieldEnums[outcome] missing")
	}
	if !foundLearningRead {
		t.Error("learning_read.FieldEnums[view] missing")
	}
}

// ============================================================================
// Consolidated from a2a_integration_test.go (Track-1K test-file consolidation).
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

// TestIntegration_SearchKnowledge_CorpusExclusion seeds a confusable non-corpus
// note that matches the query term alongside one in-corpus content row, and
// asserts only corpus source types (content, note) surface in search_knowledge
// results. The in-corpus content row presence guards against a vacuous pass (a
// non-matching term would make exclusion trivially true).
func TestIntegration_SearchKnowledge_CorpusExclusion(t *testing.T) {
	s := setupServer(t)
	const term = "zqxexcl"
	seedSearchContent(t, "sk-excl-content", term, "draft")

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

// --- plan_day position bounds (#13) ---

// seedTodoState inserts a todo in the given state and returns its id. plan_day
// requires todos in state=todo; the registry sync in setupServer seeds the
// default created_by='human' agent so the FK resolves.
func seedTodoState(t *testing.T, title, state string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO todos (title, state) VALUES ($1, $2::todo_state) RETURNING id`,
		title, state,
	).Scan(&id); err != nil {
		t.Fatalf("seeding todo %q (state=%s): %v", title, state, err)
	}
	return id
}

// countPlanItems returns how many daily_plan_items rows exist for a todo.
func countPlanItems(t *testing.T, todoID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM daily_plan_items WHERE todo_id = $1`, todoID,
	).Scan(&n); err != nil {
		t.Fatalf("counting plan items: %v", err)
	}
	return n
}

// TestIntegration_PlanDay_PositionOutOfRangeRejected guards the position bound:
// createPlanItemTx bounds the caller-supplied position to [0, maxPlanPosition]
// (100000) so the int32 cast cannot overflow. A position above the ceiling or
// below zero must be rejected, and because the whole plan_day write runs inside
// a single withActorTx, the rejection rolls back the DeletePlannedByDate that
// opened the idempotent-replace window — leaving zero daily_plan_items written.
//
// plan_day is author-gated to planner, so the call goes through callHandlerAs("planner").
func TestIntegration_PlanDay_PositionOutOfRangeRejected(t *testing.T) {
	s := setupServer(t)
	todoID := seedTodoState(t, "bounded-plan-item", "todo")

	tests := []struct {
		name     string
		position int
	}{
		{name: "above maxPlanPosition", position: maxPlanPosition + 1},
		{name: "well above ceiling", position: 1_000_000},
		{name: "negative position", position: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := callHandlerAs(t, "planner", s.planDay, PlanDayInput{
				Items: []PlanDayItem{
					{TaskID: todoID.String(), Position: tc.position},
				},
			})
			if err == nil {
				t.Fatalf("plan_day accepted out-of-range position %d; want rejection", tc.position)
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("error = %q, want it to name the out-of-range position", err)
			}
			if got := countPlanItems(t, todoID); got != 0 {
				t.Errorf("daily_plan_items for todo = %d, want 0 (tx rollback on rejection)", got)
			}
		})
	}

	// Control: an in-range position for the same todo succeeds, proving the
	// rejection above is the bounds gate and not a setup error.
	_, out, err := callHandlerAs(t, "planner", s.planDay, PlanDayInput{
		Items: []PlanDayItem{
			{TaskID: todoID.String(), Position: 1},
		},
	})
	if err != nil {
		t.Fatalf("plan_day with in-range position: %v", err)
	}
	if out.ItemsCreated != 1 {
		t.Errorf("items_created = %d, want 1 for the in-range control", out.ItemsCreated)
	}
	if got := countPlanItems(t, todoID); got != 1 {
		t.Errorf("daily_plan_items for todo = %d, want 1 after in-range plan", got)
	}
}
