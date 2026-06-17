// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// recommend_integration_test.go covers GET /api/admin/learning/next-target —
// the session-independent "Next up" card endpoint. It exercises the full
// handler → store → SQL path against real PostgreSQL: the empty state (no
// weakness signal), a populated recommendation off the severity-ordered
// WeaknessAnalysis, and domain scoping.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/...
package learning_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Koopa0/koopa/internal/learning"
	"github.com/google/uuid"
)

// seedWeaknessObservation inserts a weakness observation with an explicit
// severity and created_at. The shared seedObservation helper leaves severity
// NULL and created_at = now(), which is fine for mastery/dashboard tests; but
// next-target's reason depends on the severity band AND WeaknessAnalysis
// derives last_seen_at from MAX(ao.created_at) — so both must be settable to
// exercise days-since-practice deterministically.
func seedWeaknessObservation(t *testing.T, attemptID, conceptID uuid.UUID, category, severity, confidence string, position int, createdAt time.Time) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_attempt_observations
		   (attempt_id, concept_id, signal_type, category, severity, confidence, position, created_at)
		 VALUES ($1, $2, 'weakness', $3, $4, $5, $6, $7)`,
		attemptID, conceptID, category, severity, confidence, position, createdAt,
	)
	if err != nil {
		t.Fatalf("seeding weakness observation (%s/%s/%s): %v", category, severity, confidence, err)
	}
}

// nextTargetBody is the decoded response shape, mirroring learning.NextTarget.
type nextTargetBody struct {
	Data learning.NextTarget `json:"data"`
}

// callNextTarget runs the NextTarget handler with an optional ?domain= and
// returns the decoded body.
func callNextTarget(t *testing.T, h *learning.Handler, domain string) (int, learning.NextTarget) {
	t.Helper()
	url := "/api/admin/learning/next-target"
	if domain != "" {
		url += "?domain=" + domain
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	h.NextTarget(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body nextTargetBody
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding next-target body: %v (raw=%s)", err, w.Body.String())
	}
	return w.Code, body.Data
}

// TestNextTarget_Empty — with no weakness signal in the window the endpoint
// returns 200 with {empty: true} and a renderable reason, NOT a 404. The card
// must be able to render an empty state from a successful response.
func TestNextTarget_Empty(t *testing.T) {
	truncateDashboardTables(t)
	h := learning.NewHandler(learning.NewStore(testPool), slog.Default())

	code, got := callNextTarget(t, h, "")

	if code != http.StatusOK {
		t.Fatalf("NextTarget (empty) status = %d, want %d (empty must be 200, never 404)", code, http.StatusOK)
	}
	if !got.Empty {
		t.Errorf("NextTarget (empty).Empty = false, want true")
	}
	if got.Reason == "" {
		t.Errorf("NextTarget (empty).Reason is empty; the card needs a sentence to show")
	}
	if got.ConceptSlug != "" {
		t.Errorf("NextTarget (empty).ConceptSlug = %q, want empty", got.ConceptSlug)
	}
}

// TestNextTarget_RecommendsMostSevereConcept — given two weakness concepts,
// the endpoint surfaces the one the SQL orders first (critical_count DESC),
// not the one with the higher raw occurrence count. This is the end-to-end
// proof that handler + WeaknessAnalysis + SelectNextTarget agree on "most
// urgent first".
func TestNextTarget_RecommendsMostSevereConcept(t *testing.T) {
	truncateDashboardTables(t)
	store := learning.NewStore(testPool)
	h := learning.NewHandler(store, slog.Default())

	seedConceptCategory(t, "off-by-one", "leetcode")
	seedConceptCategory(t, "naming", "leetcode")

	critical := seedConcept(t, "two-pointer", "Two Pointer", "leetcode", "pattern")
	noisy := seedConcept(t, "hash-map", "Hash Map", "leetcode", "pattern")

	session := seedSession(t, "leetcode")
	target := seedTarget(t, "next-target-severity")
	recent := time.Now().Add(-3 * 24 * time.Hour)
	attempt := seedAttempt(t, session, target, recent)

	// last_seen_at = MAX(observation.created_at), so stamp the observations
	// 3 days back to drive DaysSincePractice deterministically.
	seen := recent
	// Critical concept: 2 critical observations (urgent, low volume).
	seedWeaknessObservation(t, attempt, critical, "off-by-one", "critical", "high", 0, seen)
	seedWeaknessObservation(t, attempt, critical, "off-by-one", "critical", "high", 1, seen)
	// Noisy concept: many minor observations (high volume, low urgency).
	for i := range 5 {
		seedWeaknessObservation(t, attempt, noisy, "naming", "minor", "high", 2+i, seen)
	}

	code, got := callNextTarget(t, h, "")

	if code != http.StatusOK {
		t.Fatalf("NextTarget status = %d, want %d", code, http.StatusOK)
	}
	if got.Empty {
		t.Fatalf("NextTarget.Empty = true, want a recommendation")
	}
	if got.ConceptSlug != "two-pointer" {
		t.Errorf("NextTarget.ConceptSlug = %q, want %q (critical concept must outrank the noisier minor one)", got.ConceptSlug, "two-pointer")
	}
	if got.Severity != "critical" {
		t.Errorf("NextTarget.Severity = %q, want %q", got.Severity, "critical")
	}
	if got.Domain != "leetcode" {
		t.Errorf("NextTarget.Domain = %q, want %q", got.Domain, "leetcode")
	}
	if got.DaysSincePractice != 3 {
		t.Errorf("NextTarget.DaysSincePractice = %d, want 3", got.DaysSincePractice)
	}
	if got.Reason == "" {
		t.Errorf("NextTarget.Reason is empty; want a rendered sentence")
	}
}

// TestNextTarget_DomainScope — ?domain= filters the weakness signal so the
// recommendation reflects only that practice track. A concept in another
// domain must not leak into the recommendation when a domain is supplied.
func TestNextTarget_DomainScope(t *testing.T) {
	truncateDashboardTables(t)
	store := learning.NewStore(testPool)
	h := learning.NewHandler(store, slog.Default())

	seedConceptCategory(t, "off-by-one", "leetcode")
	seedConceptCategory(t, "grammar", "japanese")

	lc := seedConcept(t, "binary-search", "Binary Search", "leetcode", "pattern")
	jp := seedConcept(t, "keigo", "Keigo", "japanese", "pattern")

	day := time.Now().Add(-24 * time.Hour)

	// leetcode weakness. Only one session may be active at a time
	// (uq_learning_sessions_one_active), so end each before opening the next.
	lcSession := seedSession(t, "leetcode")
	lcTarget := seedTarget(t, "next-target-domain-lc")
	lcAttempt := seedAttempt(t, lcSession, lcTarget, day)
	seedWeaknessObservation(t, lcAttempt, lc, "off-by-one", "critical", "high", 0, day)
	endSession(t, lcSession)

	// japanese weakness (must not appear when scoped to leetcode).
	jpSession := seedSession(t, "japanese")
	jpTarget := seedTargetDomain(t, "japanese", "next-target-domain-jp")
	jpAttempt := seedAttempt(t, jpSession, jpTarget, day)
	seedWeaknessObservation(t, jpAttempt, jp, "grammar", "critical", "high", 0, day)

	code, got := callNextTarget(t, h, "leetcode")
	if code != http.StatusOK {
		t.Fatalf("NextTarget (scoped) status = %d, want %d", code, http.StatusOK)
	}
	if got.Empty {
		t.Fatalf("NextTarget (scoped to leetcode).Empty = true, want the leetcode concept")
	}
	if got.ConceptSlug != "binary-search" {
		t.Errorf("NextTarget (scoped to leetcode).ConceptSlug = %q, want %q (japanese concept leaked across the domain filter)", got.ConceptSlug, "binary-search")
	}
	if got.Domain != "leetcode" {
		t.Errorf("NextTarget (scoped).Domain = %q, want leetcode", got.Domain)
	}
}

// seedTargetDomain inserts a learning_target in an arbitrary domain. The
// shared seedTarget helper hardcodes 'leetcode'; the domain-scope test needs
// a target in a second domain.
func seedTargetDomain(t *testing.T, domain, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title, external_id, created_by)
		 VALUES ($1, $2, $3, 'human')
		 RETURNING id`,
		domain, title, t.Name()+"::"+title,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding learning_target %q in %q: %v", title, domain, err)
	}
	return id
}
