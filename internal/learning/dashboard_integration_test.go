//go:build integration

// dashboard_integration_test.go covers the GET /api/admin/learning/dashboard
// reshape: observation-backed concept rows with mastery_value + next_due,
// FSRS-computed retention on due_today.items, last_reviewed_at derived from
// MAX(review_logs.reviewed_at), and confidence_filter propagation.
//
// All tests target the store layer + Retention helper (and run real SQL
// against testcontainers PostgreSQL). The handler is one thin layer above —
// its wire shape is locked by handler_test.go::TestDashboardWireContract.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/...
package learning_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/fsrs"
)

// truncateDashboardTables clears every per-test row touched by the
// dashboard. Includes concepts and learning_target_concepts which the
// shared truncateLearningTables() omits.
func truncateDashboardTables(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE
			review_logs,
			review_cards,
			learning_attempt_observations,
			learning_attempts,
			learning_sessions,
			learning_target_concepts,
			learning_target_relations,
			learning_targets,
			concepts
		RESTART IDENTITY CASCADE
	`)
	if err != nil {
		t.Fatalf("truncateDashboardTables: %v", err)
	}
}

// seedConcept inserts a concept. Returns its id.
func seedConcept(t *testing.T, slug, name, domain, kind string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO concepts (slug, name, domain, kind, created_by)
		 VALUES ($1, $2, $3, $4, 'human')
		 RETURNING id`,
		slug, name, domain, kind,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding concept %q: %v", slug, err)
	}
	return id
}

// seedSession inserts a learning_session and returns its id. Sessions
// must exist for attempts to link.
func seedSession(t *testing.T, domain string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_sessions (domain, session_mode)
		 VALUES ($1, 'practice')
		 RETURNING id`,
		domain,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding session: %v", err)
	}
	return id
}

// endSession stamps ended_at so subsequent seedSession calls don't trip
// the one-active-session-per-domain partial unique index.
func endSession(t *testing.T, id uuid.UUID) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		`UPDATE learning_sessions SET ended_at = now() WHERE id = $1`, id,
	)
	if err != nil {
		t.Fatalf("ending session %s: %v", id, err)
	}
}

// seedAttempt inserts a learning_attempt for the given (target, session).
// Returns its id. attempted_at defaults to now(); pass non-zero to override.
func seedAttempt(t *testing.T, sessionID, targetID uuid.UUID, attemptedAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if attemptedAt.IsZero() {
		err := testPool.QueryRow(t.Context(),
			`INSERT INTO learning_attempts (session_id, learning_target_id, attempt_number, paradigm, outcome)
			 VALUES ($1, $2, 1, 'problem_solving', 'solved_independent')
			 RETURNING id`,
			sessionID, targetID,
		).Scan(&id)
		if err != nil {
			t.Fatalf("seeding attempt: %v", err)
		}
		return id
	}
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_attempts (session_id, learning_target_id, attempt_number, paradigm, outcome, attempted_at)
		 VALUES ($1, $2, 1, 'problem_solving', 'solved_independent', $3)
		 RETURNING id`,
		sessionID, targetID, attemptedAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding attempt: %v", err)
	}
	return id
}

// seedObservation inserts a single attempt_observation row.
func seedObservation(t *testing.T, attemptID, conceptID uuid.UUID, signalType, category, confidence string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_attempt_observations
		   (attempt_id, concept_id, signal_type, category, confidence, position)
		 VALUES ($1, $2, $3, $4, $5, 0)
		 RETURNING id`,
		attemptID, conceptID, signalType, category, confidence,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding observation (%s/%s/%s): %v", signalType, category, confidence, err)
	}
	return id
}

// seedConceptCategory registers an observation_categories row scoped to
// the given domain. learning_attempt_observations.category has a FK to
// this table; tests that produce observations on a fresh domain must
// seed the category first (the migration only seeds canonical domains).
func seedConceptCategory(t *testing.T, slug, domain string) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		`INSERT INTO observation_categories (slug, domain) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`,
		slug, domain,
	)
	if err != nil {
		t.Fatalf("seeding observation_category %q: %v", slug, err)
	}
}

// linkTargetConcept attaches a concept to a target via
// learning_target_concepts. Used so the dashboard's next_due join can
// pick up the concept's review card.
func linkTargetConcept(t *testing.T, targetID, conceptID uuid.UUID) {
	t.Helper()
	_, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_concepts (learning_target_id, concept_id, relevance)
		 VALUES ($1, $2, 'primary')
		 ON CONFLICT DO NOTHING`,
		targetID, conceptID,
	)
	if err != nil {
		t.Fatalf("linking target %s ↔ concept %s: %v", targetID, conceptID, err)
	}
}

// TestDashboard_Empty_ReturnsEmptyContainers — with no data seeded, the
// store layer returns empty slices (never nil) so the handler can
// encode them as `[]` / `{}`.
func TestDashboard_Empty_ReturnsEmptyContainers(t *testing.T) {
	truncateDashboardTables(t)
	store := learning.NewStore(testPool)
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	since := now.Add(-90 * 24 * time.Hour)

	rows, err := store.DashboardConceptRows(t.Context(), nil, since, "high")
	if err != nil {
		t.Fatalf("DashboardConceptRows: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("DashboardConceptRows len = %d, want 0", len(rows))
	}

	items, err := store.DashboardDueReviews(t.Context(), nil, now.Add(24*time.Hour), 50, nil, now)
	if err != nil {
		t.Fatalf("DashboardDueReviews: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("DashboardDueReviews len = %d, want 0", len(items))
	}

	obs, err := store.DashboardRecentObservations(t.Context(), nil, "high", 20)
	if err != nil {
		t.Fatalf("DashboardRecentObservations: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("DashboardRecentObservations len = %d, want 0", len(obs))
	}
}

// TestDashboard_ConceptWithNoFSRSCard_NextDueNull — a concept with
// observations but no review_card on any of its targets must yield
// next_due=nil (the LEFT JOIN against concept_next_due produces NULL).
func TestDashboard_ConceptWithNoFSRSCard_NextDueNull(t *testing.T) {
	truncateDashboardTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	conceptID := seedConcept(t, "sliding-window-card-test", "Sliding Window", "leetcode", "pattern")
	targetID := seedTarget(t, "lc-card-test")
	linkTargetConcept(t, targetID, conceptID)

	sessionID := seedSession(t, "leetcode")
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	attemptID := seedAttempt(t, sessionID, targetID, now.Add(-time.Hour))

	// Three high-conf weakness obs so the row appears.
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "high")
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "high")
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "high")

	store := learning.NewStore(testPool)
	rows, err := store.DashboardConceptRows(t.Context(), nil, now.Add(-90*24*time.Hour), "high")
	if err != nil {
		t.Fatalf("DashboardConceptRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows len = %d, want 1", len(rows))
	}
	if rows[0].NextDue != nil {
		t.Errorf("rows[0].NextDue = %v, want nil (no review_card seeded)", *rows[0].NextDue)
	}
}

// TestDashboard_LowConfidence_FilteredByDefault — a concept whose only
// observations are confidence='low' is excluded by the default
// confidence_filter='high' but appears with confidence_filter='all'.
func TestDashboard_LowConfidence_FilteredByDefault(t *testing.T) {
	truncateDashboardTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	conceptID := seedConcept(t, "dp-low-conf-test", "Dynamic Programming", "leetcode", "pattern")
	targetID := seedTarget(t, "lc-dp-low-conf")
	linkTargetConcept(t, targetID, conceptID)

	sessionID := seedSession(t, "leetcode")
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	attemptID := seedAttempt(t, sessionID, targetID, now.Add(-time.Hour))

	// Three low-conf observations — under high filter they all drop.
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "low")
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "low")
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "low")

	store := learning.NewStore(testPool)
	since := now.Add(-90 * 24 * time.Hour)

	high, err := store.DashboardConceptRows(t.Context(), nil, since, "high")
	if err != nil {
		t.Fatalf("DashboardConceptRows(high): %v", err)
	}
	if len(high) != 0 {
		t.Errorf("high filter returned %d rows, want 0 (only low-confidence obs exist)", len(high))
	}

	all, err := store.DashboardConceptRows(t.Context(), nil, since, "all")
	if err != nil {
		t.Fatalf("DashboardConceptRows(all): %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("all filter returned %d rows, want 1", len(all))
	}
	if all[0].ObsCount != 3 {
		t.Errorf("all filter ObsCount = %d, want 3", all[0].ObsCount)
	}

	// Same filter applies to recent_observations.
	obsHigh, err := store.DashboardRecentObservations(t.Context(), nil, "high", 20)
	if err != nil {
		t.Fatalf("DashboardRecentObservations(high): %v", err)
	}
	if len(obsHigh) != 0 {
		t.Errorf("recent_observations(high) len = %d, want 0", len(obsHigh))
	}
	obsAll, err := store.DashboardRecentObservations(t.Context(), nil, "all", 20)
	if err != nil {
		t.Fatalf("DashboardRecentObservations(all): %v", err)
	}
	if len(obsAll) != 3 {
		t.Errorf("recent_observations(all) len = %d, want 3", len(obsAll))
	}
}

// TestDashboard_MasteryValueFromHighConfFilteredCounts — pin that the
// mastery_value scalar uses the same filtered count set as the dashboard's
// other aggregations. Three high-conf mastery + zero high-conf weakness
// → mastery_value = 1.0, mastery_stage = solid.
func TestDashboard_MasteryValueFromHighConfFilteredCounts(t *testing.T) {
	truncateDashboardTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	conceptID := seedConcept(t, "binary-search-mastery-test", "Binary Search", "leetcode", "pattern")
	targetID := seedTarget(t, "lc-binary-search")
	linkTargetConcept(t, targetID, conceptID)

	sessionID := seedSession(t, "leetcode")
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	attemptID := seedAttempt(t, sessionID, targetID, now.Add(-time.Hour))

	// 3 high-conf mastery + 1 low-conf weakness (excluded by default).
	seedObservation(t, attemptID, conceptID, "mastery", "state-transition", "high")
	seedObservation(t, attemptID, conceptID, "mastery", "state-transition", "high")
	seedObservation(t, attemptID, conceptID, "mastery", "state-transition", "high")
	seedObservation(t, attemptID, conceptID, "weakness", "state-transition", "low")

	store := learning.NewStore(testPool)
	since := now.Add(-90 * 24 * time.Hour)

	rows, err := store.DashboardConceptRows(t.Context(), nil, since, "high")
	if err != nil {
		t.Fatalf("DashboardConceptRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows len = %d, want 1", len(rows))
	}
	if got := rows[0].MasteryValue; got != 1.0 {
		t.Errorf("MasteryValue = %v, want 1.0 (3 mastery / 3 total under high filter)", got)
	}
	if got := rows[0].MasteryStage; got != learning.StageSolid {
		t.Errorf("MasteryStage = %q, want %q", got, learning.StageSolid)
	}
	if got := rows[0].ObsCount; got != 3 {
		t.Errorf("ObsCount = %d, want 3", got)
	}
}

// TestDashboard_RecentObservations_WireFieldNames — pin that the store
// projection uses signal/body/confidence/domain/concept_slug (not
// signal_type/detail). Detail=NULL in DB must surface as body="".
func TestDashboard_RecentObservations_WireFieldNames(t *testing.T) {
	truncateDashboardTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	conceptID := seedConcept(t, "two-pointers-shape-test", "Two Pointers", "leetcode", "pattern")
	targetID := seedTarget(t, "lc-two-pointers")
	linkTargetConcept(t, targetID, conceptID)
	sessionID := seedSession(t, "leetcode")
	attemptID := seedAttempt(t, sessionID, targetID, time.Time{})

	// Observation with NULL detail (no detail param) — body should be "".
	seedObservation(t, attemptID, conceptID, "improvement", "state-transition", "high")

	store := learning.NewStore(testPool)
	obs, err := store.DashboardRecentObservations(t.Context(), nil, "high", 20)
	if err != nil {
		t.Fatalf("DashboardRecentObservations: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("obs len = %d, want 1", len(obs))
	}
	got := obs[0]
	if got.Signal != "improvement" {
		t.Errorf("Signal = %q, want %q (wire rename: signal, not signal_type)", got.Signal, "improvement")
	}
	if got.Body != "" {
		t.Errorf("Body = %q, want \"\" (detail NULL must coalesce to empty string on wire)", got.Body)
	}
	if got.Domain != "leetcode" {
		t.Errorf("Domain = %q, want %q", got.Domain, "leetcode")
	}
	if got.ConceptSlug != "two-pointers-shape-test" {
		t.Errorf("ConceptSlug = %q, want %q", got.ConceptSlug, "two-pointers-shape-test")
	}
	if got.Confidence != "high" {
		t.Errorf("Confidence = %q, want %q", got.Confidence, "high")
	}

	// Round-trip the DTO through JSON to confirm the wire keys.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{"id", "signal", "category", "body", "domain", "concept_slug", "confidence", "created_at"} {
		if _, ok := m[want]; !ok {
			t.Errorf("recent_observation JSON missing wire field %q", want)
		}
	}
	if _, present := m["signal_type"]; present {
		t.Errorf("recent_observation JSON has forbidden legacy field %q", "signal_type")
	}
	if _, present := m["detail"]; present {
		t.Errorf("recent_observation JSON has forbidden legacy field %q", "detail")
	}
}

// TestDashboard_DueToday_RealRetention_NullableLastReviewedAt covers the
// full due_today flow: a real review through fsrs.Store leaves a card +
// review_log behind. The dashboard query must surface card_id, target
// metadata, a non-zero retention (real float64 from FSRS state), and a
// non-nil last_reviewed_at. A second card that was inserted but never
// reviewed yields last_reviewed_at=nil — the dashboard renders that as
// `null` per the spec.
func TestDashboard_DueToday_RealRetention_NullableLastReviewedAt(t *testing.T) {
	truncateDashboardTables(t)
	ctx := t.Context()

	reviewedTargetID := seedTarget(t, "lc-due-reviewed")
	unreviewedTargetID := seedTarget(t, "lc-due-unreviewed")

	fsrsStore := fsrs.NewStore(testPool)

	// Card 1: a successful review writes both review_cards and review_logs rows.
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	if _, _, err := fsrsStore.ReviewByOutcome(ctx, reviewedTargetID, "solved_independent", now.Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("baseline ReviewByOutcome: %v", err)
	}

	// Card 2: insert a card directly with non-zero stability but no review_log.
	// Mirrors the corner case where a card row exists from a prior code path
	// without an accompanying log entry.
	rawState, err := json.Marshal(map[string]any{
		"Due":           now.Add(-time.Hour),
		"Stability":     5.0,
		"Difficulty":    5.0,
		"ElapsedDays":   uint64(0),
		"ScheduledDays": uint64(0),
		"Reps":          uint64(1),
		"Lapses":        uint64(0),
		"State":         2, // Review
		"LastReview":    now.Add(-5 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal card state: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`INSERT INTO review_cards (learning_target_id, card_state, due)
		 VALUES ($1, $2, $3)`,
		unreviewedTargetID, rawState, now.Add(-time.Hour),
	); err != nil {
		t.Fatalf("inserting unreviewed card: %v", err)
	}

	store := learning.NewStore(testPool)
	dueBefore := now.Add(48 * time.Hour) // wide enough to catch both
	retentionFn := func(state []byte, t time.Time) float64 {
		return fsrsStore.Retention(state, t)
	}
	items, err := store.DashboardDueReviews(ctx, nil, dueBefore, 50, retentionFn, now)
	if err != nil {
		t.Fatalf("DashboardDueReviews: %v", err)
	}
	if len(items) < 2 {
		t.Fatalf("items len = %d, want >= 2", len(items))
	}

	var reviewed, unreviewed *learning.DashboardDueTodayItem
	for i := range items {
		switch items[i].Target.ID {
		case reviewedTargetID:
			reviewed = &items[i]
		case unreviewedTargetID:
			unreviewed = &items[i]
		}
	}
	if reviewed == nil {
		t.Fatalf("reviewed target not returned by DashboardDueReviews")
	}
	if unreviewed == nil {
		t.Fatalf("unreviewed target not returned by DashboardDueReviews")
	}

	// Reviewed: retention is a real float64 in (0,1] and last_reviewed_at != nil.
	if reviewed.Retention <= 0 || reviewed.Retention > 1 {
		t.Errorf("reviewed.Retention = %v, want in (0, 1]", reviewed.Retention)
	}
	if reviewed.LastReviewedAt == nil {
		t.Errorf("reviewed.LastReviewedAt = nil, want non-nil (review_log was written)")
	}
	if reviewed.Target.Title != "lc-due-reviewed" {
		t.Errorf("reviewed.Target.Title = %q, want %q", reviewed.Target.Title, "lc-due-reviewed")
	}
	if reviewed.Domain != "leetcode" {
		t.Errorf("reviewed.Domain = %q, want %q", reviewed.Domain, "leetcode")
	}

	// Unreviewed: retention is a real float64 (from the seeded state),
	// last_reviewed_at IS nil (no review_logs row for this card).
	if unreviewed.Retention <= 0 || unreviewed.Retention > 1 {
		t.Errorf("unreviewed.Retention = %v, want in (0, 1] (seeded Stability=5 + LastReview 5 days ago)", unreviewed.Retention)
	}
	if unreviewed.LastReviewedAt != nil {
		t.Errorf("unreviewed.LastReviewedAt = %v, want nil (no review_log row)", *unreviewed.LastReviewedAt)
	}
}
