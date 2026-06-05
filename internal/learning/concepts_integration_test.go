// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// concepts_integration_test.go covers the GET /api/admin/learning/concepts
// and GET /api/admin/learning/concepts/{slug} reshape.
//
// Tests target the store layer (real SQL via testcontainers PostgreSQL).
// Handler-level wire contracts and validation are pinned in handler_test.go.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/...
package learning_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/learning"
)

// truncateConceptsTables clears every per-test row the concepts list
// and detail tests touch.
func truncateConceptsTables(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE
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
		t.Fatalf("truncateConceptsTables: %v", err)
	}
}

// seedConceptWithParent inserts a concept with an optional parent_id.
func seedConceptWithParent(t *testing.T, slug, name, domain, kind string, parentID *uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO concepts (slug, name, domain, kind, created_by, parent_id, description)
		 VALUES ($1, $2, $3, $4, 'human', $5, $6)
		 RETURNING id`,
		slug, name, domain, kind, parentID, "test description",
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding concept %q: %v", slug, err)
	}
	return id
}

// TestConceptsList_ConceptWithZeroObservations_AppearsAsDeveloping —
// the catalog view (vs the dashboard) must surface concepts even when
// they have no observations in the window. Zero observations should
// produce obs_count=0, all zero mastery_counts, mastery_stage=developing
// (DeriveMasteryStage(0,0,0)), and next_due_target=nil.
func TestConceptsList_ConceptWithZeroObservations_AppearsAsDeveloping(t *testing.T) {
	truncateConceptsTables(t)

	id := seedConceptWithParent(t, "untouched-concept", "Untouched", "leetcode", "pattern", nil)

	store := learning.NewStore(testPool)
	rows, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{}, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("ConceptsList: %v", err)
	}
	var got *learning.ConceptListRow
	for i := range rows {
		if rows[i].Slug == "untouched-concept" {
			got = &rows[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("untouched concept (%s) not in result — LEFT JOIN must surface zero-obs rows", id)
	}
	if got.ObsCount != 0 {
		t.Errorf("ObsCount = %d, want 0", got.ObsCount)
	}
	if got.MasteryCounts != (learning.SignalCounts{}) {
		t.Errorf("MasteryCounts = %+v, want zero struct", got.MasteryCounts)
	}
	if got.MasteryStage != learning.StageDeveloping {
		t.Errorf("MasteryStage = %q, want %q (under MinObservationsForVerdict floor)", got.MasteryStage, learning.StageDeveloping)
	}
	if got.ParentSlug != nil {
		t.Errorf("ParentSlug = %v, want nil (no parent seeded)", *got.ParentSlug)
	}
}

// TestConceptsList_FilterByMasteryStage — the mastery_stage filter
// runs in Go after DeriveMasteryStage. Seeded three concepts producing
// solid/struggling/developing and assert the filter returns the right
// subset.
func TestConceptsList_FilterByMasteryStage(t *testing.T) {
	truncateConceptsTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	sessionID := seedSession(t, "leetcode")

	// Solid: 3 high-conf mastery, 0 weakness.
	solidID := seedConceptWithParent(t, "solid-concept", "Solid", "leetcode", "pattern", nil)
	solidTarget := seedTarget(t, "lc-solid")
	linkTargetConcept(t, solidTarget, solidID)
	solidAttempt := seedAttempt(t, sessionID, solidTarget, now.Add(-time.Hour))
	seedObservation(t, solidAttempt, solidID, "mastery", "state-transition", "high")
	seedObservation(t, solidAttempt, solidID, "mastery", "state-transition", "high")
	seedObservation(t, solidAttempt, solidID, "mastery", "state-transition", "high")

	// Struggling: 3 high-conf weakness, 0 mastery.
	struggID := seedConceptWithParent(t, "struggling-concept", "Struggling", "leetcode", "pattern", nil)
	struggTarget := seedTarget(t, "lc-struggling")
	linkTargetConcept(t, struggTarget, struggID)
	struggAttempt := seedAttempt(t, sessionID, struggTarget, now.Add(-time.Hour))
	seedObservation(t, struggAttempt, struggID, "weakness", "state-transition", "high")
	seedObservation(t, struggAttempt, struggID, "weakness", "state-transition", "high")
	seedObservation(t, struggAttempt, struggID, "weakness", "state-transition", "high")

	// Developing: zero observations (LEFT JOIN catches it).
	seedConceptWithParent(t, "developing-concept", "Developing", "leetcode", "pattern", nil)

	store := learning.NewStore(testPool)
	since := now.Add(-90 * 24 * time.Hour)

	// No filter — all three appear.
	all, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{}, since)
	if err != nil {
		t.Fatalf("ConceptsList(no filter): %v", err)
	}
	if len(all) != 3 {
		t.Errorf("no-filter rows = %d, want 3", len(all))
	}

	// solid + struggling — both kept, developing dropped.
	keep, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{
		MasteryStages: []string{"solid", "struggling"},
	}, since)
	if err != nil {
		t.Fatalf("ConceptsList(solid,struggling): %v", err)
	}
	if len(keep) != 2 {
		t.Errorf("(solid,struggling) rows = %d, want 2", len(keep))
	}
	for i := range keep {
		if keep[i].MasteryStage == learning.StageDeveloping {
			t.Errorf("(solid,struggling) leaked a developing row: %q", keep[i].Slug)
		}
	}

	// developing only — just the zero-obs concept.
	dev, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{
		MasteryStages: []string{"developing"},
	}, since)
	if err != nil {
		t.Fatalf("ConceptsList(developing): %v", err)
	}
	if len(dev) != 1 {
		t.Fatalf("(developing) rows = %d, want 1", len(dev))
	}
	if dev[0].Slug != "developing-concept" {
		t.Errorf("(developing) row slug = %q, want %q", dev[0].Slug, "developing-concept")
	}
}

// TestConceptsList_FilterByKindAndQ — kind goes to SQL (concepts.kind =
// $param); q is ILIKE substring on slug + name. Both filters combine.
func TestConceptsList_FilterByKindAndQ(t *testing.T) {
	truncateConceptsTables(t)

	seedConceptWithParent(t, "sliding-window-search", "Sliding Window Search", "leetcode", "pattern", nil)
	seedConceptWithParent(t, "fixed-window-pattern", "Fixed Window Pattern", "leetcode", "pattern", nil)
	seedConceptWithParent(t, "edge-case-handling", "Edge Case Handling", "leetcode", "skill", nil)
	seedConceptWithParent(t, "amortized-analysis", "Amortized Analysis", "leetcode", "principle", nil)

	store := learning.NewStore(testPool)
	since := time.Now().Add(-90 * 24 * time.Hour)

	patternRows, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{Kind: "pattern"}, since)
	if err != nil {
		t.Fatalf("ConceptsList(kind=pattern): %v", err)
	}
	if len(patternRows) != 2 {
		t.Errorf("kind=pattern rows = %d, want 2", len(patternRows))
	}
	for i := range patternRows {
		if patternRows[i].Kind != "pattern" {
			t.Errorf("kind=pattern row has Kind=%q, want pattern", patternRows[i].Kind)
		}
	}

	qRows, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{Q: "window"}, since)
	if err != nil {
		t.Fatalf("ConceptsList(q=window): %v", err)
	}
	if len(qRows) != 2 {
		t.Errorf("q=window rows = %d, want 2 (slug+name substring match)", len(qRows))
	}

	// Combined: kind=pattern AND q=window → both window concepts (both are pattern).
	combinedRows, err := store.ConceptsList(t.Context(),
		learning.ConceptListFilter{Kind: "pattern", Q: "window"}, since)
	if err != nil {
		t.Fatalf("ConceptsList(kind=pattern, q=window): %v", err)
	}
	if len(combinedRows) != 2 {
		t.Errorf("(kind=pattern AND q=window) rows = %d, want 2", len(combinedRows))
	}

	// q must match across slug too — search 'amort' (no name 'Amort' word).
	slugRows, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{Q: "amort"}, since)
	if err != nil {
		t.Fatalf("ConceptsList(q=amort): %v", err)
	}
	if len(slugRows) != 1 || slugRows[0].Slug != "amortized-analysis" {
		t.Errorf("(q=amort) rows = %+v, want [amortized-analysis]", slugRows)
	}
}

// TestConceptsList_ParentSlug — parent_slug is the parent concept's
// slug (or nil for root concepts).
func TestConceptsList_ParentSlug(t *testing.T) {
	truncateConceptsTables(t)

	parentID := seedConceptWithParent(t, "parent-concept", "Parent", "leetcode", "pattern", nil)
	seedConceptWithParent(t, "child-concept", "Child", "leetcode", "skill", &parentID)

	store := learning.NewStore(testPool)
	rows, err := store.ConceptsList(t.Context(), learning.ConceptListFilter{}, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("ConceptsList: %v", err)
	}

	var parent, child *learning.ConceptListRow
	for i := range rows {
		switch rows[i].Slug {
		case "parent-concept":
			parent = &rows[i]
		case "child-concept":
			child = &rows[i]
		}
	}
	if parent == nil || child == nil {
		t.Fatalf("missing parent (%v) or child (%v) in results", parent, child)
	}
	if parent.ParentSlug != nil {
		t.Errorf("parent.ParentSlug = %v, want nil (root concept)", *parent.ParentSlug)
	}
	if child.ParentSlug == nil {
		t.Fatalf("child.ParentSlug = nil, want %q", "parent-concept")
	}
	if *child.ParentSlug != "parent-concept" {
		t.Errorf("child.ParentSlug = %q, want %q", *child.ParentSlug, "parent-concept")
	}
}

// TestConceptDetail_LowConfidenceCountsSeparate — mastery_counts honour
// confidence_filter; low_confidence_counts always count low-only,
// regardless of the filter axis.
func TestConceptDetail_LowConfidenceCountsSeparate(t *testing.T) {
	truncateConceptsTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")
	ctx := t.Context()

	conceptID := seedConceptWithParent(t, "two-axis-counts", "Two Axis", "leetcode", "pattern", nil)
	target := seedTarget(t, "lc-two-axis")
	linkTargetConcept(t, target, conceptID)
	sess := seedSession(t, "leetcode")
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	att := seedAttempt(t, sess, target, now.Add(-time.Hour))

	// 3 high-conf weakness + 2 low-conf weakness + 1 low-conf mastery.
	for range 3 {
		seedObservation(t, att, conceptID, "weakness", "state-transition", "high")
	}
	for range 2 {
		seedObservation(t, att, conceptID, "weakness", "state-transition", "low")
	}
	seedObservation(t, att, conceptID, "mastery", "state-transition", "low")

	store := learning.NewStore(testPool)

	highResp, err := store.ConceptDetail(ctx, "leetcode", "two-axis-counts", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail(high): %v", err)
	}
	if got := highResp.MasteryCounts.Weakness; got != 3 {
		t.Errorf("high mastery_counts.weakness = %d, want 3", got)
	}
	if got := highResp.MasteryCounts.Mastery; got != 0 {
		t.Errorf("high mastery_counts.mastery = %d, want 0", got)
	}
	if got := highResp.LowConfidenceCounts.Weakness; got != 2 {
		t.Errorf("low_confidence_counts.weakness = %d, want 2", got)
	}
	if got := highResp.LowConfidenceCounts.Mastery; got != 1 {
		t.Errorf("low_confidence_counts.mastery = %d, want 1", got)
	}

	// confidence_filter=all rolls high+low into mastery_counts.
	allResp, err := store.ConceptDetail(ctx, "leetcode", "two-axis-counts", "all", 20)
	if err != nil {
		t.Fatalf("ConceptDetail(all): %v", err)
	}
	if got := allResp.MasteryCounts.Weakness; got != 5 {
		t.Errorf("all mastery_counts.weakness = %d, want 5", got)
	}
	if got := allResp.MasteryCounts.Mastery; got != 1 {
		t.Errorf("all mastery_counts.mastery = %d, want 1", got)
	}
	// low_confidence_counts must remain identical across filter values.
	if allResp.LowConfidenceCounts != highResp.LowConfidenceCounts {
		t.Errorf("low_confidence_counts changed with filter — got %+v (all) vs %+v (high)",
			allResp.LowConfidenceCounts, highResp.LowConfidenceCounts)
	}

	// mastery_stage uses MasteryCounts under the requested filter.
	// 3 weakness, 0 mastery, total 3 → struggling.
	if highResp.MasteryStage != learning.StageStruggling {
		t.Errorf("high mastery_stage = %q, want %q", highResp.MasteryStage, learning.StageStruggling)
	}
}

// TestConceptDetail_ParentAndChildren — parent (singular) comes from
// concepts.parent_id; children is every concept whose parent_id is this
// concept. Both filter out archived rows.
func TestConceptDetail_ParentAndChildren(t *testing.T) {
	truncateConceptsTables(t)

	rootID := seedConceptWithParent(t, "graph-pattern", "Graph", "leetcode", "pattern", nil)
	traversalID := seedConceptWithParent(t, "graph-traversal", "Graph Traversal", "leetcode", "skill", &rootID)
	seedConceptWithParent(t, "dfs", "DFS", "leetcode", "skill", &traversalID)
	seedConceptWithParent(t, "bfs", "BFS", "leetcode", "skill", &traversalID)

	store := learning.NewStore(testPool)
	resp, err := store.ConceptDetail(t.Context(), "leetcode", "graph-traversal", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail: %v", err)
	}
	if resp.Parent == nil {
		t.Fatalf("Parent = nil, want graph-pattern")
	}
	if resp.Parent.Slug != "graph-pattern" {
		t.Errorf("Parent.Slug = %q, want %q", resp.Parent.Slug, "graph-pattern")
	}
	if len(resp.Children) != 2 {
		t.Fatalf("Children len = %d, want 2", len(resp.Children))
	}
	slugs := []string{resp.Children[0].Slug, resp.Children[1].Slug}
	if !((slugs[0] == "bfs" && slugs[1] == "dfs") || (slugs[0] == "dfs" && slugs[1] == "bfs")) {
		t.Errorf("Children slugs = %v, want {bfs, dfs}", slugs)
	}

	// Root concept has no parent but has one child.
	rootResp, err := store.ConceptDetail(t.Context(), "leetcode", "graph-pattern", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail(root): %v", err)
	}
	if rootResp.Parent != nil {
		t.Errorf("root.Parent = %+v, want nil", *rootResp.Parent)
	}
	if len(rootResp.Children) != 1 || rootResp.Children[0].Slug != "graph-traversal" {
		t.Errorf("root.Children = %+v, want [graph-traversal]", rootResp.Children)
	}
}

// TestConceptDetail_StubbedFieldsReturnEmptyArrays — relations,
// linked_notes, linked_contents are stub fields in PR B. They must
// always be `[]`, never nil, so the encoded JSON has `[]` not `null`.
func TestConceptDetail_StubbedFieldsReturnEmptyArrays(t *testing.T) {
	truncateConceptsTables(t)
	seedConceptWithParent(t, "stub-test-concept", "Stub Test", "leetcode", "pattern", nil)

	store := learning.NewStore(testPool)
	resp, err := store.ConceptDetail(t.Context(), "leetcode", "stub-test-concept", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail: %v", err)
	}

	if resp.Relations == nil {
		t.Error("Relations = nil, want []")
	}
	if resp.LinkedNotes == nil {
		t.Error("LinkedNotes = nil, want []")
	}
	if resp.LinkedContents == nil {
		t.Error("LinkedContents = nil, want []")
	}
	if len(resp.Relations) != 0 || len(resp.LinkedNotes) != 0 || len(resp.LinkedContents) != 0 {
		t.Errorf("stub arrays should be empty: relations=%d, linked_notes=%d, linked_contents=%d",
			len(resp.Relations), len(resp.LinkedNotes), len(resp.LinkedContents))
	}

	// Confirm via JSON round trip — `[]` not `null`.
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	for _, want := range []string{`"relations":[]`, `"linked_notes":[]`, `"linked_contents":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in encoded response, got: %s", want, body)
		}
	}
}

// TestConceptDetail_RecentObservationsShape — wire field names must be
// dashboard-compatible: signal/body/confidence/domain/concept_slug.
// detail=NULL coalesces to body="".
func TestConceptDetail_RecentObservationsShape(t *testing.T) {
	truncateConceptsTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	conceptID := seedConceptWithParent(t, "shape-test", "Shape Test", "leetcode", "pattern", nil)
	target := seedTarget(t, "lc-shape-target")
	linkTargetConcept(t, target, conceptID)
	sess := seedSession(t, "leetcode")
	att := seedAttempt(t, sess, target, time.Time{})
	seedObservation(t, att, conceptID, "improvement", "state-transition", "high")

	store := learning.NewStore(testPool)
	resp, err := store.ConceptDetail(t.Context(), "leetcode", "shape-test", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail: %v", err)
	}
	if len(resp.RecentObservations) != 1 {
		t.Fatalf("RecentObservations len = %d, want 1", len(resp.RecentObservations))
	}
	got := resp.RecentObservations[0]
	if got.Signal != "improvement" {
		t.Errorf("Signal = %q, want %q", got.Signal, "improvement")
	}
	if got.Body != "" {
		t.Errorf("Body = %q, want \"\" (NULL detail must coalesce)", got.Body)
	}
	if got.Domain != "leetcode" {
		t.Errorf("Domain = %q, want %q", got.Domain, "leetcode")
	}
	if got.ConceptSlug != "shape-test" {
		t.Errorf("ConceptSlug = %q, want %q", got.ConceptSlug, "shape-test")
	}
}

// TestConceptDetail_RecentAttemptsSlimShape — recent_attempts must
// carry only (id, target_title, outcome, created_at). No metadata,
// no external_id, no paradigm, no session_id. Verify via JSON.
func TestConceptDetail_RecentAttemptsSlimShape(t *testing.T) {
	truncateConceptsTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")

	conceptID := seedConceptWithParent(t, "slim-test", "Slim Test", "leetcode", "pattern", nil)
	target := seedTarget(t, "lc-slim-target")
	linkTargetConcept(t, target, conceptID)
	sess := seedSession(t, "leetcode")
	att := seedAttempt(t, sess, target, time.Time{})
	seedObservation(t, att, conceptID, "weakness", "state-transition", "high")

	store := learning.NewStore(testPool)
	resp, err := store.ConceptDetail(t.Context(), "leetcode", "slim-test", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail: %v", err)
	}
	if len(resp.RecentAttempts) != 1 {
		t.Fatalf("RecentAttempts len = %d, want 1", len(resp.RecentAttempts))
	}
	got := resp.RecentAttempts[0]
	if got.TargetTitle != "lc-slim-target" {
		t.Errorf("TargetTitle = %q, want %q", got.TargetTitle, "lc-slim-target")
	}
	if got.Outcome != "solved_independent" {
		t.Errorf("Outcome = %q, want %q", got.Outcome, "solved_independent")
	}

	// Marshal the slim DTO and ensure no full-Attempt fields leak.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{
		"metadata", "external_id", "paradigm", "session_id", "duration_minutes",
		"learning_target_id", "attempt_number",
	} {
		if _, present := m[forbidden]; present {
			t.Errorf("slim attempt leaks forbidden field %q\nfull JSON: %s", forbidden, b)
		}
	}
}

// TestConceptDetail_NotFoundReturns404 — ConceptDetail returns
// ErrNotFound when (domain, slug) does not match a live concept. The
// handler maps that sentinel to a 404 via storeErrors; here we pin the
// store-layer contract.
func TestConceptDetail_NotFoundReturns404(t *testing.T) {
	truncateConceptsTables(t)

	store := learning.NewStore(testPool)
	_, err := store.ConceptDetail(t.Context(), "leetcode", "ghost-slug", "high", 20)
	if !errors.Is(err, learning.ErrNotFound) {
		t.Errorf("ConceptDetail(ghost) error = %v, want ErrNotFound", err)
	}
}

// TestConceptDetail_ConfidenceFilterAll_LowSignalsLiftStage — when
// confidence_filter=all, low-confidence observations DO contribute to
// mastery_stage. Same concept yields different stages under high vs all.
func TestConceptDetail_ConfidenceFilterAll_LowSignalsLiftStage(t *testing.T) {
	truncateConceptsTables(t)
	seedConceptCategory(t, "state-transition", "leetcode")
	ctx := t.Context()

	conceptID := seedConceptWithParent(t, "filter-axis-test", "Filter Axis", "leetcode", "pattern", nil)
	target := seedTarget(t, "lc-filter-axis")
	linkTargetConcept(t, target, conceptID)
	sess := seedSession(t, "leetcode")
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	att := seedAttempt(t, sess, target, now.Add(-time.Hour))

	// 2 high-conf mastery + 1 low-conf mastery → high filter sees 2/2/0
	// (under floor → developing); all filter sees 3/0/0 (solid).
	seedObservation(t, att, conceptID, "mastery", "state-transition", "high")
	seedObservation(t, att, conceptID, "mastery", "state-transition", "high")
	seedObservation(t, att, conceptID, "mastery", "state-transition", "low")

	store := learning.NewStore(testPool)

	highResp, err := store.ConceptDetail(ctx, "leetcode", "filter-axis-test", "high", 20)
	if err != nil {
		t.Fatalf("ConceptDetail(high): %v", err)
	}
	if highResp.MasteryStage != learning.StageDeveloping {
		t.Errorf("high mastery_stage = %q, want %q (2 mastery under floor)", highResp.MasteryStage, learning.StageDeveloping)
	}

	allResp, err := store.ConceptDetail(ctx, "leetcode", "filter-axis-test", "all", 20)
	if err != nil {
		t.Fatalf("ConceptDetail(all): %v", err)
	}
	if allResp.MasteryStage != learning.StageSolid {
		t.Errorf("all mastery_stage = %q, want %q (3 mastery clears floor + ratio)", allResp.MasteryStage, learning.StageSolid)
	}
}
