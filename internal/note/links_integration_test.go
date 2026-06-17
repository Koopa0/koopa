// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// Integration coverage for note ↔ concept / learning-target link editing
// against a real PostgreSQL: SetConcepts / SetTargets reconcile the junction
// sets (add / remove / clear / preserve), a non-existent id maps to
// ErrInvalidLink, the resolved-ref reads round-trip (TargetRefsForNote joins
// the real learning_target_notes.target_id column), and the full HTTP path
// persists on success but rolls the whole PUT back on a bad id.
//
// Run with:
//
//	go test -tags=integration ./internal/note/...
package note

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/testdb"
)

// setupLinks builds on setup() (notes + agents) and additionally clears the
// learning graph. Truncating learning_domains cascades to concepts,
// learning_targets, and the note↔concept / note↔target junctions, so each
// link test starts from a clean slate.
func setupLinks(t *testing.T) *Store {
	t.Helper()
	s := setup(t)
	if err := testdb.TruncateCtx(t.Context(), testPool, "learning_domains"); err != nil {
		t.Fatal(err)
	}
	return s
}

func seedDomain(t *testing.T, slug string) {
	t.Helper()
	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_domains (slug, name) VALUES ($1, $2)
		 ON CONFLICT (slug) DO NOTHING`, slug, slug+" domain"); err != nil {
		t.Fatalf("seeding domain %q: %v", slug, err)
	}
}

// seedConcept inserts a concept in the given domain (which must exist) and
// returns its id. created_by is the setup-seeded 'human' agent.
func seedConcept(t *testing.T, slug, domain string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO concepts (slug, name, domain, kind, created_by)
		 VALUES ($1, $2, $3, 'pattern', 'human') RETURNING id`,
		slug, slug+" name", domain).Scan(&id); err != nil {
		t.Fatalf("seeding concept %q in %q: %v", slug, domain, err)
	}
	return id
}

// seedTarget inserts a learning target in the given domain and returns its id.
func seedTarget(t *testing.T, title, domain string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title, created_by)
		 VALUES ($1, $2, 'human') RETURNING id`,
		domain, title).Scan(&id); err != nil {
		t.Fatalf("seeding target %q in %q: %v", title, domain, err)
	}
	return id
}

// sortIDs returns a sorted copy so set comparisons are order-independent and
// nil/empty compare equal.
func sortIDs(ids []uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID{}, ids...)
	slices.SortFunc(out, func(a, b uuid.UUID) int {
		return strings.Compare(a.String(), b.String())
	})
	return out
}

func ptrIDs(in ...uuid.UUID) *[]uuid.UUID {
	v := append([]uuid.UUID{}, in...)
	return &v
}

func TestUpdate_ConceptReconciliation(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	seedDomain(t, "alpha")
	seedDomain(t, "beta")
	cA := seedConcept(t, "concept-a", "alpha")
	cB := seedConcept(t, "concept-b", "beta") // cross-domain: ids, not slugs
	cC := seedConcept(t, "concept-c", "alpha")

	tests := []struct {
		name    string
		initial []uuid.UUID
		update  *[]uuid.UUID
		want    []uuid.UUID
	}{
		{name: "set from empty", initial: nil, update: ptrIDs(cA, cB), want: []uuid.UUID{cA, cB}},
		{name: "clear with empty slice", initial: []uuid.UUID{cA, cB}, update: ptrIDs(), want: nil},
		{name: "nil leaves untouched", initial: []uuid.UUID{cA, cB}, update: nil, want: []uuid.UUID{cA, cB}},
		{name: "diff add and remove", initial: []uuid.UUID{cA, cB}, update: ptrIDs(cB, cC), want: []uuid.UUID{cB, cC}},
		{name: "duplicates deduped", initial: nil, update: ptrIDs(cA, cA), want: []uuid.UUID{cA}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := seedNote(t, s, "concept-recon-"+strings.ReplaceAll(tt.name, " ", "-")+"-"+uuid.NewString()[:8], tt.name)
			_ = i
			if len(tt.initial) > 0 {
				if err := s.SetConcepts(ctx, n.ID, tt.initial); err != nil {
					t.Fatalf("seeding initial concepts: %v", err)
				}
			}
			title := "updated"
			if _, err := s.Update(ctx, n.ID, UpdateParams{Title: &title, ConceptIDs: tt.update}); err != nil {
				t.Fatalf("Update() error = %v", err)
			}
			got, err := s.ConceptsForNote(ctx, n.ID)
			if err != nil {
				t.Fatalf("ConceptsForNote() error = %v", err)
			}
			if diff := cmp.Diff(sortIDs(tt.want), sortIDs(got)); diff != "" {
				t.Errorf("concepts after Update mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUpdate_TargetReconciliation(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	seedDomain(t, "alpha")
	t1 := seedTarget(t, "Target one", "alpha")
	t2 := seedTarget(t, "Target two", "alpha")
	t3 := seedTarget(t, "Target three", "alpha")

	tests := []struct {
		name    string
		initial []uuid.UUID
		update  *[]uuid.UUID
		want    []uuid.UUID
	}{
		{name: "set from empty", initial: nil, update: ptrIDs(t1, t2), want: []uuid.UUID{t1, t2}},
		{name: "clear with empty slice", initial: []uuid.UUID{t1, t2}, update: ptrIDs(), want: nil},
		{name: "nil leaves untouched", initial: []uuid.UUID{t1}, update: nil, want: []uuid.UUID{t1}},
		{name: "diff add and remove", initial: []uuid.UUID{t1, t2}, update: ptrIDs(t2, t3), want: []uuid.UUID{t2, t3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := seedNote(t, s, "target-recon-"+uuid.NewString()[:8], tt.name)
			if len(tt.initial) > 0 {
				if err := s.SetTargets(ctx, n.ID, tt.initial); err != nil {
					t.Fatalf("seeding initial targets: %v", err)
				}
			}
			title := "updated"
			if _, err := s.Update(ctx, n.ID, UpdateParams{Title: &title, TargetIDs: tt.update}); err != nil {
				t.Fatalf("Update() error = %v", err)
			}
			got, err := s.TargetsForNote(ctx, n.ID)
			if err != nil {
				t.Fatalf("TargetsForNote() error = %v", err)
			}
			if diff := cmp.Diff(sortIDs(tt.want), sortIDs(got)); diff != "" {
				t.Errorf("targets after Update mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUpdate_BadLinkID(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	seedDomain(t, "alpha")
	cA := seedConcept(t, "concept-a", "alpha")
	bad := uuid.New()

	tests := []struct {
		name   string
		params UpdateParams
	}{
		{name: "unknown concept id", params: UpdateParams{ConceptIDs: ptrIDs(bad)}},
		{name: "unknown target id", params: UpdateParams{TargetIDs: ptrIDs(bad)}},
		{name: "valid concept plus unknown", params: UpdateParams{ConceptIDs: ptrIDs(cA, bad)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := seedNote(t, s, "bad-link-"+uuid.NewString()[:8], tt.name)
			_, err := s.Update(ctx, n.ID, tt.params)
			if !errors.Is(err, ErrInvalidLink) {
				t.Fatalf("Update() error = %v, want ErrInvalidLink", err)
			}
		})
	}
}

// TestResolvedRefs_AfterAttach is the runtime proof that the resolved-ref
// reads work — in particular TargetRefsForNote, whose join previously pointed
// at a non-existent learning_target_notes.learning_target_id column and so
// errored on every call. Concepts are cross-domain to exercise id resolution.
func TestResolvedRefs_AfterAttach(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	seedDomain(t, "alpha")
	seedDomain(t, "beta")
	cA := seedConcept(t, "concept-a", "alpha")
	cB := seedConcept(t, "concept-b", "beta")
	tg := seedTarget(t, "Target one", "alpha")

	n := seedNote(t, s, "refs-note", "Refs note")
	if _, err := s.Update(ctx, n.ID, UpdateParams{
		ConceptIDs: ptrIDs(cA, cB),
		TargetIDs:  ptrIDs(tg),
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	conceptRefs, err := s.ConceptRefsForNote(ctx, n.ID)
	if err != nil {
		t.Fatalf("ConceptRefsForNote() error = %v", err)
	}
	gotConceptIDs := make([]uuid.UUID, len(conceptRefs))
	for i := range conceptRefs {
		gotConceptIDs[i] = conceptRefs[i].ID
	}
	if diff := cmp.Diff(sortIDs([]uuid.UUID{cA, cB}), sortIDs(gotConceptIDs)); diff != "" {
		t.Errorf("ConceptRefsForNote ids mismatch (-want +got):\n%s", diff)
	}

	targetRefs, err := s.TargetRefsForNote(ctx, n.ID)
	if err != nil {
		t.Fatalf("TargetRefsForNote() error = %v", err)
	}
	want := []TargetRef{{ID: tg, Title: "Target one", Domain: "alpha"}}
	if diff := cmp.Diff(want, targetRefs); diff != "" {
		t.Errorf("TargetRefsForNote mismatch (-want +got):\n%s", diff)
	}
}

// TestUpdateHTTP_PersistsAndRollsBack drives the real request path —
// api.ActorMiddleware (tx) → Handler.Update → store → PostgreSQL. A valid PUT
// commits and the response reflects the new links; a PUT with a bad id after
// a valid attach in the same request returns 422 and the whole change rolls
// back (the valid attach does not survive), proving atomicity.
func TestUpdateHTTP_PersistsAndRollsBack(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	seedDomain(t, "alpha")
	seedDomain(t, "beta")
	cA := seedConcept(t, "concept-a", "alpha")
	cB := seedConcept(t, "concept-b", "beta")
	bad := uuid.New()
	n := seedNote(t, s, "http-note", "HTTP note")

	logger := slog.New(slog.DiscardHandler)
	handler := NewHandler(s, logger)
	served := api.ActorMiddleware(testPool, "human", logger)(http.HandlerFunc(handler.Update))

	put := func(t *testing.T, payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		req := httptest.NewRequestWithContext(ctx, http.MethodPut,
			"/api/admin/knowledge/notes/"+n.ID.String(), bytes.NewReader(body))
		req.SetPathValue("id", n.ID.String())
		w := httptest.NewRecorder()
		served.ServeHTTP(w, req)
		return w
	}

	// Valid PUT: commits, and the response body carries the new concept ref.
	w := put(t, map[string]any{"concept_ids": []string{cA.String()}})
	if w.Code != http.StatusOK {
		t.Fatalf("valid PUT status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Concepts []ConceptRef `json:"concepts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Data.Concepts) != 1 || resp.Data.Concepts[0].ID != cA {
		t.Errorf("response concepts = %+v, want exactly [%s]", resp.Data.Concepts, cA)
	}
	if got, _ := s.ConceptsForNote(ctx, n.ID); len(got) != 1 || got[0] != cA {
		t.Fatalf("after valid PUT, ConceptsForNote = %v, want [%s]", got, cA)
	}

	// Bad PUT: wants {cB, bad}. SetConcepts attaches cB (valid) then fails on
	// bad → 422. With the request rolled back, cB's attach is undone and the
	// note's links return to the prior {cA}.
	w = put(t, map[string]any{"concept_ids": []string{cB.String(), bad.String()}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad PUT status = %d, want 422 (body: %s)", w.Code, w.Body.String())
	}
	got, err := s.ConceptsForNote(ctx, n.ID)
	if err != nil {
		t.Fatalf("ConceptsForNote() after bad PUT error = %v", err)
	}
	if diff := cmp.Diff([]uuid.UUID{cA}, got); diff != "" {
		t.Errorf("links not rolled back after 422 (-want +got):\n%s", diff)
	}

	// Targets get the same persist + atomic-rollback guarantee via SetTargets.
	tg1 := seedTarget(t, "Target one", "alpha")
	tg2 := seedTarget(t, "Target two", "alpha")

	w = put(t, map[string]any{"target_ids": []string{tg1.String()}})
	if w.Code != http.StatusOK {
		t.Fatalf("valid target PUT status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if gotT, _ := s.TargetsForNote(ctx, n.ID); len(gotT) != 1 || gotT[0] != tg1 {
		t.Fatalf("after valid target PUT, TargetsForNote = %v, want [%s]", gotT, tg1)
	}

	// Wants {tg2, bad}: tg2 attaches, then bad fails → 422 → the whole request
	// rolls back, so tg2's attach is undone and targets return to {tg1}.
	w = put(t, map[string]any{"target_ids": []string{tg2.String(), bad.String()}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad target PUT status = %d, want 422 (body: %s)", w.Code, w.Body.String())
	}
	gotT, err := s.TargetsForNote(ctx, n.ID)
	if err != nil {
		t.Fatalf("TargetsForNote() after bad PUT error = %v", err)
	}
	if diff := cmp.Diff([]uuid.UUID{tg1}, gotT); diff != "" {
		t.Errorf("targets not rolled back after 422 (-want +got):\n%s", diff)
	}
}

func relevanceOf(t *testing.T, noteID, conceptID uuid.UUID) string {
	t.Helper()
	var rel string
	if err := testPool.QueryRow(t.Context(),
		`SELECT relevance FROM note_concepts WHERE note_id = $1 AND concept_id = $2`,
		noteID, conceptID).Scan(&rel); err != nil {
		t.Fatalf("reading relevance for (%s,%s): %v", noteID, conceptID, err)
	}
	return rel
}

func countPrimaryLinks(t *testing.T, noteID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(t.Context(),
		`SELECT count(*) FROM note_concepts WHERE note_id = $1 AND relevance = 'primary'`,
		noteID).Scan(&n); err != nil {
		t.Fatalf("counting primary links for %s: %v", noteID, err)
	}
	return n
}

// TestUpdate_PreservesPrimaryAndNeverAddsSecond pins the load-bearing claim of
// the relevance design: a 'primary' link set elsewhere survives a picker
// re-save (SetConcepts only adds/removes, never rewrites existing rows), new
// picker links are always 'secondary', and adding a concept to a note that
// already has a primary never creates a second primary — so the
// idx_note_concepts_one_primary partial unique index is never violated.
func TestUpdate_PreservesPrimaryAndNeverAddsSecond(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	seedDomain(t, "alpha")
	cPrimary := seedConcept(t, "concept-primary", "alpha")
	cSecondary := seedConcept(t, "concept-secondary", "alpha")
	n := seedNote(t, s, "primary-preserve", "Primary preserve")

	// Seed an existing primary link the way a non-picker path would (the
	// picker itself never assigns primary).
	if err := s.AttachConcept(ctx, n.ID, cPrimary, "primary"); err != nil {
		t.Fatalf("seeding primary concept: %v", err)
	}

	// Re-save via Update, keeping the primary and adding a second concept.
	if _, err := s.Update(ctx, n.ID, UpdateParams{ConceptIDs: ptrIDs(cPrimary, cSecondary)}); err != nil {
		t.Fatalf("Update() error = %v (a second-primary unique violation would surface here)", err)
	}

	if got := relevanceOf(t, n.ID, cPrimary); got != "primary" {
		t.Errorf("pre-existing primary relevance = %q after re-save, want %q (must not be downgraded)", got, "primary")
	}
	if got := relevanceOf(t, n.ID, cSecondary); got != "secondary" {
		t.Errorf("newly added link relevance = %q, want %q", got, "secondary")
	}
	if got := countPrimaryLinks(t, n.ID); got != 1 {
		t.Errorf("primary link count = %d after adding a second concept, want 1", got)
	}

	// Clearing must remove even a primary link (DetachConcept covers all
	// relevances, not just secondary).
	if _, err := s.Update(ctx, n.ID, UpdateParams{ConceptIDs: ptrIDs()}); err != nil {
		t.Fatalf("Update(clear) error = %v", err)
	}
	if got := countPrimaryLinks(t, n.ID); got != 0 {
		t.Errorf("primary link count = %d after clear, want 0", got)
	}
	if got, _ := s.ConceptsForNote(ctx, n.ID); len(got) != 0 {
		t.Errorf("concepts after clear = %v, want empty", got)
	}
}

// TestCreateHTTP_RejectsLinks pins that note Create rejects link fields with
// 400 — links are an edit-mode PUT operation — rather than silently dropping
// them, while a plain create still succeeds. Driven over the real
// ActorMiddleware tx so it exercises the production path.
func TestCreateHTTP_RejectsLinks(t *testing.T) {
	s := setupLinks(t)
	ctx := t.Context()
	logger := slog.New(slog.DiscardHandler)
	handler := NewHandler(s, logger)
	served := api.ActorMiddleware(testPool, "human", logger)(http.HandlerFunc(handler.Create))

	post := func(t *testing.T, payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		req := httptest.NewRequestWithContext(ctx, http.MethodPost,
			"/api/admin/knowledge/notes", bytes.NewReader(body))
		w := httptest.NewRecorder()
		served.ServeHTTP(w, req)
		return w
	}
	base := func() map[string]any {
		return map[string]any{"slug": "create-" + uuid.NewString()[:8], "title": "T", "kind": string(KindMusing)}
	}

	// A valid uuid string is also a valid slug string, so it decodes for both
	// concept_slugs ([]string) and target_ids ([]uuid.UUID) — isolating the
	// link-reject from a decode error.
	for _, field := range []string{"concept_slugs", "target_ids"} {
		t.Run("rejects "+field, func(t *testing.T) {
			p := base()
			p[field] = []string{uuid.NewString()}
			w := post(t, p)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("create with %s status = %d, want 400 (body: %s)", field, w.Code, w.Body.String())
			}
		})
	}

	t.Run("succeeds without links", func(t *testing.T) {
		w := post(t, base())
		if w.Code != http.StatusCreated {
			t.Fatalf("plain create status = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
	})
}
