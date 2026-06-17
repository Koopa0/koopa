// Copyright 2026 Koopa. All rights reserved.

//go:build integration

// integration_test.go bundles every testcontainers-backed test for the
// learning package. Coverage is grouped into two concerns:
//
//  1. Symmetric relation trigger — trg_learning_target_relations_symmetry
//     auto-mirrors (A,B,same_pattern) to produce (B,A,same_pattern), and
//     must be idempotent + directed-type-safe.
//  2. Session concurrency — the uq_learning_sessions_one_active partial
//     unique index enforces "one active session per domain" against
//     concurrent StartSession calls.
//
// Run with:
//
//	go test -tags=integration ./internal/learning/...
package learning_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa/internal/agent"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup := testdb.StartPool()
	testPool = pool

	// BuiltinAgents must land in the agents table so FK targets are present
	// for every test that inserts via a handler path (or via seedTarget,
	// which references the 'leetcode' domain from migration 002).
	registry := agent.NewBuiltinRegistry()
	if _, err := agent.SyncToTable(context.Background(), registry, agent.NewStore(pool), nil, slog.Default()); err != nil {
		slog.Default().Error("agent.SyncToTable", "error", err)
		cleanup()
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}

// --- Helpers ---

// seedTarget inserts a learning_target in the leetcode domain (already
// seeded by migration 002) and returns its id. Uses an anonymous
// external_id derived from t.Name() so repeated invocations inside the
// same shared container do not collide on the (domain, external_id)
// partial unique index.
func seedTarget(t *testing.T, title string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_targets (domain, title, external_id, created_by)
		 VALUES ('leetcode', $1, $2, 'human')
		 RETURNING id`,
		title, t.Name()+"::"+title,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seeding learning_target %q: %v", title, err)
	}
	return id
}

// countRelations returns how many rows exist for the given (anchor,
// related, relation_type) triple. 0 or 1 under the unique index.
func countRelations(t *testing.T, anchor, related uuid.UUID, relType string) int {
	t.Helper()
	var n int
	err := testPool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM learning_target_relations
		 WHERE anchor_id = $1 AND related_id = $2 AND relation_type = $3`,
		anchor, related, relType,
	).Scan(&n)
	if err != nil {
		t.Fatalf("counting relations: %v", err)
	}
	return n
}

// truncateLearningTables clears every per-test learning row. Order is
// child-first so FK CASCADE chains stay consistent even when RESTART
// IDENTITY resets sequences.
func truncateLearningTables(t *testing.T) {
	t.Helper()
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE
			learning_attempt_observations,
			learning_attempts,
			learning_sessions,
			learning_target_relations,
			learning_targets
		RESTART IDENTITY CASCADE
	`)
	if err != nil {
		t.Fatalf("truncateLearningTables: %v", err)
	}
}

// =========================================================================
// Section 1: Symmetric relation trigger
// =========================================================================
//
// made symmetric relation types
// (same_pattern, similar_structure) auto-mirror: a single INSERT of
// (A, B, same_pattern) produces two rows — (A, B) and (B, A) — via the
// AFTER INSERT trigger, with ON CONFLICT DO NOTHING preventing
// recursion.

// TestSymmetricRelation_InsertsReverseEdge — inserting one direction of
// a symmetric relation must produce both directions.
func TestSymmetricRelation_InsertsReverseEdge(t *testing.T) {
	a := seedTarget(t, "A-symmetric")
	b := seedTarget(t, "B-symmetric")

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type, created_by)
		 VALUES ($1, $2, 'same_pattern', 'human')`,
		a, b,
	); err != nil {
		t.Fatalf("inserting forward edge: %v", err)
	}

	if got := countRelations(t, a, b, "same_pattern"); got != 1 {
		t.Errorf("forward (a→b) same_pattern count = %d, want 1", got)
	}
	if got := countRelations(t, b, a, "same_pattern"); got != 1 {
		t.Errorf("reverse (b→a) same_pattern count = %d, want 1 (trigger auto-insert)", got)
	}
}

// TestDirectedRelation_LeavesReverseEmpty — non-symmetric relation
// types must NOT auto-mirror. easier_variant is directed.
func TestDirectedRelation_LeavesReverseEmpty(t *testing.T) {
	a := seedTarget(t, "A-directed")
	b := seedTarget(t, "B-directed")

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type, created_by)
		 VALUES ($1, $2, 'easier_variant', 'human')`,
		a, b,
	); err != nil {
		t.Fatalf("inserting directed edge: %v", err)
	}

	if got := countRelations(t, a, b, "easier_variant"); got != 1 {
		t.Errorf("forward easier_variant count = %d, want 1", got)
	}
	if got := countRelations(t, b, a, "easier_variant"); got != 0 {
		t.Errorf("reverse easier_variant count = %d, want 0 (directed type must not mirror)", got)
	}
}

// TestSymmetricRelation_ReverseInsertIdempotent — manually inserting
// the reverse edge of an already-mirrored pair must be a no-op (trigger
// would try to re-insert the forward edge; ON CONFLICT DO NOTHING
// keeps it terminating instead of recursing forever).
func TestSymmetricRelation_ReverseInsertIdempotent(t *testing.T) {
	a := seedTarget(t, "A-idempotent")
	b := seedTarget(t, "B-idempotent")

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type, created_by)
		 VALUES ($1, $2, 'similar_structure', 'human')`,
		a, b,
	); err != nil {
		t.Fatalf("inserting first direction: %v", err)
	}

	if _, err := testPool.Exec(t.Context(),
		`INSERT INTO learning_target_relations (anchor_id, related_id, relation_type, created_by)
		 VALUES ($1, $2, 'similar_structure', 'human')
		 ON CONFLICT DO NOTHING`,
		b, a,
	); err != nil {
		t.Fatalf("manual reverse insert should be a no-op: %v", err)
	}

	if got := countRelations(t, a, b, "similar_structure"); got != 1 {
		t.Errorf("forward similar_structure count = %d, want 1", got)
	}
	if got := countRelations(t, b, a, "similar_structure"); got != 1 {
		t.Errorf("reverse similar_structure count = %d, want 1 (no duplicate)", got)
	}
}

// =========================================================================
// Section 2: Session concurrency
// =========================================================================

// TestStartSession_ConcurrentStart_OnlyOneWins — the
// uq_learning_sessions_one_active partial unique index makes concurrent
// StartSession calls on the same domain safe: exactly one wins with a
// live session, every other caller gets ErrActiveExists. Without the
// partial unique index, the in-process ActiveSession check is a TOCTOU
// window; the DB constraint is the real guarantee. A future migration
// that drops the partial unique index must fail this test.
func TestStartSession_ConcurrentStart_OnlyOneWins(t *testing.T) {
	truncateLearningTables(t)

	store := learning.NewStore(testPool)

	const callers = 10
	var (
		wg              sync.WaitGroup
		successCount    atomic.Int32
		activeExistsErr atomic.Int32
		otherErrs       atomic.Int32
	)

	for range callers {
		wg.Go(func() {
			_, _, err := store.StartSession(t.Context(), "leetcode", learning.ModePractice, nil)
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, learning.ErrActiveExists):
				activeExistsErr.Add(1)
			default:
				otherErrs.Add(1)
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()

	if got := successCount.Load(); got != 1 {
		t.Errorf("successful StartSession count = %d, want 1", got)
	}
	if got := activeExistsErr.Load(); got != callers-1 {
		t.Errorf("ErrActiveExists count = %d, want %d", got, callers-1)
	}
	if got := otherErrs.Load(); got != 0 {
		t.Errorf("unexpected error count = %d, want 0", got)
	}
}

// TestCreateDomain_HappyPath exercises the real store path behind the
// learning_domain decision-stamp create. A valid kebab-case slug must
// produce a learning_domains row (active=true) and become visible via
// Domains()/DomainExists(). Uses a unique slug so it does not collide with
// the migration-seeded domains, and cleans up after itself since
// learning_domains is outside truncateLearningTables.
func TestCreateDomain_HappyPath(t *testing.T) {
	store := learning.NewStore(testPool)
	slug := "w8-test-domain"

	// Clean any leftover from a prior interrupted run, and after this test.
	cleanup := func() {
		if _, err := testPool.Exec(context.Background(),
			`DELETE FROM learning_domains WHERE slug = $1`, slug); err != nil {
			t.Logf("cleanup learning_domains %q: %v", slug, err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	d, err := store.CreateDomain(t.Context(), slug, "W8 Test Domain")
	if err != nil {
		t.Fatalf("CreateDomain(%q): %v", slug, err)
	}
	if d.Slug != slug {
		t.Errorf("CreateDomain slug = %q, want %q", d.Slug, slug)
	}
	if d.Name != "W8 Test Domain" {
		t.Errorf("CreateDomain name = %q, want %q", d.Name, "W8 Test Domain")
	}
	if !d.Active {
		t.Errorf("CreateDomain active = false, want true")
	}

	exists, err := store.DomainExists(t.Context(), slug)
	if err != nil {
		t.Fatalf("DomainExists(%q): %v", slug, err)
	}
	if !exists {
		t.Errorf("DomainExists(%q) = false after create, want true", slug)
	}
}

// TestListDomains_HTTP exercises GET /api/admin/learning/domains end to end
// against a real database: a created domain must appear in the handler's
// {data:[...]} envelope, and the list is always a JSON array.
func TestListDomains_HTTP(t *testing.T) {
	store := learning.NewStore(testPool)
	slug := "w8-list-test-domain"

	cleanup := func() {
		if _, err := testPool.Exec(context.Background(),
			`DELETE FROM learning_domains WHERE slug = $1`, slug); err != nil {
			t.Logf("cleanup learning_domains %q: %v", slug, err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := store.CreateDomain(t.Context(), slug, "W8 List Test Domain"); err != nil {
		t.Fatalf("CreateDomain(%q): %v", slug, err)
	}

	h := learning.NewHandler(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/learning/domains", http.NoBody)
	w := httptest.NewRecorder()
	h.ListDomains(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListDomains status = %d, want %d (body: %s)", w.Code, http.StatusOK, w.Body.String())
	}

	var resp struct {
		Data []learning.Domain `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal ListDomains response: %v (body: %s)", err, w.Body.String())
	}
	if !slices.ContainsFunc(resp.Data, func(d learning.Domain) bool { return d.Slug == slug }) {
		t.Errorf("ListDomains response missing created domain %q (got %d domains)", slug, len(resp.Data))
	}
}

// =========================================================================
// Section 3: Target attempts endpoint (audit-gate picker)
// =========================================================================

// seedPickerAttempt inserts attempt #number on the target, backdated by
// ageMinutes so the newest-first (attempted_at DESC) ordering is
// deterministic. The explicit attempt_number satisfies the per-target
// uniqueness index (idx_learning_attempts_item_number). Unlike seedAttempt
// (dashboard suite), outcome and the nullable duration are
// caller-controlled so the picker-field assertions can cover both the
// populated and the omitted duration_minutes row.
func seedPickerAttempt(t *testing.T, sessionID, targetID uuid.UUID, number int32, outcome string, duration *int32, ageMinutes int32) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(t.Context(),
		`INSERT INTO learning_attempts (session_id, learning_target_id, attempt_number, paradigm, outcome, duration_minutes, attempted_at)
		 VALUES ($1, $2, $3, 'problem_solving', $4, $5, now() - make_interval(mins => $6))
		 RETURNING id`,
		sessionID, targetID, number, outcome, duration, ageMinutes,
	).Scan(&id); err != nil {
		t.Fatalf("seeding attempt (%s): %v", outcome, err)
	}
	return id
}

// TestTargetAttempts_HTTP drives GET /api/admin/learning/targets/{id}/attempts
// end to end: newest-first ordering with the picker fields populated, the
// limit bound (1-100, default 20), and the 404-free empty contract — a target
// with no attempts (or an unknown id) returns 200 with an empty list so the
// audit-gate picker renders empty instead of erroring.
func TestTargetAttempts_HTTP(t *testing.T) {
	truncateLearningTables(t)

	target := seedTarget(t, "Target Attempts Endpoint")
	emptyTarget := seedTarget(t, "Target Without Attempts")
	session := seedSession(t, "leetcode")

	dur := int32(25)
	oldest := seedPickerAttempt(t, session, target, 1, "gave_up", nil, 180)
	middle := seedPickerAttempt(t, session, target, 2, "solved_with_hint", &dur, 120)
	newest := seedPickerAttempt(t, session, target, 3, "solved_independent", &dur, 60)

	h := learning.NewHandler(learning.NewStore(testPool), slog.New(slog.NewTextHandler(io.Discard, nil)))

	get := func(t *testing.T, targetID, query string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet,
			"/api/admin/learning/targets/"+targetID+"/attempts"+query, http.NoBody)
		req.SetPathValue("id", targetID)
		w := httptest.NewRecorder()
		h.TargetAttempts(w, req)
		return w
	}

	decode := func(t *testing.T, body []byte) []learning.Attempt {
		t.Helper()
		var resp struct {
			Data []learning.Attempt `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal response: %v (body: %s)", err, body)
		}
		if resp.Data == nil {
			t.Fatalf("data = null, want JSON array (body: %s)", body)
		}
		return resp.Data
	}

	attemptIDs := func(atts []learning.Attempt) []uuid.UUID {
		ids := make([]uuid.UUID, len(atts))
		for i, a := range atts {
			ids[i] = a.ID
		}
		return ids
	}

	t.Run("newest first with picker fields", func(t *testing.T) {
		w := get(t, target.String(), "")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		got := decode(t, w.Body.Bytes())
		if diff := cmp.Diff([]uuid.UUID{newest, middle, oldest}, attemptIDs(got)); diff != "" {
			t.Fatalf("attempt order mismatch (-want +got):\n%s", diff)
		}

		first := got[0]
		if first.Outcome != "solved_independent" {
			t.Errorf("first outcome = %q, want %q", first.Outcome, "solved_independent")
		}
		if first.SessionID != session {
			t.Errorf("first session_id = %s, want %s", first.SessionID, session)
		}
		if first.CreatedAt.IsZero() {
			t.Errorf("first created_at is zero, want populated")
		}
		if first.DurationMinutes == nil || *first.DurationMinutes != dur {
			t.Errorf("first duration_minutes = %v, want %d", first.DurationMinutes, dur)
		}
		if last := got[2]; last.DurationMinutes != nil {
			t.Errorf("last duration_minutes = %v, want omitted (seeded NULL)", *last.DurationMinutes)
		}
	})

	t.Run("limit caps the page at the newest rows", func(t *testing.T) {
		w := get(t, target.String(), "?limit=2")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		got := decode(t, w.Body.Bytes())
		if diff := cmp.Diff([]uuid.UUID{newest, middle}, attemptIDs(got)); diff != "" {
			t.Errorf("limited page mismatch (-want +got):\n%s", diff)
		}
	})

	emptyTests := []struct {
		name     string
		targetID string
	}{
		{name: "target with no attempts", targetID: emptyTarget.String()},
		{name: "unknown target id", targetID: uuid.NewString()},
	}
	for _, tt := range emptyTests {
		t.Run(tt.name+" returns empty list not 404", func(t *testing.T) {
			w := get(t, tt.targetID, "")
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			if got := decode(t, w.Body.Bytes()); len(got) != 0 {
				t.Errorf("len(data) = %d, want 0", len(got))
			}
		})
	}

	limitTests := []struct {
		name  string
		query string
	}{
		{name: "limit zero", query: "?limit=0"},
		{name: "limit above max", query: "?limit=101"},
		{name: "limit not a number", query: "?limit=abc"},
	}
	for _, tt := range limitTests {
		t.Run(tt.name+" rejects with 400", func(t *testing.T) {
			w := get(t, target.String(), tt.query)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
		})
	}

	t.Run("invalid target id rejects with 400", func(t *testing.T) {
		w := get(t, "not-a-uuid", "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
		}
	})
}
