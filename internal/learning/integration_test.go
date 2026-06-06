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
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"

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
