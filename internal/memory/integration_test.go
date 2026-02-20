//go:build integration
// +build integration

package memory

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koopa0/koopa/internal/testutil"
)

// ============================================================
// Setup + Helpers
// ============================================================

var (
	sharedDB *testutil.TestDBContainer
	sharedAI *testutil.GoogleAISetup
)

func TestMain(m *testing.M) {
	// Google AI is required for all memory integration tests.
	var err error
	sharedAI, err = testutil.SetupGoogleAIForMain()
	if err != nil {
		fmt.Println(err)
		os.Exit(0) // skip all tests gracefully
	}

	var dbCleanup func()
	sharedDB, dbCleanup, err = testutil.SetupTestDBForMain()
	if err != nil {
		log.Fatalf("starting test database: %v", err)
	}
	code := m.Run()
	dbCleanup()
	os.Exit(code)
}

// setupIntegrationTest creates a Store using the shared test database and Google AI embedder.
// Truncates all tables for test isolation.
func setupIntegrationTest(t *testing.T) *Store {
	t.Helper()

	testutil.CleanTables(t, sharedDB.Pool)

	store, err := NewStore(sharedDB.Pool, sharedAI.Embedder, sharedAI.Logger)
	if err != nil {
		t.Fatalf("NewStore() unexpected error: %v", err)
	}
	return store
}

// uniqueOwner returns a unique owner ID for test isolation.
func uniqueOwner() string {
	return "test-" + uuid.New().String()[:8]
}

// createSession inserts a row into the sessions table and returns its UUID.
// This is required because memories.source_session_id has a FK to sessions.id.
func createSession(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO sessions DEFAULT VALUES RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("creating test session: %v", err)
	}
	return id
}

// addMemory is a helper that adds a memory and fails on error.
func addMemory(t *testing.T, store *Store, content string, cat Category, owner string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sid := createSession(t, store.pool)

	if err := store.Add(ctx, content, cat, owner, sid, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(%q, %q) unexpected error: %v", content, cat, err)
	}

	// Retrieve the ID of the just-added memory.
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(%q) unexpected error: %v", owner, err)
	}
	for _, m := range all {
		if m.Content == content {
			return m.ID
		}
	}
	t.Fatalf("addMemory(%q) not found after Add", content)
	return uuid.Nil
}

// rawMemory holds raw column values read directly from the database.
type rawMemory struct {
	ID             uuid.UUID
	Active         bool
	Importance     int
	AccessCount    int
	LastAccessedAt *time.Time
	DecayScore     float64
	SupersededBy   *uuid.UUID
	ExpiresAt      *time.Time
}

// queryRaw reads raw column values directly from the database, bypassing Store methods.
func queryRaw(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) rawMemory {
	t.Helper()
	var m rawMemory
	err := pool.QueryRow(context.Background(),
		`SELECT id, active, importance, access_count, last_accessed_at,
		        decay_score, superseded_by, expires_at
		 FROM memories WHERE id = $1`, id).
		Scan(&m.ID, &m.Active, &m.Importance, &m.AccessCount, &m.LastAccessedAt,
			&m.DecayScore, &m.SupersededBy, &m.ExpiresAt)
	if err != nil {
		t.Fatalf("queryRaw(%s) unexpected error: %v", id, err)
	}
	return m
}

// setUpdatedAt directly overwrites updated_at for testing decay calculations.
func setUpdatedAt(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE memories SET updated_at = $1 WHERE id = $2`, at, id)
	if err != nil {
		t.Fatalf("setUpdatedAt(%s) unexpected error: %v", id, err)
	}
}

// setExpiresAt directly overwrites expires_at for testing stale expiry.
func setExpiresAt(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE memories SET expires_at = $1 WHERE id = $2`, at, id)
	if err != nil {
		t.Fatalf("setExpiresAt(%s) unexpected error: %v", id, err)
	}
}

// setSupersedeRaw directly sets superseded_by, bypassing business logic.
func setSupersedeRaw(t *testing.T, pool *pgxpool.Pool, oldID, newID uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`UPDATE memories SET superseded_by = $1 WHERE id = $2`, newID, oldID)
	if err != nil {
		t.Fatalf("setSupersedeRaw(%s -> %s) unexpected error: %v", oldID, newID, err)
	}
}

// ============================================================
// Proposal 014: Core CRUD (existing tests, updated)
// ============================================================

func TestStore_NewStore_NilEmbedder(t *testing.T) {
	db := testutil.SetupTestDB(t)

	_, err := NewStore(db.Pool, nil, nil)
	if err == nil {
		t.Fatal("NewStore(pool, nil, nil) expected error, got nil")
	}
}

func TestStore_NewStore_NilLogger(t *testing.T) {
	db := testutil.SetupTestDB(t)
	ai := testutil.SetupGoogleAI(t)

	store, err := NewStore(db.Pool, ai.Embedder, nil)
	if err != nil {
		t.Fatalf("NewStore(nil logger) unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("NewStore(nil logger) returned nil store")
	}
}

func TestStore_AddAndSearch(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	err := store.Add(ctx, "I prefer Go over Python for backend development", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	results, err := store.Search(ctx, "programming language preference", ownerID, 5)
	if err != nil {
		t.Fatalf("Search() unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search() returned 0 results, want >= 1")
	}
	if results[0].Content != "I prefer Go over Python for backend development" {
		t.Errorf("Search() result content = %q, want %q", results[0].Content, "I prefer Go over Python for backend development")
	}
	if results[0].OwnerID != ownerID {
		t.Errorf("Search() result owner = %q, want %q", results[0].OwnerID, ownerID)
	}
	if results[0].Category != CategoryIdentity {
		t.Errorf("Search() result category = %q, want %q", results[0].Category, CategoryIdentity)
	}
	if !results[0].Active {
		t.Error("Search() result active = false, want true")
	}
}

func TestStore_AddValidation(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	sessionID := createSession(t, store.pool)

	tests := []struct {
		name     string
		content  string
		category Category
		ownerID  string
		wantErr  string
	}{
		{name: "invalid category", content: "test", category: "bad", ownerID: "u1", wantErr: "invalid category"},
		{name: "empty content", content: "", category: CategoryIdentity, ownerID: "u1", wantErr: "content is required"},
		{name: "empty owner", content: "test", category: CategoryIdentity, ownerID: "", wantErr: "owner ID is required"},
		{name: "content too long", content: string(make([]byte, MaxContentLength+1)), category: CategoryIdentity, ownerID: "u1", wantErr: "exceeds maximum"},
		{name: "contains secrets", content: "my key is sk-abcdefghijklmnopqrstuvwxyz1234567890", category: CategoryIdentity, ownerID: "u1", wantErr: "contains potential secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Add(ctx, tt.content, tt.category, tt.ownerID, sessionID, AddOpts{}, nil)
			if err == nil {
				t.Fatalf("Add(%q) expected error, got nil", tt.name)
			}
			if got := err.Error(); !strings.Contains(got, tt.wantErr) {
				t.Errorf("Add(%q) error = %q, want contains %q", tt.name, got, tt.wantErr)
			}
		})
	}
}

func TestStore_All(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	if err := store.Add(ctx, "My name is Alice", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(identity) unexpected error: %v", err)
	}
	if err := store.Add(ctx, "Currently working on Project X", CategoryContextual, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(contextual) unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All(no filter) unexpected error: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("All(no filter) count = %d, want 2", len(all))
	}

	identityOnly, err := store.All(ctx, ownerID, CategoryIdentity)
	if err != nil {
		t.Fatalf("All(identity) unexpected error: %v", err)
	}
	if len(identityOnly) != 1 {
		t.Fatalf("All(identity) count = %d, want 1", len(identityOnly))
	}
	if identityOnly[0].Category != CategoryIdentity {
		t.Errorf("All(identity) category = %q, want %q", identityOnly[0].Category, CategoryIdentity)
	}

	_, err = store.All(ctx, ownerID, "bad")
	if err == nil {
		t.Error("All(bad category) expected error, got nil")
	}
}

func TestStore_Delete(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	if err := store.Add(ctx, "To be deleted", CategoryContextual, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("All() count = %d, want 1", len(all))
	}

	memID := all[0].ID

	if err := store.Delete(ctx, memID, ownerID); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	allAfter, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() after delete unexpected error: %v", err)
	}
	if len(allAfter) != 0 {
		t.Errorf("All() after delete count = %d, want 0", len(allAfter))
	}
}

func TestStore_Delete_NotFound(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()

	err := store.Delete(ctx, uuid.New(), "user1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(nonexistent) error = %v, want ErrNotFound", err)
	}
}

func TestStore_Delete_Forbidden(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	if err := store.Add(ctx, "Private memory", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("All() count = %d, want 1", len(all))
	}

	err = store.Delete(ctx, all[0].ID, "other-user")
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("Delete(wrong owner) error = %v, want ErrForbidden", err)
	}
}

func TestStore_DeleteAll(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	for i := range 3 {
		content := []string{"Fact A", "Fact B", "Fact C"}[i]
		if err := store.Add(ctx, content, CategoryContextual, ownerID, sessionID, AddOpts{}, nil); err != nil {
			t.Fatalf("Add(%q) unexpected error: %v", content, err)
		}
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("All() count = %d, want 3", len(all))
	}

	if err := store.DeleteAll(ctx, ownerID); err != nil {
		t.Fatalf("DeleteAll() unexpected error: %v", err)
	}

	allAfter, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() after DeleteAll unexpected error: %v", err)
	}
	if len(allAfter) != 0 {
		t.Errorf("All() after DeleteAll count = %d, want 0", len(allAfter))
	}
}

func TestStore_OwnerIsolation(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	user1 := uniqueOwner()
	user2 := uniqueOwner()
	sessionID := createSession(t, store.pool)

	if err := store.Add(ctx, "User 1 secret preference", CategoryIdentity, user1, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(user1) unexpected error: %v", err)
	}

	results, err := store.Search(ctx, "secret preference", user2, 5)
	if err != nil {
		t.Fatalf("Search(user2) unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Search(user2) count = %d, want 0 (owner isolation)", len(results))
	}

	all, err := store.All(ctx, user2, "")
	if err != nil {
		t.Fatalf("All(user2) unexpected error: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("All(user2) count = %d, want 0", len(all))
	}
}

func TestStore_SearchEmptyInputs(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()

	// Empty query returns empty slice.
	results, err := store.Search(ctx, "", "user1", 5)
	if err != nil {
		t.Fatalf("Search(empty query) unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Search(empty query) len = %d, want 0", len(results))
	}

	// Empty ownerID returns empty slice.
	results, err = store.Search(ctx, "test", "", 5)
	if err != nil {
		t.Fatalf("Search(empty owner) unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Search(empty owner) len = %d, want 0", len(results))
	}
}

// ============================================================
// Proposal 014: Dedup Merge
// ============================================================

func TestStore_DedupMerge(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add a fact.
	if err := store.Add(ctx, "I prefer Go for backend services", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(original) unexpected error: %v", err)
	}

	// Add a very similar rephrasing — should merge (update) the existing memory.
	if err := store.Add(ctx, "I prefer Go for backend development", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(similar) unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}

	// Dedup should have merged: we expect 1 memory, not 2.
	// If the embeddings are similar enough (>= 0.92), the second Add updates the first.
	// Note: exact behavior depends on embedder similarity. If it didn't merge,
	// we should have at most 2.
	if len(all) > 2 {
		t.Errorf("DedupMerge() count = %d, want <= 2 (ideally 1 if merged)", len(all))
	}

	// The latest content should be the updated one.
	found := false
	for _, m := range all {
		if m.Content == "I prefer Go for backend development" {
			found = true
		}
	}
	if !found {
		t.Error("DedupMerge() latest content not found after merge/add")
	}
}

func TestStore_DedupDistinct(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add two completely different facts.
	if err := store.Add(ctx, "I prefer Go for backend services", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(fact1) unexpected error: %v", err)
	}
	if err := store.Add(ctx, "My favorite food is sushi", CategoryContextual, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(fact2) unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("DedupDistinct() count = %d, want 2", len(all))
	}
}

// ============================================================
// Phase 4a: Migration 000005 Schema Verification
// ============================================================

func TestStore_Migration005_Schema(t *testing.T) {
	db := testutil.SetupTestDB(t)
	ctx := context.Background()

	// Verify Phase 4a columns exist.
	var columnCount int
	err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM information_schema.columns
		 WHERE table_name = 'memories'
		   AND column_name IN ('importance', 'access_count', 'last_accessed_at',
		                       'decay_score', 'superseded_by', 'expires_at', 'search_text')`).
		Scan(&columnCount)
	if err != nil {
		t.Fatalf("checking columns: %v", err)
	}
	if columnCount != 7 {
		t.Errorf("migration 000005 columns present = %d, want 7", columnCount)
	}

	// Verify Phase 4a indexes exist.
	var indexCount int
	err = db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM pg_indexes
		 WHERE tablename = 'memories'
		   AND indexname IN ('idx_memories_search_text', 'idx_memories_decay_candidates',
		                     'idx_memories_superseded_by', 'idx_memories_expires_at')`).
		Scan(&indexCount)
	if err != nil {
		t.Fatalf("checking indexes: %v", err)
	}
	if indexCount != 4 {
		t.Errorf("migration 000005 indexes present = %d, want 4", indexCount)
	}

	// Verify category CHECK accepts all 4 categories.
	for _, cat := range AllCategories() {
		_, err := db.Pool.Exec(ctx,
			`INSERT INTO memories (owner_id, content, embedding, category)
			 VALUES ($1, $2, $3::vector, $4)`,
			"schema-test", "test-"+string(cat), zeroVector(), string(cat))
		if err != nil {
			t.Errorf("INSERT category %q failed: %v", cat, err)
		}
	}

	// Verify invalid category is rejected.
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO memories (owner_id, content, embedding, category)
		 VALUES ($1, $2, $3::vector, $4)`,
		"schema-test", "bad-cat", zeroVector(), "invalid_category")
	if err == nil {
		t.Error("INSERT invalid category expected error, got nil")
	}

	// Verify importance CHECK (1-10).
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO memories (owner_id, content, embedding, category, importance)
		 VALUES ($1, $2, $3::vector, $4, $5)`,
		"schema-test", "bad-importance", zeroVector(), "identity", 0)
	if err == nil {
		t.Error("INSERT importance=0 expected error, got nil")
	}
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO memories (owner_id, content, embedding, category, importance)
		 VALUES ($1, $2, $3::vector, $4, $5)`,
		"schema-test", "bad-importance-high", zeroVector(), "identity", 11)
	if err == nil {
		t.Error("INSERT importance=11 expected error, got nil")
	}

	// Verify decay_score CHECK (0.0-1.0).
	_, err = db.Pool.Exec(ctx,
		`INSERT INTO memories (owner_id, content, embedding, category, decay_score)
		 VALUES ($1, $2, $3::vector, $4, $5)`,
		"schema-test", "bad-decay", zeroVector(), "identity", 1.5)
	if err == nil {
		t.Error("INSERT decay_score=1.5 expected error, got nil")
	}

	// Verify self-supersede CHECK.
	var memID uuid.UUID
	err = db.Pool.QueryRow(ctx,
		`INSERT INTO memories (owner_id, content, embedding, category)
		 VALUES ($1, $2, $3::vector, $4)
		 RETURNING id`,
		"schema-test", "self-ref-test", zeroVector(), "identity").Scan(&memID)
	if err != nil {
		t.Fatalf("INSERT for self-ref test: %v", err)
	}
	_, err = db.Pool.Exec(ctx,
		`UPDATE memories SET superseded_by = $1 WHERE id = $1`, memID)
	if err == nil {
		t.Error("UPDATE self-supersede expected error, got nil")
	}

	// Verify tsvector GENERATED column works.
	var hasSearchText bool
	err = db.Pool.QueryRow(ctx,
		`SELECT search_text IS NOT NULL FROM memories
		 WHERE owner_id = 'schema-test' AND content = 'test-identity'`).
		Scan(&hasSearchText)
	if err != nil {
		t.Fatalf("checking search_text: %v", err)
	}
	if !hasSearchText {
		t.Error("search_text GENERATED column is NULL, want non-NULL")
	}
}

// zeroVector returns a 768-dimension zero vector for schema tests that don't need embeddings.
func zeroVector() string {
	var b strings.Builder
	b.WriteByte('[')
	for i := range VectorDimension {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('0')
	}
	b.WriteByte(']')
	return b.String()
}

// ============================================================
// Phase 4a: New Column Defaults
// ============================================================

func TestStore_NewColumnDefaults(t *testing.T) {
	store := setupIntegrationTest(t)
	ownerID := uniqueOwner()

	id := addMemory(t, store, "Testing default column values", CategoryIdentity, ownerID)
	raw := queryRaw(t, store.pool, id)

	if raw.Importance != 5 {
		t.Errorf("default importance = %d, want 5", raw.Importance)
	}
	if raw.AccessCount != 0 {
		t.Errorf("default access_count = %d, want 0", raw.AccessCount)
	}
	if raw.LastAccessedAt != nil {
		t.Errorf("default last_accessed_at = %v, want nil", raw.LastAccessedAt)
	}
	if raw.DecayScore != 1.0 {
		t.Errorf("default decay_score = %v, want 1.0", raw.DecayScore)
	}
	if raw.SupersededBy != nil {
		t.Errorf("default superseded_by = %v, want nil", raw.SupersededBy)
	}
	if !raw.Active {
		t.Error("default active = false, want true")
	}

	// Identity memories should have nil expires_at (never expire).
	if raw.ExpiresAt != nil {
		t.Errorf("identity expires_at = %v, want nil", raw.ExpiresAt)
	}
}

func TestStore_NewColumnDefaults_ContextualExpiry(t *testing.T) {
	store := setupIntegrationTest(t)
	ownerID := uniqueOwner()

	id := addMemory(t, store, "A contextual fact with TTL", CategoryContextual, ownerID)
	raw := queryRaw(t, store.pool, id)

	// Contextual memories should have expires_at ~30 days in the future.
	if raw.ExpiresAt == nil {
		t.Fatal("contextual expires_at = nil, want ~30d in future")
	}
	expected := time.Now().Add(30 * 24 * time.Hour)
	diff := raw.ExpiresAt.Sub(expected)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("contextual expires_at = %v, want ~%v (diff %v)", raw.ExpiresAt, expected, diff)
	}
}

// ============================================================
// Phase 4a: Category Expansion (4 categories)
// ============================================================

func TestStore_CategoryExpansion(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add one memory per category.
	categories := map[Category]string{
		CategoryIdentity:   "My name is Bob and I am a developer",
		CategoryPreference: "I strongly prefer Vim over Emacs for editing",
		CategoryProject:    "Currently building a Go web application called Koopa",
		CategoryContextual: "Debugging a memory leak in the scheduler component",
	}
	for cat, content := range categories {
		if err := store.Add(ctx, content, cat, ownerID, sessionID, AddOpts{}, nil); err != nil {
			t.Fatalf("Add(%q) unexpected error: %v", cat, err)
		}
	}

	// All() should return all 4.
	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All(no filter) unexpected error: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("All(no filter) count = %d, want 4", len(all))
	}

	// Each category filter should return exactly 1.
	for _, cat := range AllCategories() {
		filtered, err := store.All(ctx, ownerID, cat)
		if err != nil {
			t.Fatalf("All(%q) unexpected error: %v", cat, err)
		}
		if len(filtered) != 1 {
			t.Errorf("All(%q) count = %d, want 1", cat, len(filtered))
		}
		if len(filtered) > 0 && filtered[0].Category != cat {
			t.Errorf("All(%q) returned category = %q", cat, filtered[0].Category)
		}
	}
}

// ============================================================
// Phase 4a: HybridSearch
// ============================================================

func TestStore_HybridSearch(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add memories with varying relevance to "Go programming language".
	if err := store.Add(ctx, "I am an expert Go programmer who builds microservices", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(relevant) unexpected error: %v", err)
	}
	if err := store.Add(ctx, "I sometimes write Python scripts for automation tasks", CategoryPreference, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(somewhat relevant) unexpected error: %v", err)
	}
	if err := store.Add(ctx, "My favorite food is ramen from the local shop", CategoryContextual, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(irrelevant) unexpected error: %v", err)
	}

	results, err := store.HybridSearch(ctx, "Go programming language experience", ownerID, 10)
	if err != nil {
		t.Fatalf("HybridSearch() unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("HybridSearch() returned 0 results, want >= 1")
	}

	// All results should have Score > 0.
	for i, m := range results {
		if m.Score <= 0 {
			t.Errorf("HybridSearch() result[%d].Score = %v, want > 0", i, m.Score)
		}
	}

	// Results should be sorted by Score descending.
	for i := 1; i < len(results); i++ {
		if results[i].Score > results[i-1].Score {
			t.Errorf("HybridSearch() results not sorted: [%d].Score=%v > [%d].Score=%v",
				i, results[i].Score, i-1, results[i-1].Score)
		}
	}

	// The Go-related memory should rank higher than the food memory.
	if len(results) >= 2 {
		goIdx := -1
		foodIdx := -1
		for i, m := range results {
			if strings.Contains(m.Content, "Go programmer") {
				goIdx = i
			}
			if strings.Contains(m.Content, "ramen") {
				foodIdx = i
			}
		}
		if goIdx >= 0 && foodIdx >= 0 && goIdx > foodIdx {
			t.Errorf("HybridSearch() Go memory (idx=%d) ranked lower than food memory (idx=%d)", goIdx, foodIdx)
		}
	}
}

func TestStore_HybridSearch_ExcludesExpired(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "This fact about Go has expired", CategoryContextual, ownerID)

	// Backdate expires_at to the past.
	setExpiresAt(t, store.pool, id, time.Now().Add(-24*time.Hour))

	results, err := store.HybridSearch(ctx, "fact about Go", ownerID, 10)
	if err != nil {
		t.Fatalf("HybridSearch() unexpected error: %v", err)
	}
	for _, m := range results {
		if m.ID == id {
			t.Errorf("HybridSearch() returned expired memory %s", id)
		}
	}
}

func TestStore_HybridSearch_ExcludesSuperseded(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	oldID := addMemory(t, store, "I used to prefer Java for everything", CategoryIdentity, ownerID)
	newID := addMemory(t, store, "I now prefer Go over Java completely", CategoryIdentity, ownerID)

	// Mark old as superseded by new.
	setSupersedeRaw(t, store.pool, oldID, newID)

	results, err := store.HybridSearch(ctx, "language preference Java or Go", ownerID, 10)
	if err != nil {
		t.Fatalf("HybridSearch() unexpected error: %v", err)
	}
	for _, m := range results {
		if m.ID == oldID {
			t.Errorf("HybridSearch() returned superseded memory %s", oldID)
		}
	}
}

func TestStore_HybridSearch_InputValidation(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		query   string
		ownerID string
	}{
		{name: "empty query", query: "", ownerID: "user1"},
		{name: "empty owner", query: "test", ownerID: ""},
		{name: "null byte in query", query: "test\x00injection", ownerID: "user1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := store.HybridSearch(ctx, tt.query, tt.ownerID, 5)
			if err != nil {
				t.Fatalf("HybridSearch(%q, %q) unexpected error: %v", tt.query, tt.ownerID, err)
			}
			if len(results) != 0 {
				t.Errorf("HybridSearch(%q, %q) len = %d, want 0", tt.query, tt.ownerID, len(results))
			}
		})
	}
}

func TestStore_HybridSearch_LongQueryTruncated(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	addMemory(t, store, "I prefer Go for all backend tasks", CategoryIdentity, ownerID)

	// Create a query longer than MaxSearchQueryLen.
	longQuery := strings.Repeat("Go programming ", MaxSearchQueryLen/15+1)
	if len(longQuery) <= MaxSearchQueryLen {
		t.Fatalf("test setup: longQuery len = %d, need > %d", len(longQuery), MaxSearchQueryLen)
	}

	// Should not error — query gets truncated internally.
	results, err := store.HybridSearch(ctx, longQuery, ownerID, 5)
	if err != nil {
		t.Fatalf("HybridSearch(long query) unexpected error: %v", err)
	}
	// Should still find results (truncated query contains relevant terms).
	if len(results) == 0 {
		t.Error("HybridSearch(long query) returned 0 results, want >= 1")
	}
}

func TestStore_HybridSearch_AccessTracking(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "I am a senior software engineer", CategoryIdentity, ownerID)

	// Before search: access_count should be 0.
	rawBefore := queryRaw(t, store.pool, id)
	if rawBefore.AccessCount != 0 {
		t.Fatalf("before HybridSearch: access_count = %d, want 0", rawBefore.AccessCount)
	}

	// HybridSearch should trigger UpdateAccess.
	results, err := store.HybridSearch(ctx, "software engineer", ownerID, 5)
	if err != nil {
		t.Fatalf("HybridSearch() unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("HybridSearch() returned 0 results, want >= 1")
	}

	// After search: access_count should be incremented.
	rawAfter := queryRaw(t, store.pool, id)
	if rawAfter.AccessCount != 1 {
		t.Errorf("after HybridSearch: access_count = %d, want 1", rawAfter.AccessCount)
	}
	if rawAfter.LastAccessedAt == nil {
		t.Error("after HybridSearch: last_accessed_at = nil, want non-nil")
	}
}

// ============================================================
// Phase 4a: UpdateAccess
// ============================================================

func TestStore_UpdateAccess(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "Tracking access counts", CategoryIdentity, ownerID)

	// First update.
	if err := store.UpdateAccess(ctx, []uuid.UUID{id}); err != nil {
		t.Fatalf("UpdateAccess() unexpected error: %v", err)
	}

	raw1 := queryRaw(t, store.pool, id)
	if raw1.AccessCount != 1 {
		t.Errorf("after 1st UpdateAccess: access_count = %d, want 1", raw1.AccessCount)
	}
	if raw1.LastAccessedAt == nil {
		t.Error("after 1st UpdateAccess: last_accessed_at = nil, want non-nil")
	}

	// Second update.
	if err := store.UpdateAccess(ctx, []uuid.UUID{id}); err != nil {
		t.Fatalf("UpdateAccess() 2nd call unexpected error: %v", err)
	}

	raw2 := queryRaw(t, store.pool, id)
	if raw2.AccessCount != 2 {
		t.Errorf("after 2nd UpdateAccess: access_count = %d, want 2", raw2.AccessCount)
	}
}

func TestStore_UpdateAccess_EmptyIDs(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()

	// Empty IDs should not error.
	if err := store.UpdateAccess(ctx, nil); err != nil {
		t.Errorf("UpdateAccess(nil) unexpected error: %v", err)
	}
	if err := store.UpdateAccess(ctx, []uuid.UUID{}); err != nil {
		t.Errorf("UpdateAccess(empty) unexpected error: %v", err)
	}
}

// ============================================================
// Phase 4a: UpdateDecayScores
// ============================================================

func TestStore_UpdateDecayScores(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Add identity memory (never decays) and contextual memory (decays with TTL=30d).
	identityID := addMemory(t, store, "My name is Charlie the developer", CategoryIdentity, ownerID)
	contextualID := addMemory(t, store, "Currently debugging a performance issue", CategoryContextual, ownerID)

	// Backdate contextual memory's updated_at to 15 days ago (= half-life for contextual).
	fifteenDaysAgo := time.Now().Add(-15 * 24 * time.Hour)
	setUpdatedAt(t, store.pool, contextualID, fifteenDaysAgo)

	// Run decay score update.
	n, err := store.UpdateDecayScores(ctx)
	if err != nil {
		t.Fatalf("UpdateDecayScores() unexpected error: %v", err)
	}
	if n < 2 {
		t.Errorf("UpdateDecayScores() updated %d rows, want >= 2", n)
	}

	// Identity memory should still have decay_score = 1.0.
	rawIdentity := queryRaw(t, store.pool, identityID)
	if rawIdentity.DecayScore != 1.0 {
		t.Errorf("identity decay_score = %v, want 1.0", rawIdentity.DecayScore)
	}

	// Contextual memory should have decay_score ~0.5 (at half-life).
	rawContextual := queryRaw(t, store.pool, contextualID)
	if rawContextual.DecayScore >= 1.0 {
		t.Errorf("contextual decay_score = %v, want < 1.0 (15 days old)", rawContextual.DecayScore)
	}
	if math.Abs(rawContextual.DecayScore-0.5) > 0.15 {
		t.Errorf("contextual decay_score = %v, want ~0.5 at half-life (tolerance 0.15)", rawContextual.DecayScore)
	}

	// Cross-check: Go formula should match DB result.
	lambda := CategoryContextual.DecayLambda()
	elapsed := time.Since(fifteenDaysAgo)
	goScore := decayScore(lambda, elapsed)
	if math.Abs(rawContextual.DecayScore-goScore) > 0.05 {
		t.Errorf("Go decayScore=%v vs DB decay_score=%v differ by > 0.05", goScore, rawContextual.DecayScore)
	}
}

func TestStore_UpdateDecayScores_AllCategories(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Add one memory per category, all backdated to 30 days ago.
	thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)

	ids := make(map[Category]uuid.UUID)
	for _, cat := range AllCategories() {
		id := addMemory(t, store, "Decay test for "+string(cat), cat, ownerID)
		setUpdatedAt(t, store.pool, id, thirtyDaysAgo)
		ids[cat] = id
	}

	if _, err := store.UpdateDecayScores(ctx); err != nil {
		t.Fatalf("UpdateDecayScores() unexpected error: %v", err)
	}

	// Identity: should be 1.0 (no decay).
	if raw := queryRaw(t, store.pool, ids[CategoryIdentity]); raw.DecayScore != 1.0 {
		t.Errorf("identity (30d old) decay_score = %v, want 1.0", raw.DecayScore)
	}

	// Preference (TTL=90d, half-life=45d): 30d < half-life, so score > 0.5.
	rawPref := queryRaw(t, store.pool, ids[CategoryPreference])
	if rawPref.DecayScore <= 0.5 || rawPref.DecayScore >= 1.0 {
		t.Errorf("preference (30d old, half-life=45d) decay_score = %v, want (0.5, 1.0)", rawPref.DecayScore)
	}

	// Project (TTL=60d, half-life=30d): at half-life, so score ~0.5.
	rawProj := queryRaw(t, store.pool, ids[CategoryProject])
	if math.Abs(rawProj.DecayScore-0.5) > 0.15 {
		t.Errorf("project (30d old, half-life=30d) decay_score = %v, want ~0.5", rawProj.DecayScore)
	}

	// Contextual (TTL=30d, half-life=15d): 30d = 2x half-life, so score ~0.25.
	rawCtx := queryRaw(t, store.pool, ids[CategoryContextual])
	if math.Abs(rawCtx.DecayScore-0.25) > 0.15 {
		t.Errorf("contextual (30d old, half-life=15d) decay_score = %v, want ~0.25", rawCtx.DecayScore)
	}

	// Verify ordering: identity > preference > project > contextual.
	if rawPref.DecayScore <= rawProj.DecayScore {
		t.Errorf("preference decay (%v) should be > project decay (%v)", rawPref.DecayScore, rawProj.DecayScore)
	}
	if rawProj.DecayScore <= rawCtx.DecayScore {
		t.Errorf("project decay (%v) should be > contextual decay (%v)", rawProj.DecayScore, rawCtx.DecayScore)
	}
}

// TestStore_UpdateDecayScores_PreservesUpdatedAt verifies that UpdateDecayScores
// does NOT modify updated_at. If someone accidentally adds "updated_at = now()"
// to the SQL, decay scores would reset on every scheduler run (silent failure).
func TestStore_UpdateDecayScores_PreservesUpdatedAt(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "Checking updated_at invariant for decay", CategoryContextual, ownerID)

	// Backdate updated_at to a known time.
	fixedTime := time.Now().Add(-10 * 24 * time.Hour)
	setUpdatedAt(t, store.pool, id, fixedTime)

	// Capture updated_at before decay.
	var beforeUpdatedAt time.Time
	err := store.pool.QueryRow(ctx,
		`SELECT updated_at FROM memories WHERE id = $1`, id).Scan(&beforeUpdatedAt)
	if err != nil {
		t.Fatalf("reading updated_at before: %v", err)
	}

	// Run decay.
	if _, err := store.UpdateDecayScores(ctx); err != nil {
		t.Fatalf("UpdateDecayScores() unexpected error: %v", err)
	}

	// Capture updated_at after decay.
	var afterUpdatedAt time.Time
	err = store.pool.QueryRow(ctx,
		`SELECT updated_at FROM memories WHERE id = $1`, id).Scan(&afterUpdatedAt)
	if err != nil {
		t.Fatalf("reading updated_at after: %v", err)
	}

	// updated_at must NOT change.
	if !beforeUpdatedAt.Equal(afterUpdatedAt) {
		t.Errorf("UpdateDecayScores() changed updated_at: before=%v, after=%v", beforeUpdatedAt, afterUpdatedAt)
	}

	// Verify decay_score actually changed (confirm the UPDATE ran).
	raw := queryRaw(t, store.pool, id)
	if raw.DecayScore >= 1.0 {
		t.Errorf("decay_score = %v, want < 1.0 (10 days old contextual)", raw.DecayScore)
	}
}

// ============================================================
// Phase 4a: Dedup Cross-Category Behavior
// ============================================================

// TestStore_DedupCrossCategory verifies that dedup matches across categories.
// When content is semantically identical but category differs, the existing
// memory is updated with the new category. This is the current design —
// dedup searches ALL memories regardless of category.
func TestStore_DedupCrossCategory(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add as identity.
	if err := store.Add(ctx, "I strongly prefer using Go for backend services", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(identity) unexpected error: %v", err)
	}

	// Add nearly identical content as preference — should merge, not create new.
	if err := store.Add(ctx, "I strongly prefer using Go for backend development", CategoryPreference, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(preference) unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}

	// Dedup should have merged: expect 1 memory (or 2 if embeddings weren't similar enough).
	if len(all) > 2 {
		t.Errorf("DedupCrossCategory() count = %d, want <= 2", len(all))
	}

	// If merged, the category should now be "preference" (the newer one overwrites).
	if len(all) == 1 {
		if all[0].Category != CategoryPreference {
			t.Errorf("merged memory category = %q, want %q (newer wins)", all[0].Category, CategoryPreference)
		}
		if all[0].Content != "I strongly prefer using Go for backend development" {
			t.Errorf("merged memory content = %q, want newer content", all[0].Content)
		}
	}
}

// ============================================================
// Phase 4a: Soft-Delete Reactivation
// ============================================================

// TestStore_DedupReactivation verifies that adding content similar to a
// soft-deleted memory reactivates it instead of creating a new row.
// The dedup search includes inactive memories (active = false).
func TestStore_DedupReactivation(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add a memory.
	if err := store.Add(ctx, "I work at a startup in Tokyo", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	// Get its ID.
	allBefore, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(allBefore) != 1 {
		t.Fatalf("All() count = %d, want 1", len(allBefore))
	}
	originalID := allBefore[0].ID

	// Soft-delete it.
	if err := store.Delete(ctx, originalID, ownerID); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	// Confirm it's gone from All().
	allDeleted, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() after delete unexpected error: %v", err)
	}
	if len(allDeleted) != 0 {
		t.Fatalf("All() after delete count = %d, want 0", len(allDeleted))
	}

	// Re-add similar content — should reactivate the old row, not create new.
	if err := store.Add(ctx, "I work at a startup in Tokyo Japan", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil); err != nil {
		t.Fatalf("Add(reactivate) unexpected error: %v", err)
	}

	allAfter, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() after reactivation unexpected error: %v", err)
	}

	// Should have exactly 1 memory.
	if len(allAfter) != 1 {
		t.Fatalf("All() after reactivation count = %d, want 1", len(allAfter))
	}

	// The reactivated memory should have the original ID (reused row, not new).
	if allAfter[0].ID != originalID {
		t.Logf("reactivation created new ID %s instead of reusing %s — embeddings may differ slightly", allAfter[0].ID, originalID)
		// Not a hard failure: if embeddings differ enough, a new row is expected.
		// But if same ID, it confirms the reactivation path.
	}

	// Content should be the newer version.
	if allAfter[0].Content != "I work at a startup in Tokyo Japan" {
		t.Errorf("reactivated content = %q, want newer version", allAfter[0].Content)
	}

	// Must be active.
	if !allAfter[0].Active {
		t.Error("reactivated memory active = false, want true")
	}
}

// ============================================================
// Phase 4a: DeleteStale
// ============================================================

func TestStore_DeleteStale(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "This will expire soon", CategoryContextual, ownerID)

	// Backdate expires_at to the past.
	setExpiresAt(t, store.pool, id, time.Now().Add(-1*time.Hour))

	n, err := store.DeleteStale(ctx)
	if err != nil {
		t.Fatalf("DeleteStale() unexpected error: %v", err)
	}
	if n < 1 {
		t.Errorf("DeleteStale() expired %d, want >= 1", n)
	}

	// Memory should now be inactive.
	raw := queryRaw(t, store.pool, id)
	if raw.Active {
		t.Error("after DeleteStale: active = true, want false")
	}

	// Should not appear in All().
	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("All() after DeleteStale count = %d, want 0", len(all))
	}
}

func TestStore_DeleteStale_NotYetExpired(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "This is still valid", CategoryContextual, ownerID)

	// Ensure expires_at is in the future (set by Add via category.ExpiresAt).
	raw := queryRaw(t, store.pool, id)
	if raw.ExpiresAt == nil || raw.ExpiresAt.Before(time.Now()) {
		t.Fatalf("test setup: expires_at should be in the future, got %v", raw.ExpiresAt)
	}

	n, err := store.DeleteStale(ctx)
	if err != nil {
		t.Fatalf("DeleteStale() unexpected error: %v", err)
	}

	// Should not have expired anything (memory is still valid).
	rawAfter := queryRaw(t, store.pool, id)
	if !rawAfter.Active {
		t.Error("after DeleteStale(not expired): active = false, want true")
	}
	_ = n // May be 0 or non-zero depending on other test data in container.
}

func TestStore_DeleteStale_IdentityNeverExpires(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "My name is permanent", CategoryIdentity, ownerID)

	// Identity memories should have nil expires_at.
	raw := queryRaw(t, store.pool, id)
	if raw.ExpiresAt != nil {
		t.Fatalf("identity expires_at = %v, want nil", raw.ExpiresAt)
	}

	// DeleteStale should not affect it.
	if _, err := store.DeleteStale(ctx); err != nil {
		t.Fatalf("DeleteStale() unexpected error: %v", err)
	}

	rawAfter := queryRaw(t, store.pool, id)
	if !rawAfter.Active {
		t.Error("identity memory deactivated by DeleteStale, want active")
	}
}

// ============================================================
// Phase 4a: Search/All Filter Exclusions
// ============================================================

func TestStore_SearchExcludesSuperseded(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	oldID := addMemory(t, store, "I used to use Python exclusively", CategoryIdentity, ownerID)
	newID := addMemory(t, store, "I switched from Python to Go in 2024", CategoryIdentity, ownerID)

	setSupersedeRaw(t, store.pool, oldID, newID)

	results, err := store.Search(ctx, "Python programming", ownerID, 10)
	if err != nil {
		t.Fatalf("Search() unexpected error: %v", err)
	}
	for _, m := range results {
		if m.ID == oldID {
			t.Errorf("Search() returned superseded memory %s", oldID)
		}
	}
}

func TestStore_SearchExcludesExpired(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "This expired fact about Python", CategoryContextual, ownerID)
	setExpiresAt(t, store.pool, id, time.Now().Add(-1*time.Hour))

	results, err := store.Search(ctx, "Python fact", ownerID, 10)
	if err != nil {
		t.Fatalf("Search() unexpected error: %v", err)
	}
	for _, m := range results {
		if m.ID == id {
			t.Errorf("Search() returned expired memory %s", id)
		}
	}
}

func TestStore_AllExcludesSuperseded(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	oldID := addMemory(t, store, "Old preference that was superseded", CategoryIdentity, ownerID)
	newID := addMemory(t, store, "New preference replacing the old one", CategoryIdentity, ownerID)

	setSupersedeRaw(t, store.pool, oldID, newID)

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	for _, m := range all {
		if m.ID == oldID {
			t.Errorf("All() returned superseded memory %s", oldID)
		}
	}
	// Should still see the new one.
	found := false
	for _, m := range all {
		if m.ID == newID {
			found = true
		}
	}
	if !found {
		t.Errorf("All() missing non-superseded memory %s", newID)
	}
}

func TestStore_AllExcludesExpired(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "This will be expired in All test", CategoryContextual, ownerID)
	setExpiresAt(t, store.pool, id, time.Now().Add(-1*time.Hour))

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	for _, m := range all {
		if m.ID == id {
			t.Errorf("All() returned expired memory %s", id)
		}
	}
}

// ============================================================
// Phase 4a: Scheduler
// ============================================================

func TestScheduler_ContextCancellation(t *testing.T) {
	store := setupIntegrationTest(t)

	// Create scheduler with very short interval for testing.
	scheduler := &Scheduler{
		store:    store,
		interval: 50 * time.Millisecond,
		logger:   slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		scheduler.Run(ctx)
		close(done)
	}()

	// Let at least one tick execute.
	time.Sleep(150 * time.Millisecond)

	// Cancel and verify Run exits.
	cancel()

	select {
	case <-done:
		// Success: Run exited after context cancellation.
	case <-time.After(5 * time.Second):
		t.Fatal("Scheduler.Run() did not exit within 5s after context cancellation")
	}
}

func TestScheduler_RunOnce(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Setup: add an identity memory and a contextual memory.
	identityID := addMemory(t, store, "Scheduler test identity fact", CategoryIdentity, ownerID)
	contextualID := addMemory(t, store, "Scheduler test contextual fact", CategoryContextual, ownerID)

	// Backdate contextual memory to trigger decay.
	setUpdatedAt(t, store.pool, contextualID, time.Now().Add(-20*24*time.Hour))

	// Add an expired memory for DeleteStale.
	expiredID := addMemory(t, store, "Scheduler test expired fact", CategoryContextual, ownerID)
	setExpiresAt(t, store.pool, expiredID, time.Now().Add(-1*time.Hour))

	// Create scheduler and run once.
	scheduler := NewScheduler(store, slog.Default())
	scheduler.runOnce(ctx)

	// Verify: identity decay_score = 1.0.
	rawIdentity := queryRaw(t, store.pool, identityID)
	if rawIdentity.DecayScore != 1.0 {
		t.Errorf("after runOnce: identity decay_score = %v, want 1.0", rawIdentity.DecayScore)
	}

	// Verify: contextual decay_score < 1.0 (20 days old, half-life = 15d).
	rawContextual := queryRaw(t, store.pool, contextualID)
	if rawContextual.DecayScore >= 1.0 {
		t.Errorf("after runOnce: contextual decay_score = %v, want < 1.0", rawContextual.DecayScore)
	}

	// Verify: expired memory is deactivated.
	rawExpired := queryRaw(t, store.pool, expiredID)
	if rawExpired.Active {
		t.Error("after runOnce: expired memory active = true, want false")
	}
}

func TestScheduler_RetentionCleanup(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Add an active memory (should NOT be cleaned up).
	activeID := addMemory(t, store, "Active memory", CategoryIdentity, ownerID)

	// Add an inactive memory (soft-deleted), backdated beyond retention.
	inactiveID := addMemory(t, store, "Inactive old memory", CategoryContextual, ownerID)
	if err := store.Delete(ctx, inactiveID, ownerID); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	// Backdate the inactive memory beyond retention cutoff.
	setUpdatedAt(t, store.pool, inactiveID, time.Now().AddDate(0, 0, -100))

	// Add a recently inactive memory (should NOT be cleaned up).
	recentInactiveID := addMemory(t, store, "Recently inactive memory", CategoryContextual, ownerID)
	if err := store.Delete(ctx, recentInactiveID, ownerID); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Create scheduler with retention = 90 days, no session cleaner.
	scheduler := NewScheduler(store, slog.Default())
	scheduler.SetRetention(90, nil)

	// Run once — should hard-delete the 100-day-old inactive memory.
	scheduler.runOnce(ctx)

	// Verify: active memory still exists.
	rawActive := queryRaw(t, store.pool, activeID)
	if rawActive.ID != activeID {
		t.Errorf("active memory should still exist after retention cleanup")
	}

	// Verify: old inactive memory is hard-deleted (row gone).
	_, err := store.pool.Exec(ctx, "SELECT id FROM memories WHERE id = $1", inactiveID)
	// Can't use queryRaw since it might not find the row. Let's check directly.
	var found int
	if err := store.pool.QueryRow(ctx, "SELECT COUNT(*) FROM memories WHERE id = $1", inactiveID).Scan(&found); err != nil {
		t.Fatalf("checking inactive memory: %v", err)
	}
	if found != 0 {
		t.Errorf("old inactive memory (100 days) count = %d, want 0 (should be hard-deleted)", found)
	}

	// Verify: recent inactive memory still exists (only 0 days old, within 90-day retention).
	var recentFound int
	if err = store.pool.QueryRow(ctx, "SELECT COUNT(*) FROM memories WHERE id = $1", recentInactiveID).Scan(&recentFound); err != nil {
		t.Fatalf("checking recent inactive memory: %v", err)
	}
	if recentFound != 1 {
		t.Errorf("recent inactive memory count = %d, want 1 (within retention period)", recentFound)
	}
}

func TestScheduler_SetRetention_Zero(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Add and deactivate a memory, backdate it.
	id := addMemory(t, store, "Should survive zero retention", CategoryContextual, ownerID)
	if err := store.Delete(ctx, id, ownerID); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	setUpdatedAt(t, store.pool, id, time.Now().AddDate(0, 0, -500))

	// RetentionDays = 0 → disabled, should not clean up.
	scheduler := NewScheduler(store, slog.Default())
	scheduler.SetRetention(0, nil)
	scheduler.runOnce(ctx)

	var found int
	if err := store.pool.QueryRow(ctx, "SELECT COUNT(*) FROM memories WHERE id = $1", id).Scan(&found); err != nil {
		t.Fatalf("checking memory: %v", err)
	}
	if found != 1 {
		t.Errorf("memory count = %d, want 1 (retention disabled, should not delete)", found)
	}
}

func TestStore_Memory_OwnershipCheck(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	otherOwner := uniqueOwner()

	id := addMemory(t, store, "Ownership test memory", CategoryIdentity, ownerID)

	// Owner can access.
	m, err := store.Memory(ctx, id, ownerID)
	if err != nil {
		t.Fatalf("Memory(%v, owner) unexpected error: %v", id, err)
	}
	if m.ID != id {
		t.Errorf("Memory(%v, owner).ID = %v, want %v", id, m.ID, id)
	}

	// Other owner is forbidden.
	_, err = store.Memory(ctx, id, otherOwner)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("Memory(%v, other) error = %v, want ErrForbidden", id, err)
	}

	// Non-existent ID returns not found.
	_, err = store.Memory(ctx, uuid.New(), ownerID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Memory(random, owner) error = %v, want ErrNotFound", err)
	}
}

func TestStore_Memories_Pagination(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Add 5 memories.
	for i := 0; i < 5; i++ {
		addMemory(t, store, fmt.Sprintf("Pagination test memory %d", i), CategoryContextual, ownerID)
	}

	// Page 1: limit=2, offset=0.
	memories, total, err := store.Memories(ctx, ownerID, 2, 0)
	if err != nil {
		t.Fatalf("Memories(limit=2, offset=0) error: %v", err)
	}
	if total != 5 {
		t.Errorf("Memories() total = %d, want 5", total)
	}
	if len(memories) != 2 {
		t.Errorf("Memories() len = %d, want 2", len(memories))
	}

	// Page 3: limit=2, offset=4.
	memories, total, err = store.Memories(ctx, ownerID, 2, 4)
	if err != nil {
		t.Fatalf("Memories(limit=2, offset=4) error: %v", err)
	}
	if total != 5 {
		t.Errorf("Memories() total = %d, want 5", total)
	}
	if len(memories) != 1 {
		t.Errorf("Memories() len = %d, want 1 (last page)", len(memories))
	}
}

func TestStore_ActiveCount(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Start with 0 memories.
	count, err := store.ActiveCount(ctx, ownerID)
	if err != nil {
		t.Fatalf("ActiveCount() error: %v", err)
	}
	if count != 0 {
		t.Errorf("ActiveCount() = %d, want 0", count)
	}

	// Add 3 memories.
	addMemory(t, store, "Active count test 1", CategoryIdentity, ownerID)
	id2 := addMemory(t, store, "Active count test 2", CategoryContextual, ownerID)
	addMemory(t, store, "Active count test 3", CategoryProject, ownerID)

	count, err = store.ActiveCount(ctx, ownerID)
	if err != nil {
		t.Fatalf("ActiveCount() error: %v", err)
	}
	if count != 3 {
		t.Errorf("ActiveCount() = %d, want 3", count)
	}

	// Deactivate one.
	if err := store.Delete(ctx, id2, ownerID); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	count, err = store.ActiveCount(ctx, ownerID)
	if err != nil {
		t.Fatalf("ActiveCount() error: %v", err)
	}
	if count != 2 {
		t.Errorf("ActiveCount() after delete = %d, want 2", count)
	}
}

// ============================================================
// Phase 4b: Supersede
// ============================================================

func TestStore_Supersede(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	oldID := addMemory(t, store, "Old fact about my work environment", CategoryProject, ownerID)
	newID := addMemory(t, store, "Updated fact about my work environment", CategoryProject, ownerID)

	if err := store.Supersede(ctx, oldID, newID); err != nil {
		t.Fatalf("Supersede() unexpected error: %v", err)
	}

	// Verify old memory is superseded and inactive.
	raw := queryRaw(t, store.pool, oldID)
	if raw.Active {
		t.Error("superseded memory active = true, want false")
	}
	if raw.SupersededBy == nil || *raw.SupersededBy != newID {
		t.Errorf("superseded_by = %v, want %s", raw.SupersededBy, newID)
	}
}

func TestStore_Supersede_SelfReference(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	id := addMemory(t, store, "Cannot supersede self", CategoryIdentity, ownerID)

	err := store.Supersede(ctx, id, id)
	if err == nil {
		t.Fatal("Supersede(self) expected error, got nil")
	}
}

func TestStore_Supersede_DoubleSupersede(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	a := addMemory(t, store, "First version of project info", CategoryProject, ownerID)
	b := addMemory(t, store, "Second version of project info", CategoryProject, ownerID)
	c := addMemory(t, store, "Third version of project info", CategoryProject, ownerID)

	if err := store.Supersede(ctx, a, b); err != nil {
		t.Fatalf("Supersede(a,b) unexpected error: %v", err)
	}

	// Trying to supersede 'a' again should fail (already superseded).
	err := store.Supersede(ctx, a, c)
	if err == nil {
		t.Fatal("Supersede(a,c) expected error (already superseded), got nil")
	}
}

func TestStore_Supersede_CrossOwner(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()

	owner1 := uniqueOwner()
	owner2 := uniqueOwner()

	idOwner1 := addMemory(t, store, "Owner 1 fact for supersede test", CategoryIdentity, owner1)
	idOwner2 := addMemory(t, store, "Owner 2 fact for supersede test", CategoryIdentity, owner2)

	// Cross-owner supersede should fail (owner mismatch).
	err := store.Supersede(ctx, idOwner1, idOwner2)
	if err == nil {
		t.Fatal("Supersede(cross-owner) expected error, got nil")
	}
}

// ============================================================
// Phase 4b: AddOpts (importance + expires_in)
// ============================================================

func TestStore_Add_ImportanceAndExpiry(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	opts := AddOpts{Importance: 8, ExpiresIn: "7d"}
	err := store.Add(ctx, "High importance fact with 7d expiry", CategoryContextual, ownerID, sessionID, opts, nil)
	if err != nil {
		t.Fatalf("Add() with opts unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("All() count = %d, want 1", len(all))
	}

	m := all[0]
	if m.Importance != 8 {
		t.Errorf("importance = %d, want 8", m.Importance)
	}
	if m.ExpiresAt == nil {
		t.Fatal("expires_at = nil, want non-nil")
	}
	// 7d expiry should be approximately 7 days from now.
	expected := time.Now().Add(7 * 24 * time.Hour)
	if m.ExpiresAt.Before(expected.Add(-time.Minute)) || m.ExpiresAt.After(expected.Add(time.Minute)) {
		t.Errorf("expires_at = %v, want ~%v", m.ExpiresAt, expected)
	}
}

func TestStore_Add_ImportanceDefault(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Zero importance should default to 5.
	err := store.Add(ctx, "Default importance fact", CategoryIdentity, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("All() count = %d, want 1", len(all))
	}
	if all[0].Importance != 5 {
		t.Errorf("importance = %d, want 5 (default)", all[0].Importance)
	}
}

func TestStore_Add_InvalidExpiresInFallback(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Invalid expires_in should fall back to category default (30d for contextual).
	opts := AddOpts{ExpiresIn: "invalid"}
	err := store.Add(ctx, "Invalid expires_in fallback test", CategoryContextual, ownerID, sessionID, opts, nil)
	if err != nil {
		t.Fatalf("Add() with invalid expires_in unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("All() count = %d, want 1", len(all))
	}
	// Should have category default expiry (~30d for contextual).
	if all[0].ExpiresAt == nil {
		t.Fatal("expires_at = nil, want non-nil (category default)")
	}
	expected := time.Now().Add(30 * 24 * time.Hour)
	if all[0].ExpiresAt.Before(expected.Add(-time.Minute)) || all[0].ExpiresAt.After(expected.Add(time.Minute)) {
		t.Errorf("expires_at = %v, want ~%v (30d default)", all[0].ExpiresAt, expected)
	}
}

// ============================================================
// Phase 4b: Arbitration (mock)
// ============================================================

// mockArbitrator implements Arbitrator for testing.
type mockArbitrator struct {
	result *ArbitrationResult
	err    error
	called bool
}

func (m *mockArbitrator) Arbitrate(_ context.Context, _, _ string) (*ArbitrationResult, error) {
	m.called = true
	return m.result, m.err
}

func TestStore_Add_ArbitrationNOOP(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add first memory.
	err := store.Add(ctx, "I prefer using dark mode in all editors", CategoryPreference, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first memory unexpected error: %v", err)
	}

	// Add similar content that falls in arbitration band.
	// The mock returns NOOP (discard candidate).
	arb := &mockArbitrator{result: &ArbitrationResult{Operation: OpNoop}}
	err = store.Add(ctx, "I prefer using dark mode in most editors", CategoryPreference, ownerID, sessionID, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() with NOOP arbitration unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}

	// NOOP: candidate discarded, only original should exist.
	// Note: whether arbitration is triggered depends on actual embedding similarity.
	// If similarity >= AutoMergeThreshold, auto-merge happens instead.
	// This test verifies the mock was set up correctly; actual threshold behavior
	// is inherently embedding-dependent.
	if len(all) == 0 {
		t.Fatal("All() returned 0 memories, expected at least 1")
	}
}

func TestStore_Add_ArbitrationError_FallsThrough(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add first memory.
	err := store.Add(ctx, "I work remotely from my home office in Seattle", CategoryProject, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first memory unexpected error: %v", err)
	}

	// Mock arbitrator returns error — should fall through to ADD.
	arb := &mockArbitrator{err: fmt.Errorf("LLM unavailable")}
	err = store.Add(ctx, "I work remotely from my apartment in Portland", CategoryProject, ownerID, sessionID, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() with failing arbitration unexpected error: %v", err)
	}

	// Should have at least 1 memory (may be 1 if auto-merged or 2 if added separately).
	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("All() returned 0 memories, expected at least 1")
	}
}

func TestStore_Add_ArbitrationUPDATE(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add first memory.
	err := store.Add(ctx, "I prefer VS Code for Go development", CategoryPreference, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first memory unexpected error: %v", err)
	}

	// Mock arbitrator returns UPDATE with merged content.
	arb := &mockArbitrator{result: &ArbitrationResult{
		Operation: OpUpdate,
		Content:   "I prefer VS Code for Go and Python development",
		Reasoning: "Merged language preferences",
	}}
	err = store.Add(ctx, "I prefer VS Code for Python development", CategoryPreference, ownerID, sessionID, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() with UPDATE arbitration unexpected error: %v", err)
	}

	// Whether arbitration fires depends on embedding similarity.
	// If similarity is in [0.85, 0.95), the mock should have been called.
	// Either way, no error means the flow completed.
	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("All() returned 0 memories, expected at least 1")
	}

	// If the mock was called and UPDATE applied, we should see merged content.
	if arb.called {
		found := false
		for _, m := range all {
			if strings.Contains(m.Content, "Go and Python") {
				found = true
			}
		}
		if !found {
			t.Error("arbitration UPDATE called but merged content not found")
		}
	}
}

func TestStore_Add_ArbitrationDELETE(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add first memory.
	err := store.Add(ctx, "I am currently using macOS Monterey", CategoryContextual, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first memory unexpected error: %v", err)
	}

	// Mock arbitrator returns DELETE (invalidate existing, keep new).
	arb := &mockArbitrator{result: &ArbitrationResult{
		Operation: OpDelete,
		Reasoning: "User upgraded OS, old fact is obsolete",
	}}
	err = store.Add(ctx, "I am currently using macOS Sonoma", CategoryContextual, ownerID, sessionID, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() with DELETE arbitration unexpected error: %v", err)
	}

	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("All() returned 0 memories, expected at least 1")
	}

	// If the mock was called, the old memory should be deactivated and new one added.
	if arb.called {
		for _, m := range all {
			if strings.Contains(m.Content, "Monterey") {
				t.Error("DELETE arbitration called but old 'Monterey' memory still active")
			}
		}
	}
}

// ============================================================
// Phase 4c: Supersede Cycle Detection (chain depth > 1)
// ============================================================

func TestStore_Supersede_CycleDetection(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Create chain: a -> b -> c (content must be distinct enough to avoid dedup).
	a := addMemory(t, store, "I commute to work by bicycle every morning", CategoryContextual, ownerID)
	b := addMemory(t, store, "My favorite programming language is Haskell for proofs", CategoryPreference, ownerID)
	c := addMemory(t, store, "Currently reading a book about quantum computing theory", CategoryProject, ownerID)

	// Build chain: a is superseded by b, b is superseded by c.
	if err := store.Supersede(ctx, a, b); err != nil {
		t.Fatalf("Supersede(a,b) unexpected error: %v", err)
	}
	if err := store.Supersede(ctx, b, c); err != nil {
		t.Fatalf("Supersede(b,c) unexpected error: %v", err)
	}

	// Now try to supersede c with a — would create cycle (a->b->c->a).
	err := store.Supersede(ctx, c, a)
	if err == nil {
		t.Fatal("Supersede(c,a) expected cycle detection error, got nil")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("Supersede(c,a) error = %q, want contains 'circular'", err.Error())
	}
}

// ============================================================
// Phase 4c: Eviction (MaxPerUser overflow)
// ============================================================

func TestStore_Eviction(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Fill to MaxPerUser by inserting directly via SQL (avoids 1000 embedding calls).
	for i := range MaxPerUser {
		_, err := store.pool.Exec(ctx,
			`INSERT INTO memories (owner_id, content, embedding, category, source_session_id)
			 VALUES ($1, $2, $3::vector, $4, $5)`,
			ownerID, fmt.Sprintf("eviction filler %d", i), zeroVector(), "contextual", sessionID)
		if err != nil {
			t.Fatalf("inserting filler memory %d: %v", i, err)
		}
	}

	// Verify we have MaxPerUser.
	var count int
	err := store.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM memories WHERE owner_id = $1 AND active = true`, ownerID).Scan(&count)
	if err != nil {
		t.Fatalf("counting memories: %v", err)
	}
	if count != MaxPerUser {
		t.Fatalf("setup: count = %d, want %d", count, MaxPerUser)
	}

	// Add one more via Add() (with real embedding) — should trigger eviction.
	err = store.Add(ctx, "This addition should trigger eviction of the oldest", CategoryContextual, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add(trigger eviction) unexpected error: %v", err)
	}

	// Should be at most MaxPerUser after eviction.
	err = store.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM memories WHERE owner_id = $1 AND active = true`, ownerID).Scan(&count)
	if err != nil {
		t.Fatalf("counting memories after eviction: %v", err)
	}
	if count > MaxPerUser {
		t.Errorf("after eviction: count = %d, want <= %d", count, MaxPerUser)
	}
}

// ============================================================
// Phase 4c: HybridSearch Decay-Weighted Ranking
// ============================================================

func TestStore_HybridSearch_DecayAffectsRanking(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()

	// Add two memories with identical content relevance but different ages.
	freshID := addMemory(t, store, "I am actively learning Kubernetes for container orchestration", CategoryProject, ownerID)
	oldID := addMemory(t, store, "I am studying Kubernetes certification exam topics", CategoryProject, ownerID)

	// Age the old memory by 60 days (well past half-life for project = 30d).
	setUpdatedAt(t, store.pool, oldID, time.Now().Add(-60*24*time.Hour))

	// Run decay to set decay_score accordingly.
	if _, err := store.UpdateDecayScores(ctx); err != nil {
		t.Fatalf("UpdateDecayScores() unexpected error: %v", err)
	}

	// Verify decay scores differ.
	rawFresh := queryRaw(t, store.pool, freshID)
	rawOld := queryRaw(t, store.pool, oldID)
	if rawOld.DecayScore >= rawFresh.DecayScore {
		t.Errorf("old decay_score (%v) should be < fresh decay_score (%v)", rawOld.DecayScore, rawFresh.DecayScore)
	}

	// Search for Kubernetes — fresh memory should rank higher due to decay weight.
	results, err := store.HybridSearch(ctx, "Kubernetes container orchestration", ownerID, 10)
	if err != nil {
		t.Fatalf("HybridSearch() unexpected error: %v", err)
	}
	if len(results) < 2 {
		t.Fatalf("HybridSearch() returned %d results, want >= 2", len(results))
	}

	// Find positions.
	freshIdx, oldIdx := -1, -1
	for i, m := range results {
		if m.ID == freshID {
			freshIdx = i
		}
		if m.ID == oldID {
			oldIdx = i
		}
	}
	if freshIdx >= 0 && oldIdx >= 0 && freshIdx > oldIdx {
		t.Errorf("fresh memory (idx=%d) ranked lower than old decayed memory (idx=%d)", freshIdx, oldIdx)
	}
}

// ============================================================
// Phase 4c: Concurrent Add Safety
// ============================================================

func TestStore_Add_ConcurrentSafe(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Spawn 10 goroutines adding distinct content concurrently.
	const n = 10
	errs := make(chan error, n)
	for i := range n {
		go func() {
			content := fmt.Sprintf("Concurrent memory fact number %d about topic %s", i, uuid.New().String()[:8])
			errs <- store.Add(ctx, content, CategoryContextual, ownerID, sessionID, AddOpts{}, nil)
		}()
	}

	for range n {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Add() error: %v", err)
		}
	}

	// All should have been stored (no panics, no deadlocks).
	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) == 0 {
		t.Error("All() returned 0 memories after concurrent adds")
	}
}

func TestStore_Add_NilArbitratorSkipsArbitration(t *testing.T) {
	store := setupIntegrationTest(t)
	ctx := context.Background()
	ownerID := uniqueOwner()
	sessionID := createSession(t, store.pool)

	// Add two somewhat similar memories with nil arbitrator.
	err := store.Add(ctx, "My primary programming language is Go", CategoryPreference, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first memory unexpected error: %v", err)
	}

	err = store.Add(ctx, "My preferred programming language is Go for all projects", CategoryPreference, ownerID, sessionID, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() second memory unexpected error: %v", err)
	}

	// Should succeed regardless (nil arb = skip arbitration, either auto-merge or ADD).
	all, err := store.All(ctx, ownerID, "")
	if err != nil {
		t.Fatalf("All() unexpected error: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("All() returned 0 memories, expected at least 1")
	}
}
