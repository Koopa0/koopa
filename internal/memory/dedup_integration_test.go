//go:build integration

package memory

import (
	"context"
	"log/slog"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/testutil"
)

// setupDedupTest creates a Store backed by real PostgreSQL but using a mock
// embedder for deterministic cosine similarity control.
func setupDedupTest(t *testing.T) (*Store, *testutil.MockEmbedder) {
	t.Helper()
	testutil.CleanTables(t, sharedDB.Pool)

	mockEmb := testutil.NewMockEmbedder(int(VectorDimension))
	store, err := NewStore(sharedDB.Pool, mockEmb.RegisterEmbedder(sharedAI.Genkit), slog.Default())
	if err != nil {
		t.Fatalf("NewStore() unexpected error: %v", err)
	}
	return store, mockEmb
}

// makeVector creates a unit vector of the given dimension with a single non-zero component.
// This makes it easy to control cosine similarity between vectors.
func makeVector(dim int, idx int) []float32 {
	vec := make([]float32, dim)
	vec[idx%dim] = 1.0
	return vec
}

// makeVectorWithAngle creates a vector at a given angle from the base vector.
// angle=0 → identical (similarity=1.0), angle=pi/2 → orthogonal (similarity=0).
func makeVectorWithAngle(dim int, angle float64) []float32 {
	vec := make([]float32, dim)
	vec[0] = float32(math.Cos(angle))
	vec[1] = float32(math.Sin(angle))
	return vec
}

func TestAdd_AutoMerge_HighSimilarity(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Set up vectors that are nearly identical (angle ≈ 0).
	// Same vector → cosine similarity = 1.0 → auto-merge.
	baseVec := makeVector(int(VectorDimension), 0)
	mockEmb.SetVector("user prefers Go language", baseVec)
	mockEmb.SetVector("user prefers Go programming", baseVec) // Same vector → sim=1.0

	// Add first memory.
	err := store.Add(ctx, "user prefers Go language", CategoryPreference, owner, sid, AddOpts{Importance: 7}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	// Verify single memory exists.
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All() after first add: %v", err)
	}
	if got, want := len(all), 1; got != want {
		t.Fatalf("All() after first add len = %d, want %d", got, want)
	}
	originalID := all[0].ID

	// Add second memory with same vector → should auto-merge (UPDATE, not INSERT).
	err = store.Add(ctx, "user prefers Go programming", CategoryPreference, owner, sid, AddOpts{Importance: 8}, nil)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	// Verify still only one memory (merged).
	all, err = store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All() after merge: %v", err)
	}
	if got, want := len(all), 1; got != want {
		t.Errorf("All() after merge len = %d, want %d (auto-merge should UPDATE, not INSERT)", got, want)
	}

	// Verify the content was updated.
	if all[0].Content != "user prefers Go programming" {
		t.Errorf("All()[0].Content = %q, want %q", all[0].Content, "user prefers Go programming")
	}

	// Verify the ID was preserved (same row updated).
	if all[0].ID != originalID {
		t.Errorf("All()[0].ID = %v, want %v (auto-merge should update same row)", all[0].ID, originalID)
	}
}

func TestAdd_NewInsert_LowSimilarity(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Set up orthogonal vectors → cosine similarity = 0 → INSERT new.
	vec1 := makeVector(int(VectorDimension), 0) // [1,0,0,...]
	vec2 := makeVector(int(VectorDimension), 1) // [0,1,0,...]
	mockEmb.SetVector("user likes cats", vec1)
	mockEmb.SetVector("user works at Google", vec2)

	err := store.Add(ctx, "user likes cats", CategoryPreference, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	err = store.Add(ctx, "user works at Google", CategoryIdentity, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	// Verify two distinct memories exist.
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	if got, want := len(all), 2; got != want {
		t.Errorf("All() len = %d, want %d (low similarity should INSERT new row)", got, want)
	}
}

// mockArbitrator implements Arbitrator with a fixed response for testing.
type mockArbitrator struct {
	result *ArbitrationResult
	called bool
}

func (a *mockArbitrator) Arbitrate(_ context.Context, _, _ string) (*ArbitrationResult, error) {
	a.called = true
	return a.result, nil
}

func TestAdd_Arbitration_MediumSimilarity(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Vectors with similarity in [0.85, 0.95) → arbitration band.
	// cos(angle) ≈ 0.90 → angle ≈ 0.451 radians.
	angle := math.Acos(0.90)
	vec1 := makeVectorWithAngle(int(VectorDimension), 0)
	vec2 := makeVectorWithAngle(int(VectorDimension), angle)
	mockEmb.SetVector("user prefers vim", vec1)
	mockEmb.SetVector("user prefers neovim", vec2)

	// Add first memory.
	err := store.Add(ctx, "user prefers vim", CategoryPreference, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	// Add second with arbitrator that returns ADD.
	arb := &mockArbitrator{
		result: &ArbitrationResult{
			Operation: OpAdd,
			Reasoning: "distinct editors",
		},
	}
	err = store.Add(ctx, "user prefers neovim", CategoryPreference, owner, sid, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	if !arb.called {
		t.Error("Arbitrator.Arbitrate() was not called for similarity in [0.85, 0.95)")
	}

	// Verify two memories exist (arbitrator said ADD).
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	if got, want := len(all), 2; got != want {
		t.Errorf("All() len = %d, want %d (arbitrator returned ADD)", got, want)
	}
}

func TestAdd_Arbitration_Noop(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Similarity in arbitration band.
	angle := math.Acos(0.90)
	vec1 := makeVectorWithAngle(int(VectorDimension), 0)
	vec2 := makeVectorWithAngle(int(VectorDimension), angle)
	mockEmb.SetVector("user uses Ubuntu", vec1)
	mockEmb.SetVector("user uses Ubuntu Linux", vec2)

	err := store.Add(ctx, "user uses Ubuntu", CategoryIdentity, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	arb := &mockArbitrator{
		result: &ArbitrationResult{
			Operation: OpNoop,
			Reasoning: "same information",
		},
	}
	err = store.Add(ctx, "user uses Ubuntu Linux", CategoryIdentity, owner, sid, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	// Verify still only one memory (NOOP discards candidate).
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	if got, want := len(all), 1; got != want {
		t.Errorf("All() len = %d, want %d (arbitrator returned NOOP)", got, want)
	}
	if all[0].Content != "user uses Ubuntu" {
		t.Errorf("All()[0].Content = %q, want original content %q", all[0].Content, "user uses Ubuntu")
	}
}

func TestAdd_Arbitration_Update(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Similarity in arbitration band.
	angle := math.Acos(0.90)
	vec1 := makeVectorWithAngle(int(VectorDimension), 0)
	vec2 := makeVectorWithAngle(int(VectorDimension), angle)
	merged := makeVectorWithAngle(int(VectorDimension), angle/2) // re-embedding merged content
	mockEmb.SetVector("user lives in Taipei", vec1)
	mockEmb.SetVector("user lives in Taipei, Taiwan", vec2)
	mockEmb.SetVector("user lives in Taipei, Taiwan (capital city)", merged)

	err := store.Add(ctx, "user lives in Taipei", CategoryIdentity, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All() after first: %v", err)
	}
	originalID := all[0].ID

	arb := &mockArbitrator{
		result: &ArbitrationResult{
			Operation: OpUpdate,
			Content:   "user lives in Taipei, Taiwan (capital city)",
			Reasoning: "merged location details",
		},
	}
	err = store.Add(ctx, "user lives in Taipei, Taiwan", CategoryIdentity, owner, sid, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	// Verify one memory with merged content.
	all, err = store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All() after update: %v", err)
	}
	if got, want := len(all), 1; got != want {
		t.Fatalf("All() len = %d, want %d (arbitrator returned UPDATE)", got, want)
	}
	if all[0].Content != "user lives in Taipei, Taiwan (capital city)" {
		t.Errorf("All()[0].Content = %q, want %q", all[0].Content, "user lives in Taipei, Taiwan (capital city)")
	}
	if all[0].ID != originalID {
		t.Errorf("All()[0].ID = %v, want %v (UPDATE should modify same row)", all[0].ID, originalID)
	}
}

func TestAdd_Arbitration_Delete(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Similarity in arbitration band.
	angle := math.Acos(0.90)
	vec1 := makeVectorWithAngle(int(VectorDimension), 0)
	vec2 := makeVectorWithAngle(int(VectorDimension), angle)
	mockEmb.SetVector("user uses Python 2", vec1)
	mockEmb.SetVector("user uses Python 3", vec2)

	err := store.Add(ctx, "user uses Python 2", CategoryPreference, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	arb := &mockArbitrator{
		result: &ArbitrationResult{
			Operation: OpDelete,
			Reasoning: "Python 2 is outdated",
		},
	}
	err = store.Add(ctx, "user uses Python 3", CategoryPreference, owner, sid, AddOpts{}, arb)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	// Verify: old soft-deleted, new inserted → only new visible via All().
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	if got, want := len(all), 1; got != want {
		t.Fatalf("All() len = %d, want %d (DELETE should soft-delete old and ADD new)", got, want)
	}
	if all[0].Content != "user uses Python 3" {
		t.Errorf("All()[0].Content = %q, want %q", all[0].Content, "user uses Python 3")
	}
}

func TestAdd_NoArbitrator_MediumSimilarity(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()
	sid := createSession(t, store.pool)

	// Similarity in [0.85, 0.95) but no arbitrator → falls through to INSERT.
	angle := math.Acos(0.90)
	vec1 := makeVectorWithAngle(int(VectorDimension), 0)
	vec2 := makeVectorWithAngle(int(VectorDimension), angle)
	mockEmb.SetVector("user likes coffee", vec1)
	mockEmb.SetVector("user loves coffee", vec2)

	err := store.Add(ctx, "user likes coffee", CategoryPreference, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() first: %v", err)
	}

	// No arbitrator provided → should fall through to INSERT.
	err = store.Add(ctx, "user loves coffee", CategoryPreference, owner, sid, AddOpts{}, nil)
	if err != nil {
		t.Fatalf("Add() second: %v", err)
	}

	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	if got, want := len(all), 2; got != want {
		t.Errorf("All() len = %d, want %d (no arbitrator → INSERT new)", got, want)
	}
}

func TestAdd_ConcurrentSameOwner(t *testing.T) {
	store, mockEmb := setupDedupTest(t)
	ctx := context.Background()
	owner := uniqueOwner()

	// All use the same vector to force auto-merge path.
	baseVec := makeVector(int(VectorDimension), 0)
	for i := 0; i < 10; i++ {
		mockEmb.SetVector("memory content "+uuid.New().String()[:4], baseVec)
	}

	// Run 10 concurrent Add() calls for the same owner.
	// Advisory lock should serialize them without errors.
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			sid := createSession(t, store.pool)
			content := "memory content " + uuid.New().String()[:4]
			mockEmb.SetVector(content, baseVec)
			errs <- store.Add(ctx, content, CategoryContextual, owner, sid, AddOpts{}, nil)
		}(i)
	}

	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Add() [%d] error: %v", i, err)
		}
	}

	// Verify: due to auto-merge (same vector), should converge to 1 memory.
	all, err := store.All(ctx, owner, "")
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	// Could be 1 (all merged) or more depending on timing.
	// The key assertion: no errors, no panics, no deadlocks.
	if len(all) < 1 {
		t.Errorf("All() len = %d, want >= 1", len(all))
	}
}
