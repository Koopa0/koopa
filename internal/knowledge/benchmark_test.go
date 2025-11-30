//go:build integration

package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
)

// Performance Expectations (from TESTING_STRATEGY_v3.md):
// - Search (1000 docs): < 100ms
// - Add single doc: < 500ms

// BenchmarkStore_Search benchmarks the search operation.
// Run with: go test -tags=integration -bench=BenchmarkStore_Search -benchmem ./internal/knowledge/...
func BenchmarkStore_Search(b *testing.B) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		b.Skip("GEMINI_API_KEY not set - skipping benchmark")
	}

	ctx := context.Background()
	store, cleanup := setupBenchmarkStore(b, ctx, 10) // Small corpus for quick setup
	defer cleanup()

	b.ResetTimer()
	for b.Loop() {
		_, err := store.Search(ctx, "machine learning AI", WithTopK(5))
		if err != nil {
			b.Fatalf("Search failed: %v", err)
		}
	}
}

// BenchmarkStore_Search_LargeCorpus benchmarks search with a larger document set.
// Note: This test requires significant setup time due to embedding generation.
func BenchmarkStore_Search_LargeCorpus(b *testing.B) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		b.Skip("GEMINI_API_KEY not set - skipping benchmark")
	}

	ctx := context.Background()
	store, cleanup := setupBenchmarkStore(b, ctx, 50) // Larger corpus
	defer cleanup()

	b.ResetTimer()
	for b.Loop() {
		_, err := store.Search(ctx, "artificial intelligence neural networks", WithTopK(10))
		if err != nil {
			b.Fatalf("Search failed: %v", err)
		}
	}
}

// BenchmarkStore_Add benchmarks adding a single document.
func BenchmarkStore_Add(b *testing.B) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		b.Skip("GEMINI_API_KEY not set - skipping benchmark")
	}

	ctx := context.Background()
	dbContainer, embedder, cleanup := setupBenchmarkDeps(b)
	defer cleanup()

	store := New(sqlc.New(dbContainer.Pool), embedder, slog.Default())

	// Pre-generate documents
	// NOTE: time.Now() is called once outside the loop to avoid syscall overhead per iteration
	baseTime := time.Now().UnixNano()
	createAt := time.Now()
	docs := make([]Document, b.N)
	for i := range b.N {
		docs[i] = Document{
			ID:       fmt.Sprintf("bench-add-%d-%d", baseTime, i),
			Content:  fmt.Sprintf("Benchmark document %d about artificial intelligence and machine learning", i),
			Metadata: map[string]string{"source_type": SourceTypeSystem, "test": "benchmark"},
			CreateAt: createAt,
		}
	}

	b.ResetTimer()
	for i := range b.N {
		err := store.Add(ctx, docs[i])
		if err != nil {
			b.Fatalf("Add failed at iteration %d: %v", i, err)
		}
	}
}

// BenchmarkStore_Count benchmarks counting documents (no API call).
func BenchmarkStore_Count(b *testing.B) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		b.Skip("GEMINI_API_KEY not set - skipping benchmark")
	}

	ctx := context.Background()
	store, cleanup := setupBenchmarkStore(b, ctx, 10)
	defer cleanup()

	b.ResetTimer()
	for b.Loop() {
		_, err := store.Count(ctx, nil)
		if err != nil {
			b.Fatalf("Count failed: %v", err)
		}
	}
}

// BenchmarkStore_Delete benchmarks deleting a document.
func BenchmarkStore_Delete(b *testing.B) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		b.Skip("GEMINI_API_KEY not set - skipping benchmark")
	}

	ctx := context.Background()
	dbContainer, embedder, cleanup := setupBenchmarkDeps(b)
	defer cleanup()

	store := New(sqlc.New(dbContainer.Pool), embedder, slog.Default())

	// Pre-create documents to delete
	// NOTE: time.Now() is called once outside the loop to avoid syscall overhead per iteration
	baseTime := time.Now().UnixNano()
	createAt := time.Now()
	docIDs := make([]string, b.N)
	for i := range b.N {
		docID := fmt.Sprintf("bench-delete-%d-%d", baseTime, i)
		docIDs[i] = docID
		err := store.Add(ctx, Document{
			ID:       docID,
			Content:  "Document to be deleted",
			Metadata: map[string]string{"source_type": SourceTypeSystem},
			CreateAt: createAt,
		})
		if err != nil {
			b.Fatalf("Setup failed: %v", err)
		}
		time.Sleep(50 * time.Millisecond) // Avoid rate limits - required for Gemini API
	}

	b.ResetTimer()
	for i := range b.N {
		err := store.Delete(ctx, docIDs[i])
		if err != nil {
			b.Fatalf("Delete failed: %v", err)
		}
	}
}

// setupBenchmarkStore creates a store with pre-loaded documents for benchmarking.
func setupBenchmarkStore(b *testing.B, ctx context.Context, numDocs int) (*Store, func()) {
	b.Helper()

	dbContainer, embedder, cleanup := setupBenchmarkDeps(b)
	store := New(sqlc.New(dbContainer.Pool), embedder, slog.Default())

	// Pre-load documents
	// NOTE: time.Now() is called once outside the loop to avoid syscall overhead per iteration
	baseTime := time.Now().UnixNano()
	createAt := time.Now()
	for i := 0; i < numDocs; i++ {
		doc := Document{
			ID:       fmt.Sprintf("bench-doc-%d-%d", baseTime, i),
			Content:  fmt.Sprintf("Benchmark test document %d about AI, machine learning, and deep learning systems", i),
			Metadata: map[string]string{"source_type": SourceTypeSystem, "index": fmt.Sprintf("%d", i)},
			CreateAt: createAt,
		}
		if err := store.Add(ctx, doc); err != nil {
			b.Fatalf("Failed to add benchmark doc %d: %v", i, err)
		}
		// Small delay to avoid rate limits - required for Gemini API
		time.Sleep(100 * time.Millisecond)
	}

	return store, cleanup
}

// setupBenchmarkDeps creates the dependencies for benchmark tests.
// Uses testutil.SetupTestDB and config.DefaultEmbedderModel for consistency.
func setupBenchmarkDeps(b *testing.B) (*testutil.TestDBContainer, ai.Embedder, func()) {
	b.Helper()

	// Use testutil for DB setup (now accepts testing.TB interface)
	dbContainer, dbCleanup := testutil.SetupTestDB(b)

	// Setup embedder using config constant for maintainability
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))
	if g == nil {
		b.Fatal("Failed to initialize Genkit: genkit.Init returned nil")
	}

	embedder := googlegenai.GoogleAIEmbedder(g, config.DefaultEmbedderModel)
	if embedder == nil {
		b.Fatalf("Failed to create embedder: GoogleAIEmbedder returned nil for model %q", config.DefaultEmbedderModel)
	}

	cleanup := func() {
		// Clean up benchmark documents
		_, _ = dbContainer.Pool.Exec(context.Background(), "DELETE FROM documents WHERE id LIKE 'bench-%'")
		dbCleanup()
	}

	return dbContainer, embedder, cleanup
}
