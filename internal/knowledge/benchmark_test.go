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
	for i := 0; i < b.N; i++ {
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
	for i := 0; i < b.N; i++ {
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
	docs := make([]Document, b.N)
	for i := 0; i < b.N; i++ {
		docs[i] = Document{
			ID:       fmt.Sprintf("bench-add-%d-%d", time.Now().UnixNano(), i),
			Content:  fmt.Sprintf("Benchmark document %d about artificial intelligence and machine learning", i),
			Metadata: map[string]string{"source_type": SourceTypeSystem, "test": "benchmark"},
			CreateAt: time.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	for i := 0; i < b.N; i++ {
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
	docIDs := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		docID := fmt.Sprintf("bench-delete-%d-%d", time.Now().UnixNano(), i)
		docIDs[i] = docID
		err := store.Add(ctx, Document{
			ID:       docID,
			Content:  "Document to be deleted",
			Metadata: map[string]string{"source_type": SourceTypeSystem},
			CreateAt: time.Now(),
		})
		if err != nil {
			b.Fatalf("Setup failed: %v", err)
		}
		time.Sleep(50 * time.Millisecond) // Avoid rate limits
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	for i := 0; i < numDocs; i++ {
		doc := Document{
			ID:       fmt.Sprintf("bench-doc-%d-%d", time.Now().UnixNano(), i),
			Content:  fmt.Sprintf("Benchmark test document %d about AI, machine learning, and deep learning systems", i),
			Metadata: map[string]string{"source_type": SourceTypeSystem, "index": fmt.Sprintf("%d", i)},
			CreateAt: time.Now(),
		}
		if err := store.Add(ctx, doc); err != nil {
			b.Fatalf("Failed to add benchmark doc %d: %v", i, err)
		}
		// Small delay to avoid rate limits
		time.Sleep(100 * time.Millisecond)
	}

	return store, cleanup
}

// setupBenchmarkDeps creates the dependencies for benchmark tests.
// Note: Benchmarks use direct setup instead of testutil because:
// 1. testutil.SetupTestDB uses testcontainers which adds significant overhead
// 2. Benchmarks need predictable, low-overhead setup
func setupBenchmarkDeps(b *testing.B) (*testutil.TestDBContainer, ai.Embedder, func()) {
	b.Helper()

	// Use testutil for DB setup
	dbContainer, dbCleanup := testutil.SetupTestDB(&testing.T{})

	// Setup embedder directly (testutil.SetupEmbedder requires *testing.T)
	ctx := context.Background()
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))
	embedder := googlegenai.GoogleAIEmbedder(g, "text-embedding-004")

	cleanup := func() {
		// Clean up benchmark documents
		_, _ = dbContainer.Pool.Exec(context.Background(), "DELETE FROM documents WHERE id LIKE 'bench-%'")
		dbCleanup()
	}

	return dbContainer, embedder, cleanup
}
