//go:build integration
// +build integration

package knowledge

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemKnowledgeIndexer_IndexAll tests the IndexAll method.
func TestSystemKnowledgeIndexer_IndexAll(t *testing.T) {
	// Check for required API key (this test needs real embedder)
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	// Setup test database
	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	// Setup embedder (required for Store.Add)
	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)
	indexer := NewSystemKnowledgeIndexer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Test: IndexAll should index all 6 system documents
	count, err := indexer.IndexAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 6, count, "should index exactly 6 system knowledge documents")

	// Verify documents are searchable
	results, err := store.Search(ctx, "error handling", WithTopK(5), WithFilter("source_type", "system"))
	require.NoError(t, err)
	assert.Greater(t, len(results), 0, "should find system knowledge documents")

	// Verify UPSERT behavior - re-indexing should not create duplicates
	count2, err := indexer.IndexAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 6, count2, "should still have 6 documents after re-indexing")
}

// TestSystemKnowledgeIndexer_ClearAll tests the ClearAll method.
func TestSystemKnowledgeIndexer_ClearAll(t *testing.T) {
	// Check for required API key
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	// Setup test database
	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	// Setup embedder
	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)
	indexer := NewSystemKnowledgeIndexer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Index system knowledge
	_, err := indexer.IndexAll(ctx)
	require.NoError(t, err)

	// Verify documents exist
	results, err := store.Search(ctx, "system", WithTopK(10), WithFilter("source_type", "system"))
	require.NoError(t, err)
	assert.Greater(t, len(results), 0, "should have system documents before clearing")

	// Test: ClearAll should remove all system documents
	err = indexer.ClearAll(ctx)
	require.NoError(t, err)

	// Verify documents are gone
	results, err = store.Search(ctx, "system", WithTopK(10), WithFilter("source_type", "system"))
	require.NoError(t, err)
	assert.Equal(t, 0, len(results), "should have no system documents after clearing")
}

// TestBuildSystemKnowledgeDocs verifies all 6 system documents are generated.
func TestBuildSystemKnowledgeDocs(t *testing.T) {
	indexer := NewSystemKnowledgeIndexer(nil, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	docs := indexer.buildSystemKnowledgeDocs()

	// Should have exactly 6 documents
	assert.Equal(t, 6, len(docs), "should generate exactly 6 system knowledge documents")

	// Verify document structure
	for i, doc := range docs {
		assert.NotEmpty(t, doc.ID, "document %d should have an ID", i)
		assert.NotEmpty(t, doc.Content, "document %d should have content", i)
		assert.NotEmpty(t, doc.Metadata, "document %d should have metadata", i)
		assert.Equal(t, "system", doc.Metadata["source_type"], "document %d should have source_type=system", i)
		assert.NotEmpty(t, doc.Metadata["category"], "document %d should have category", i)
		assert.NotEmpty(t, doc.Metadata["topic"], "document %d should have topic", i)
		assert.NotEmpty(t, doc.Metadata["version"], "document %d should have version", i)
		assert.False(t, doc.CreateAt.IsZero(), "document %d should have CreateAt timestamp", i)
	}

	// Verify expected document IDs exist
	expectedIDs := map[string]bool{
		"system:golang-errors":           false,
		"system:golang-concurrency":      false,
		"system:golang-naming":           false,
		"system:agent-tools":             false,
		"system:agent-best-practices":    false,
		"system:architecture-principles": false,
	}

	for _, doc := range docs {
		if _, exists := expectedIDs[doc.ID]; exists {
			expectedIDs[doc.ID] = true
		} else {
			t.Errorf("unexpected document ID: %s", doc.ID)
		}
	}

	// Verify all expected IDs were found
	for id, found := range expectedIDs {
		assert.True(t, found, "expected document ID not found: %s", id)
	}
}

// TestDocumentIDs_Unique ensures no duplicate document IDs.
func TestDocumentIDs_Unique(t *testing.T) {
	indexer := NewSystemKnowledgeIndexer(nil, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	docs := indexer.buildSystemKnowledgeDocs()

	seenIDs := make(map[string]bool)
	for _, doc := range docs {
		if seenIDs[doc.ID] {
			t.Errorf("duplicate document ID found: %s", doc.ID)
		}
		seenIDs[doc.ID] = true
	}

	assert.Equal(t, len(docs), len(seenIDs), "all document IDs should be unique")
}

// TestSystemKnowledge_E2E tests the full index and search workflow.
func TestSystemKnowledge_E2E(t *testing.T) {
	// Check for required API key
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	// Setup test database
	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	// Setup embedder
	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)
	indexer := NewSystemKnowledgeIndexer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Step 1: Index system knowledge
	count, err := indexer.IndexAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 6, count)

	// Step 2: Search for Golang error handling
	results, err := store.Search(ctx, "error handling best practices",
		WithTopK(3),
		WithFilter("source_type", "system"))
	require.NoError(t, err)
	assert.Greater(t, len(results), 0, "should find error handling guidance")

	// Verify result metadata
	for _, result := range results {
		assert.Equal(t, "system", result.Document.Metadata["source_type"])
		assert.NotEmpty(t, result.Document.Metadata["category"])
		assert.NotEmpty(t, result.Document.Metadata["topic"])
	}

	// Step 3: Search for Agent capabilities
	results, err = store.Search(ctx, "what tools are available",
		WithTopK(3),
		WithFilter("source_type", "system"))
	require.NoError(t, err)
	assert.Greater(t, len(results), 0, "should find agent tools documentation")

	// Step 4: Verify metadata filtering works
	golangResults, err := store.Search(ctx, "golang conventions",
		WithTopK(10),
		WithFilter("source_type", "system"))
	require.NoError(t, err)

	// All results should be system knowledge
	for _, result := range golangResults {
		assert.Equal(t, "system", result.Document.Metadata["source_type"])
	}
}

// TestIndexAll_AllFailures tests error handling when all documents fail to index.
func TestIndexAll_AllFailures(t *testing.T) {
	// Check for required API key
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	// Setup test database
	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	// Close pool to simulate database failure
	pool.Close()

	// Setup embedder (needed before it tries to access database)
	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)
	indexer := NewSystemKnowledgeIndexer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Test: IndexAll should return error when all documents fail
	count, err := indexer.IndexAll(ctx)
	assert.Error(t, err, "should return error when all documents fail to index")
	assert.Equal(t, 0, count, "count should be 0 when all fail")
	assert.Contains(t, err.Error(), "failed to index any system knowledge documents")
}

// TestIndexAll_Concurrency tests that IndexAll is safe for concurrent calls.
func TestIndexAll_Concurrency(t *testing.T) {
	// Check for required API key
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping test requiring embedder")
	}

	// Setup test database
	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	// Setup embedder
	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)
	indexer := NewSystemKnowledgeIndexer(store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Launch multiple concurrent IndexAll calls
	done := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func() {
			count, err := indexer.IndexAll(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 6, count)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify final state - should still have 6 documents (UPSERT behavior)
	results, err := store.Search(ctx, "system", WithTopK(100), WithFilter("source_type", "system"))
	require.NoError(t, err)
	assert.Equal(t, 6, len(results), "should have exactly 6 documents despite concurrent indexing")
}

// setupTestDB creates a test database connection for integration tests.
func setupTestDB(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()

	// Get database URL from environment
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://localhost/koopa_test?sslmode=disable"
	}

	// Create connection pool with timeout
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("Failed to ping test database: %v", err)
	}

	// Cleanup function
	cleanup := func() {
		pool.Close()
	}

	return pool, cleanup
}

// setupEmbedder creates a real embedder for integration tests.
// Requires GEMINI_API_KEY environment variable.
func setupEmbedder(t *testing.T, ctx context.Context) (ai.Embedder, *slog.Logger) {
	t.Helper()

	// Initialize Genkit
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	// Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, "text-embedding-004")

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	return embedder, logger
}
