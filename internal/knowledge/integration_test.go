//go:build integration
// +build integration

package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupIntegrationTest provides unified setup for all integration tests.
// Returns store and cleanup function.
func setupIntegrationTest(t *testing.T) (*Store, func()) {
	t.Helper()

	dbContainer, dbCleanup := testutil.SetupTestDB(t)
	setup := testutil.SetupGoogleAI(t)
	store := New(sqlc.New(dbContainer.Pool), setup.Embedder, setup.Logger)

	return store, dbCleanup
}

// TestKnowledgeStore_IndexDocument_Integration tests indexing a single document
func TestKnowledgeStore_IndexDocument_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index a document
	doc := Document{
		ID:      "test-go-lang",
		Content: "Go is a statically typed, compiled programming language designed at Google.",
		Metadata: map[string]string{
			"source": "test",
			"topic":  "programming",
		},
	}

	err := store.Add(ctx, doc)
	require.NoError(t, err, "Add should not return error")

	// Verify document was indexed - search for it
	results, err := store.Search(ctx, "Go programming language", WithTopK(1))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1, "Should find at least one result")

	// First result should be our document
	assert.Equal(t, doc.ID, results[0].Document.ID)
	assert.Equal(t, doc.Content, results[0].Document.Content)
}

// TestKnowledgeStore_IndexMultipleDocuments_Integration tests batch indexing
func TestKnowledgeStore_IndexMultipleDocuments_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index multiple documents
	docs := []Document{
		{
			ID:      "go-lang",
			Content: "Go is a statically typed, compiled programming language.",
			Metadata: map[string]string{
				"source": "test",
				"lang":   "en",
			},
		},
		{
			ID:      "python-lang",
			Content: "Python is a dynamically typed, interpreted programming language.",
			Metadata: map[string]string{
				"source": "test",
				"lang":   "en",
			},
		},
		{
			ID:      "javascript-lang",
			Content: "JavaScript is primarily used for web development.",
			Metadata: map[string]string{
				"source": "test",
				"lang":   "en",
			},
		},
	}

	for _, doc := range docs {
		err := store.Add(ctx, doc)
		require.NoError(t, err, "Failed to index document %s", doc.ID)
	}

	// Count documents
	count, err := store.Count(ctx, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 3, "Should have at least 3 documents")
}

// TestKnowledgeStore_SimilaritySearch_Integration tests semantic similarity search
func TestKnowledgeStore_SimilaritySearch_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index semantically distinct documents
	docs := []Document{
		{
			ID:      "compiled-langs",
			Content: "Compiled languages like C, C++, and Go convert source code to machine code before execution.",
			Metadata: map[string]string{
				"source": "test",
			},
		},
		{
			ID:      "interpreted-langs",
			Content: "Interpreted languages like Python and JavaScript execute code line by line at runtime.",
			Metadata: map[string]string{
				"source": "test",
			},
		},
		{
			ID:      "cooking-recipe",
			Content: "To make pasta, boil water, add salt, and cook the pasta for 8-10 minutes.",
			Metadata: map[string]string{
				"source": "test",
			},
		},
	}

	for _, doc := range docs {
		err := store.Add(ctx, doc)
		require.NoError(t, err)
	}

	// Search for programming-related query
	results, err := store.Search(ctx, "Tell me about compiled programming languages", WithTopK(2))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1, "Should find results")

	// First result should be about compiled languages
	assert.Equal(t, "compiled-langs", results[0].Document.ID, "Most relevant document should be about compiled languages")

	// Verify similarity scores are in reasonable range (0-1)
	for _, result := range results {
		assert.GreaterOrEqual(t, result.Similarity, 0.0, "Similarity should be >= 0")
		assert.LessOrEqual(t, result.Similarity, 1.0, "Similarity should be <= 1")
	}
}

// TestKnowledgeStore_SearchTopK_Integration tests TopK parameter
func TestKnowledgeStore_SearchTopK_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index 5 documents
	for i := 1; i <= 5; i++ {
		doc := Document{
			ID:      fmt.Sprintf("doc-%d", i),
			Content: fmt.Sprintf("This is test document number %d about programming.", i),
			Metadata: map[string]string{
				"source": "test",
			},
		}
		err := store.Add(ctx, doc)
		require.NoError(t, err)
	}

	// Search with TopK = 3
	results, err := store.Search(ctx, "programming document", WithTopK(3))
	require.NoError(t, err)
	assert.LessOrEqual(t, len(results), 3, "Should return at most 3 results")
}

// TestKnowledgeStore_SearchWithMetadata_Integration tests metadata filtering
func TestKnowledgeStore_SearchWithMetadata_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index documents with different sources
	docs := []Document{
		{
			ID:      "user-doc-1",
			Content: "User's personal notes about Go programming.",
			Metadata: map[string]string{
				"source": "user",
			},
		},
		{
			ID:      "system-doc-1",
			Content: "System documentation about Go programming.",
			Metadata: map[string]string{
				"source": "system",
			},
		},
	}

	for _, doc := range docs {
		err := store.Add(ctx, doc)
		require.NoError(t, err)
	}

	// Search with metadata filter for user documents
	results, err := store.Search(ctx, "Go programming", WithTopK(10), WithFilter("source", "user"))
	require.NoError(t, err)

	// All results should be user documents
	for _, result := range results {
		source, ok := result.Document.Metadata["source"]
		if ok {
			assert.Equal(t, "user", source, "Filtered results should only include user documents")
		}
	}
}

// TestKnowledgeStore_DeleteDocument_Integration tests deleting a document
func TestKnowledgeStore_DeleteDocument_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index a document
	doc := Document{
		ID:      "to-be-deleted",
		Content: "This document will be deleted.",
		Metadata: map[string]string{
			"source": "test",
		},
	}

	err := store.Add(ctx, doc)
	require.NoError(t, err)

	// Verify it exists
	count, err := store.Count(ctx, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)

	// Delete the document
	err = store.Delete(ctx, doc.ID)
	require.NoError(t, err)

	// Verify it's deleted
	results, err := store.Search(ctx, "deleted document", WithTopK(10))
	require.NoError(t, err)

	// Should not find the deleted document
	for _, result := range results {
		assert.NotEqual(t, "to-be-deleted", result.Document.ID, "Deleted document should not appear in results")
	}
}

// TestSystemKnowledgeIndexer_IndexAll_Integration tests system knowledge indexing
func TestSystemKnowledgeIndexer_IndexAll_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Create system indexer
	indexer := NewSystemKnowledgeIndexer(store, slog.Default())

	// Index system knowledge
	count, err := indexer.IndexAll(ctx)
	require.NoError(t, err, "IndexAll should not return error")
	t.Logf("Indexed %d system knowledge documents", count)

	// Should have indexed some documents
	assert.Greater(t, count, 0, "Should index at least some system documents")

	// Verify system documents can be searched
	results, err := store.Search(ctx, "Genkit", WithTopK(5), WithFilter("source_type", "system"))
	require.NoError(t, err)

	// Should find system documents about Genkit
	if len(results) > 0 {
		t.Logf("Found %d system documents about Genkit", len(results))
		// Verify they have system source
		for _, result := range results {
			source, ok := result.Document.Metadata["source_type"]
			if ok {
				assert.Equal(t, "system", source, "System knowledge should have source_type=system")
			}
		}
	}
}

// TestKnowledgeStore_ExactMatch_Integration tests that exact matches rank first
func TestKnowledgeStore_ExactMatch_Integration(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Index documents
	exactMatch := Document{
		ID:      "exact",
		Content: "Koopa is a terminal AI assistant built with Genkit.",
		Metadata: map[string]string{
			"source": "test",
		},
	}

	partialMatch := Document{
		ID:      "partial",
		Content: "There are many AI assistants available today.",
		Metadata: map[string]string{
			"source": "test",
		},
	}

	err := store.Add(ctx, exactMatch)
	require.NoError(t, err)

	err = store.Add(ctx, partialMatch)
	require.NoError(t, err)

	// Search with exact query
	results, err := store.Search(ctx, "Koopa is a terminal AI assistant built with Genkit", WithTopK(2))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1, "Should find results")

	// Exact match should rank first
	assert.Equal(t, "exact", results[0].Document.ID, "Exact match should rank first")

	// Exact match should have higher similarity score
	if len(results) >= 2 {
		assert.Greater(t, results[0].Similarity, results[1].Similarity, "Exact match should have higher similarity")
	}
}

// =============================================================================
// SQL Injection Prevention Tests
// =============================================================================

// TestStore_SQLInjectionPrevention verifies that SQL injection attacks are blocked.
func TestStore_SQLInjectionPrevention(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// First, add some test documents
	testDocs := []Document{
		{
			ID:       "doc-1",
			Content:  "This is a test document about AI safety",
			Metadata: map[string]string{"source_type": SourceTypeSystem, "topic": "safety"},
			CreateAt: time.Now(),
		},
		{
			ID:       "doc-2",
			Content:  "Another document about machine learning",
			Metadata: map[string]string{"source_type": SourceTypeFile, "topic": "ml"},
			CreateAt: time.Now(),
		},
	}

	for _, doc := range testDocs {
		err := store.Add(ctx, doc)
		require.NoError(t, err, "failed to add test document: %s", doc.ID)
	}

	// SQL injection attack vectors to test
	maliciousInputs := []struct {
		name        string
		queryString string
	}{
		{"single quote escape", "'; DROP TABLE documents; --"},
		{"double quote escape", `"; DROP TABLE documents; --`},
		{"or always true", "1' OR '1'='1"},
		{"or always true v2", "' OR 1=1 --"},
		{"union select", "' UNION SELECT * FROM users --"},
		{"pg_sleep", "'; SELECT pg_sleep(10); --"},
		{"stacked drop", "'; DELETE FROM documents; --"},
		{"jsonb injection", `{"source_type": "system"}'::jsonb; DROP TABLE documents; --`},
		{"comment injection", "test/**/OR/**/1=1"},
		{"null byte", "test\x00' OR '1'='1"},
	}

	// Count documents before attacks
	initialCount, err := store.Count(ctx, nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, initialCount, 2, "should have at least 2 test documents")

	for _, tc := range maliciousInputs {
		t.Run(tc.name, func(t *testing.T) {
			results, err := store.Search(ctx, tc.queryString, WithTopK(5))
			if err != nil {
				t.Logf("attack blocked with error: %v", err)
			} else {
				t.Logf("query safely escaped, returned %d results", len(results))
			}
		})
	}

	// Verify database integrity after all attacks
	t.Run("verify database integrity", func(t *testing.T) {
		finalCount, err := store.Count(ctx, nil)
		require.NoError(t, err, "documents table should still exist")
		assert.Equal(t, initialCount, finalCount,
			"document count should be unchanged after SQL injection attempts")

		results, err := store.Search(ctx, "AI safety", WithTopK(5))
		require.NoError(t, err, "normal search should still work")
		assert.Greater(t, len(results), 0, "should find results for normal query")
	})
}

// TestStore_SQLInjectionViaFilter tests injection through filter parameters.
func TestStore_SQLInjectionViaFilter(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Add test document
	err := store.Add(ctx, Document{
		ID:       "filter-test-doc",
		Content:  "Test document for filter injection",
		Metadata: map[string]string{"source_type": SourceTypeSystem},
		CreateAt: time.Now(),
	})
	require.NoError(t, err)

	// Malicious filter values
	maliciousFilters := []struct {
		name  string
		key   string
		value string
	}{
		{"sql in value", "source_type", "system'; DROP TABLE documents; --"},
		{"sql in key", "source_type'; DROP TABLE documents; --", "system"},
		{"jsonb escape", "source_type", `system"::jsonb; DELETE FROM documents; --`},
	}

	initialCount, err := store.Count(ctx, nil)
	require.NoError(t, err)

	for _, tc := range maliciousFilters {
		t.Run(tc.name, func(t *testing.T) {
			results, err := store.Search(ctx, "test",
				WithTopK(5),
				WithFilter(tc.key, tc.value))
			if err != nil {
				t.Logf("filter injection blocked: %v", err)
			} else {
				t.Logf("returned %d results", len(results))
			}
		})
	}

	// Verify integrity
	finalCount, err := store.Count(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, initialCount, finalCount, "document count should be unchanged")
}

// TestStore_SQLInjectionViaDocumentID tests injection through document IDs.
func TestStore_SQLInjectionViaDocumentID(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Add legitimate test document
	err := store.Add(ctx, Document{
		ID:       "legit-doc",
		Content:  "Legitimate test document",
		Metadata: map[string]string{"source_type": SourceTypeSystem},
		CreateAt: time.Now(),
	})
	require.NoError(t, err)

	// Malicious document IDs
	maliciousIDs := []string{
		"'; DROP TABLE documents; --",
		"1; DELETE FROM documents WHERE 1=1; --",
		"test' UNION SELECT * FROM pg_tables --",
	}

	initialCount, err := store.Count(ctx, nil)
	require.NoError(t, err)

	for _, maliciousID := range maliciousIDs {
		t.Run(maliciousID[:min(20, len(maliciousID))], func(t *testing.T) {
			err := store.Delete(ctx, maliciousID)
			t.Logf("delete result: %v", err)
		})
	}

	// Verify integrity - legit doc should still exist
	finalCount, err := store.Count(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, initialCount, finalCount, "document count should be unchanged")
}

// =============================================================================
// Race Condition Tests
// =============================================================================

// TestStore_ConcurrentAdd tests that multiple goroutines can add documents
// simultaneously without data corruption or race conditions.
func TestStore_ConcurrentAdd(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	const numGoroutines = 5 // Lower count due to API rate limits
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	var successCount atomic.Int32

	// Add documents concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			doc := Document{
				ID:       fmt.Sprintf("race-doc-%d", id),
				Content:  fmt.Sprintf("This is test document %d for race condition testing", id),
				Metadata: map[string]string{"source_type": SourceTypeSystem, "test": "race"},
				CreateAt: time.Now(),
			}

			if err := store.Add(ctx, doc); err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", id, err)
				return
			}
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors (some failures due to rate limits are acceptable)
	var errCount int
	for err := range errors {
		t.Logf("concurrent add warning: %v", err)
		errCount++
	}

	// Verify documents were added
	count, err := store.Count(ctx, nil)
	require.NoError(t, err)

	t.Logf("Successfully added %d/%d documents concurrently, total count: %d",
		successCount.Load(), numGoroutines, count)
	assert.GreaterOrEqual(t, int(successCount.Load()), 1, "at least one document should be added")
}

// TestStore_ConcurrentSearch tests that multiple goroutines can search simultaneously.
func TestStore_ConcurrentSearch(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// First, add some test documents
	for i := 0; i < 3; i++ {
		doc := Document{
			ID:       fmt.Sprintf("search-race-doc-%d", i),
			Content:  fmt.Sprintf("Document about AI technology and machine learning topic %d", i),
			Metadata: map[string]string{"source_type": SourceTypeSystem},
			CreateAt: time.Now(),
		}
		if err := store.Add(ctx, doc); err != nil {
			t.Logf("Warning: failed to add test document %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	const numGoroutines = 5
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	var successCount atomic.Int32

	queries := []string{
		"AI technology",
		"machine learning",
		"artificial intelligence",
		"deep learning",
		"neural networks",
	}

	// Search concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			query := queries[id%len(queries)]
			results, err := store.Search(ctx, query, WithTopK(5))
			if err != nil {
				errors <- fmt.Errorf("goroutine %d (query=%q): %w", id, query, err)
				return
			}
			_ = results
			successCount.Add(1)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Logf("concurrent search warning: %v", err)
	}

	t.Logf("Successfully completed %d/%d concurrent searches", successCount.Load(), numGoroutines)
	assert.GreaterOrEqual(t, int(successCount.Load()), 1, "at least one search should succeed")
}

// TestStore_ConcurrentAddSearchDelete tests mixed operations running concurrently.
func TestStore_ConcurrentAddSearchDelete(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Pre-create some documents
	docIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		docIDs[i] = fmt.Sprintf("mixed-race-doc-%d", i)
		doc := Document{
			ID:       docIDs[i],
			Content:  fmt.Sprintf("Pre-created document for mixed race test %d", i),
			Metadata: map[string]string{"source_type": SourceTypeSystem},
			CreateAt: time.Now(),
		}
		if err := store.Add(ctx, doc); err != nil {
			t.Logf("Warning: failed to pre-create document %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	var wg sync.WaitGroup

	// Add operation
	wg.Add(1)
	go func() {
		defer wg.Done()
		doc := Document{
			ID:       "mixed-race-new-doc",
			Content:  "Newly added document during concurrent operations",
			Metadata: map[string]string{"source_type": SourceTypeSystem},
			CreateAt: time.Now(),
		}
		if err := store.Add(ctx, doc); err != nil {
			t.Logf("Add warning: %v", err)
		}
	}()

	// Search operations (multiple)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := store.Search(ctx, "document test", WithTopK(5))
			if err != nil {
				t.Logf("Search %d warning: %v", id, err)
			}
		}(i)
	}

	// Delete operation
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(docIDs) > 0 {
			if err := store.Delete(ctx, docIDs[0]); err != nil {
				t.Logf("Delete warning: %v", err)
			}
		}
	}()

	// Count operation
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := store.Count(ctx, nil)
		if err != nil {
			t.Logf("Count warning: %v", err)
		}
	}()

	wg.Wait()

	// Verify database is still accessible and consistent
	count, err := store.Count(ctx, nil)
	require.NoError(t, err, "database should be accessible after concurrent operations")

	t.Logf("Mixed concurrent operations completed, final document count: %d", count)
}

// TestStore_RaceDetector is designed to trigger the Go race detector.
// Run with: go test -race -tags=integration ./internal/knowledge/...
func TestStore_RaceDetector(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupIntegrationTest(t)
	defer cleanup()

	// Pre-create a document for operations
	doc := Document{
		ID:       "race-detector-doc",
		Content:  "Test document for race detector",
		Metadata: map[string]string{"source_type": SourceTypeSystem},
		CreateAt: time.Now(),
	}
	if err := store.Add(ctx, doc); err != nil {
		t.Fatalf("Failed to create test document: %v", err)
	}

	var wg sync.WaitGroup
	const numOps = 10

	for i := 0; i < numOps; i++ {
		// Count operation - lightweight, no API call
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Count(ctx, nil)
		}()
	}

	// A few search operations (limited due to API rate limits)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, _ = store.Search(ctx, "test", WithTopK(3))
		}(i)
	}

	wg.Wait()
	t.Log("Race detector test completed - if no race detected, Store is thread-safe")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
