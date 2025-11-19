package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKnowledgeStore_IndexDocument_Integration tests indexing a single document
func TestKnowledgeStore_IndexDocument_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()
	pool, cleanup := setupTestDB(t, ctx)
	defer cleanup()

	embedder, logger := setupEmbedder(t, ctx)
	store := New(pool, embedder, logger)

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
