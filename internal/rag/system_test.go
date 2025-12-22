//go:build integration

// Package rag_test provides integration tests for RAG system knowledge functions.
package rag_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/testutil"
)

// TestIndexSystemKnowledge_FirstTime verifies first-time indexing works correctly.
func TestIndexSystemKnowledge_FirstTime(t *testing.T) {
	t.Parallel()

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)
	ctx := context.Background()

	// Index system knowledge for the first time
	count, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)
	require.NoError(t, err, "first-time indexing should succeed")
	assert.Greater(t, count, 0, "should index at least one document")

	t.Logf("Indexed %d system knowledge documents", count)
}

// TestIndexSystemKnowledge_Reindexing verifies UPSERT behavior (no duplicates on re-index).
func TestIndexSystemKnowledge_Reindexing(t *testing.T) {
	t.Parallel()

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)
	ctx := context.Background()

	// First indexing
	count1, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)
	require.NoError(t, err, "first indexing should succeed")

	// Second indexing (should not create duplicates)
	count2, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)
	require.NoError(t, err, "re-indexing should succeed")

	assert.Equal(t, count1, count2, "re-indexing should index same number of documents")

	// Verify no duplicates by counting documents with system source type
	var totalCount int
	err = dbContainer.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM documents WHERE metadata->>'source_type' = $1`,
		rag.SourceTypeSystem,
	).Scan(&totalCount)
	require.NoError(t, err, "counting documents should succeed")

	assert.Equal(t, count1, totalCount, "should have no duplicate documents after re-indexing")
	t.Logf("Total system documents after re-indexing: %d (expected: %d)", totalCount, count1)
}

// TestIndexSystemKnowledge_DocumentMetadata verifies all documents have required metadata.
func TestIndexSystemKnowledge_DocumentMetadata(t *testing.T) {
	t.Parallel()

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)
	ctx := context.Background()

	// Index documents
	_, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)
	require.NoError(t, err)

	// Query documents and verify metadata
	rows, err := dbContainer.Pool.Query(ctx,
		`SELECT id, metadata FROM documents WHERE metadata->>'source_type' = $1`,
		rag.SourceTypeSystem,
	)
	require.NoError(t, err)
	defer rows.Close()

	docCount := 0
	for rows.Next() {
		var id string
		var metadata map[string]any
		err := rows.Scan(&id, &metadata)
		require.NoError(t, err)

		// Verify required metadata fields
		assert.NotEmpty(t, metadata["id"], "document %s should have 'id' metadata", id)
		assert.NotEmpty(t, metadata["source_type"], "document %s should have 'source_type' metadata", id)
		assert.NotEmpty(t, metadata["category"], "document %s should have 'category' metadata", id)
		assert.NotEmpty(t, metadata["topic"], "document %s should have 'topic' metadata", id)

		docCount++
	}

	require.NoError(t, rows.Err())
	assert.Greater(t, docCount, 0, "should have at least one system document")
	t.Logf("Verified metadata for %d documents", docCount)
}

// TestIndexSystemKnowledge_UniqueIDs verifies all documents have unique IDs.
func TestIndexSystemKnowledge_UniqueIDs(t *testing.T) {
	t.Parallel()

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)
	ctx := context.Background()

	// Index documents
	_, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)
	require.NoError(t, err)

	// Query for duplicate IDs
	rows, err := dbContainer.Pool.Query(ctx,
		`SELECT metadata->>'id' as doc_id, COUNT(*) as cnt
		 FROM documents
		 WHERE metadata->>'source_type' = $1
		 GROUP BY metadata->>'id'
		 HAVING COUNT(*) > 1`,
		rag.SourceTypeSystem,
	)
	require.NoError(t, err)
	defer rows.Close()

	duplicates := 0
	for rows.Next() {
		var docID string
		var count int
		err := rows.Scan(&docID, &count)
		require.NoError(t, err)
		t.Errorf("duplicate document ID found: %s (count: %d)", docID, count)
		duplicates++
	}

	require.NoError(t, rows.Err())
	assert.Equal(t, 0, duplicates, "should have no duplicate document IDs")
}

// TestIndexSystemKnowledge_CanceledContext verifies graceful handling of canceled context.
func TestIndexSystemKnowledge_CanceledContext(t *testing.T) {
	t.Parallel()

	dbContainer, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)

	// Create already-canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should fail gracefully with canceled context
	_, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)

	// Error is expected (context canceled)
	assert.Error(t, err, "should fail with canceled context")
	t.Logf("Expected error: %v", err)
}
