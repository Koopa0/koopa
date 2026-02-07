//go:build integration

// Package rag_test provides integration tests for RAG system knowledge functions.
package rag_test

import (
	"context"
	"testing"

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
	if err != nil {
		t.Fatalf("IndexSystemKnowledge() first-time indexing unexpected error: %v (should succeed)", err)
	}
	if count <= 0 {
		t.Errorf("IndexSystemKnowledge() count = %d, want > 0 (should index at least one document)", count)
	}

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
	if err != nil {
		t.Fatalf("IndexSystemKnowledge() first indexing unexpected error: %v (should succeed)", err)
	}

	// Second indexing (should not create duplicates)
	count2, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool)
	if err != nil {
		t.Fatalf("IndexSystemKnowledge() re-indexing unexpected error: %v (should succeed)", err)
	}

	if count1 != count2 {
		t.Errorf("IndexSystemKnowledge() re-indexing count = %d, want %d (should index same number of documents)", count2, count1)
	}

	// Verify no duplicates by counting documents with system source type
	var totalCount int
	err = dbContainer.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM documents WHERE metadata->>'source_type' = $1`,
		rag.SourceTypeSystem,
	).Scan(&totalCount)
	if err != nil {
		t.Fatalf("QueryRow() counting documents unexpected error: %v (should succeed)", err)
	}

	if totalCount != count1 {
		t.Errorf("total system documents after re-indexing = %d, want %d (should have no duplicate documents)", totalCount, count1)
	}
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
	if _, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool); err != nil {
		t.Fatalf("IndexSystemKnowledge() unexpected error: %v", err)
	}

	// Query documents and verify metadata
	rows, err := dbContainer.Pool.Query(ctx,
		`SELECT id, metadata FROM documents WHERE metadata->>'source_type' = $1`,
		rag.SourceTypeSystem,
	)
	if err != nil {
		t.Fatalf("Query() unexpected error: %v", err)
	}
	defer rows.Close()

	docCount := 0
	for rows.Next() {
		var id string
		var metadata map[string]any
		if err := rows.Scan(&id, &metadata); err != nil {
			t.Fatalf("rows.Scan() unexpected error: %v", err)
		}

		// Verify required metadata fields
		if metadata["id"] == "" || metadata["id"] == nil {
			t.Errorf("document %q metadata[id] = empty, want non-empty", id)
		}
		if metadata["source_type"] == "" || metadata["source_type"] == nil {
			t.Errorf("document %q metadata[source_type] = empty, want non-empty", id)
		}
		if metadata["category"] == "" || metadata["category"] == nil {
			t.Errorf("document %q metadata[category] = empty, want non-empty", id)
		}
		if metadata["topic"] == "" || metadata["topic"] == nil {
			t.Errorf("document %q metadata[topic] = empty, want non-empty", id)
		}

		docCount++
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err() unexpected error: %v", err)
	}
	if docCount <= 0 {
		t.Errorf("verified documents count = %d, want > 0 (should have at least one system document)", docCount)
	}
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
	if _, err := rag.IndexSystemKnowledge(ctx, ragSetup.DocStore, dbContainer.Pool); err != nil {
		t.Fatalf("IndexSystemKnowledge() unexpected error: %v", err)
	}

	// Query for duplicate IDs
	rows, err := dbContainer.Pool.Query(ctx,
		`SELECT metadata->>'id' as doc_id, COUNT(*) as cnt
		 FROM documents
		 WHERE metadata->>'source_type' = $1
		 GROUP BY metadata->>'id'
		 HAVING COUNT(*) > 1`,
		rag.SourceTypeSystem,
	)
	if err != nil {
		t.Fatalf("Query() unexpected error: %v", err)
	}
	defer rows.Close()

	duplicates := 0
	for rows.Next() {
		var docID string
		var count int
		if err := rows.Scan(&docID, &count); err != nil {
			t.Fatalf("rows.Scan() unexpected error: %v", err)
		}
		t.Errorf("duplicate document ID found: %s (count: %d)", docID, count)
		duplicates++
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err() unexpected error: %v", err)
	}
	if duplicates != 0 {
		t.Errorf("duplicate document IDs = %d, want 0", duplicates)
	}
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
	if err == nil {
		t.Error("IndexSystemKnowledge(canceled context) error = nil, want non-nil (should fail with canceled context)")
	}
	t.Logf("Expected error: %v", err)
}
