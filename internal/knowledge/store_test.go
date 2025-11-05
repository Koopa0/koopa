package knowledge

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestStore_New(t *testing.T) {
	tmpDir := t.TempDir()
	embedder := &mockEmbedder{}

	store, err := New(tmpDir, "test-collection", embedder, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer store.Close()

	if store.db == nil {
		t.Error("store.db is nil")
	}
	if store.collection == nil {
		t.Error("store.collection is nil")
	}
}

func TestStore_AddAndSearch(t *testing.T) {
	tmpDir := t.TempDir()
	embedder := &mockEmbedder{}
	store, err := New(tmpDir, "test-collection", embedder, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Add documents
	docs := []Document{
		{
			ID:      "doc1",
			Content: "This is about artificial intelligence",
			Metadata: map[string]string{
				"source_type": "conversation",
				"topic":       "AI",
			},
			CreateAt: time.Now(),
		},
		{
			ID:      "doc2",
			Content: "This is about machine learning",
			Metadata: map[string]string{
				"source_type": "conversation",
				"topic":       "ML",
			},
			CreateAt: time.Now(),
		},
		{
			ID:      "doc3",
			Content: "This is about cooking recipes",
			Metadata: map[string]string{
				"source_type": "notion",
				"topic":       "food",
			},
			CreateAt: time.Now(),
		},
	}

	for _, doc := range docs {
		if err := store.Add(ctx, doc); err != nil {
			t.Fatalf("Add() failed for %s: %v", doc.ID, err)
		}
	}

	// Test search without filter
	t.Run("search_all", func(t *testing.T) {
		// TopK should not exceed number of documents (3)
		results, err := store.Search(ctx, "intelligence", WithTopK(3))
		if err != nil {
			t.Fatalf("Search() failed: %v", err)
		}

		if len(results) == 0 {
			t.Error("expected at least one result, got 0")
		}
	})

	// Test search with filter
	t.Run("search_with_filter", func(t *testing.T) {
		// Only 2 documents have source_type=conversation
		results, err := store.Search(ctx, "learning",
			WithTopK(2),
			WithFilter("source_type", "conversation"),
		)
		if err != nil {
			t.Fatalf("Search() with filter failed: %v", err)
		}

		// All results should have source_type=conversation
		for _, r := range results {
			if r.Document.Metadata["source_type"] != "conversation" {
				t.Errorf("expected source_type=conversation, got %s", r.Document.Metadata["source_type"])
			}
		}

		// Should not contain doc3 (which is "notion")
		for _, r := range results {
			if r.Document.ID == "doc3" {
				t.Error("filter failed: doc3 (notion) should not be in conversation results")
			}
		}
	})

	// Test TopK limiting
	t.Run("search_topk", func(t *testing.T) {
		results, err := store.Search(ctx, "test", WithTopK(2))
		if err != nil {
			t.Fatalf("Search() failed: %v", err)
		}

		if len(results) > 2 {
			t.Errorf("expected max 2 results, got %d", len(results))
		}
	})
}

func TestStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	embedder := &mockEmbedder{}
	ctx := context.Background()

	// Create store and add a document
	{
		store, err := New(tmpDir, "test-collection", embedder, nil)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		doc := Document{
			ID:      "persistent-doc",
			Content: "This should persist",
			Metadata: map[string]string{
				"test": "persistence",
			},
			CreateAt: time.Now(),
		}

		if err := store.Add(ctx, doc); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		store.Close()
	}

	// Verify database directory contains files
	// chromem-go creates its own file structure
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read tmpDir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("database files were not created")
	}

	// Reopen store and search for the document
	{
		store, err := New(tmpDir, "test-collection", embedder, nil)
		if err != nil {
			t.Fatalf("New() on existing db failed: %v", err)
		}
		defer store.Close()

		results, err := store.Search(ctx, "persist", WithTopK(1))
		if err != nil {
			t.Fatalf("Search() after reopen failed: %v", err)
		}

		found := false
		for _, r := range results {
			if r.Document.ID == "persistent-doc" {
				found = true
				if r.Document.Metadata["test"] != "persistence" {
					t.Errorf("metadata mismatch: got %s, want persistence", r.Document.Metadata["test"])
				}
			}
		}

		if !found {
			t.Error("document not found after persistence")
		}
	}
}

func TestStore_MetadataPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	embedder := &mockEmbedder{}
	store, err := New(tmpDir, "test-collection", embedder, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()

	doc := Document{
		ID:      "meta-test",
		Content: "testing metadata",
		Metadata: map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		},
		CreateAt: now,
	}

	if err := store.Add(ctx, doc); err != nil {
		t.Fatalf("Add() failed: %v", err)
	}

	results, err := store.Search(ctx, "metadata", WithTopK(1))
	if err != nil {
		t.Fatalf("Search() failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("no results returned")
	}

	result := results[0].Document

	// Verify all metadata keys are preserved
	for key, expectedValue := range doc.Metadata {
		if gotValue := result.Metadata[key]; gotValue != expectedValue {
			t.Errorf("metadata[%s] = %s, want %s", key, gotValue, expectedValue)
		}
	}

	// Verify create_at is NOT in metadata (it's in CreateAt field)
	if _, exists := result.Metadata["create_at"]; exists {
		t.Error("create_at should not be in metadata after Search")
	}

	// Verify CreateAt timestamp is preserved (within 1 second tolerance)
	if result.CreateAt.Sub(now).Abs() > time.Second {
		t.Errorf("CreateAt timestamp mismatch: got %v, want %v", result.CreateAt, now)
	}
}

func TestStore_EmptyMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	embedder := &mockEmbedder{}
	store, err := New(tmpDir, "test-collection", embedder, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Add document with nil metadata
	doc := Document{
		ID:       "no-meta",
		Content:  "document without metadata",
		Metadata: nil,
		CreateAt: time.Now(),
	}

	if err := store.Add(ctx, doc); err != nil {
		t.Fatalf("Add() with nil metadata failed: %v", err)
	}

	// Search should still work
	results, err := store.Search(ctx, "document", WithTopK(1))
	if err != nil {
		t.Fatalf("Search() failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected at least one result")
	}
}
