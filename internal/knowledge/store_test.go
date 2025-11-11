package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// ============================================================================
// Mock Implementations
// ============================================================================

// mockEmbedder implements ai.Embedder for testing
type mockEmbedder struct {
	delay         time.Duration // Simulate processing delay
	embedErr      error         // Error to return
	returnEmpty   bool          // Return empty embeddings
	returnNil     bool          // Return nil embeddings array
	embeddings    []float32     // Custom embeddings to return
	callCount     int           // Track number of calls
	lastInputText string        // Track last input for verification
}

func (m *mockEmbedder) Name() string {
	return "mock-embedder"
}

func (m *mockEmbedder) Register(r api.Registry) {
	// No-op for testing
}

func (m *mockEmbedder) Embed(ctx context.Context, req *ai.EmbedRequest) (*ai.EmbedResponse, error) {
	m.callCount++

	// Track last input
	if len(req.Input) > 0 && len(req.Input[0].Content) > 0 {
		// ai.Part is a struct with Text field (not an interface)
		m.lastInputText = req.Input[0].Content[0].Text
	}

	// Simulate delay
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
			// Normal completion
		case <-ctx.Done():
			// Context canceled (timeout)
			return nil, ctx.Err()
		}
	}

	// Return error if configured
	if m.embedErr != nil {
		return nil, m.embedErr
	}

	// Return nil embeddings array
	if m.returnNil {
		return &ai.EmbedResponse{
			Embeddings: nil,
		}, nil
	}

	// Return empty embeddings
	if m.returnEmpty {
		return &ai.EmbedResponse{
			Embeddings: []*ai.Embedding{
				{
					Embedding: []float32{},
				},
			},
		}, nil
	}

	// Return custom or default embedding
	embeddings := m.embeddings
	if embeddings == nil {
		embeddings = []float32{0.1, 0.2, 0.3}
	}

	return &ai.EmbedResponse{
		Embeddings: []*ai.Embedding{
			{
				Embedding: embeddings,
			},
		},
	}, nil
}

// mockKnowledgeQuerier implements KnowledgeQuerier for testing
type mockKnowledgeQuerier struct {
	// Error configuration
	upsertErr           error
	searchErr           error
	searchAllErr        error
	countErr            error
	countAllErr         error
	deleteErr           error
	listBySourceTypeErr error

	// Return values
	searchResults          []sqlc.SearchDocumentsRow
	searchAllResults       []sqlc.SearchDocumentsAllRow
	countResult            int64
	countAllResult         int64
	listBySourceTypeResult []sqlc.ListDocumentsBySourceTypeRow

	// Call tracking
	upsertCalls           int
	searchCalls           int
	searchAllCalls        int
	countCalls            int
	countAllCalls         int
	deleteCalls           int
	listBySourceTypeCalls int
	lastDeletedID         string
	lastUpsertParams      sqlc.UpsertDocumentParams
	lastSearchParams      sqlc.SearchDocumentsParams
	lastSearchAllParams   sqlc.SearchDocumentsAllParams
	lastListSourceType    string
}

func (m *mockKnowledgeQuerier) UpsertDocument(ctx context.Context, arg sqlc.UpsertDocumentParams) error {
	m.upsertCalls++
	m.lastUpsertParams = arg
	return m.upsertErr
}

func (m *mockKnowledgeQuerier) SearchDocuments(ctx context.Context, arg sqlc.SearchDocumentsParams) ([]sqlc.SearchDocumentsRow, error) {
	m.searchCalls++
	m.lastSearchParams = arg
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	return m.searchResults, nil
}

func (m *mockKnowledgeQuerier) SearchDocumentsAll(ctx context.Context, arg sqlc.SearchDocumentsAllParams) ([]sqlc.SearchDocumentsAllRow, error) {
	m.searchAllCalls++
	m.lastSearchAllParams = arg
	if m.searchAllErr != nil {
		return nil, m.searchAllErr
	}
	return m.searchAllResults, nil
}

func (m *mockKnowledgeQuerier) CountDocuments(ctx context.Context, filterMetadata []byte) (int64, error) {
	m.countCalls++
	return m.countResult, m.countErr
}

func (m *mockKnowledgeQuerier) CountDocumentsAll(ctx context.Context) (int64, error) {
	m.countAllCalls++
	return m.countAllResult, m.countAllErr
}

func (m *mockKnowledgeQuerier) DeleteDocument(ctx context.Context, id string) error {
	m.deleteCalls++
	m.lastDeletedID = id
	return m.deleteErr
}

func (m *mockKnowledgeQuerier) ListDocumentsBySourceType(ctx context.Context, arg sqlc.ListDocumentsBySourceTypeParams) ([]sqlc.ListDocumentsBySourceTypeRow, error) {
	m.listBySourceTypeCalls++
	m.lastListSourceType = arg.SourceType
	if m.listBySourceTypeErr != nil {
		return nil, m.listBySourceTypeErr
	}
	return m.listBySourceTypeResult, nil
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewWithQuerier(t *testing.T) {
	tests := []struct {
		name         string
		logger       *slog.Logger
		expectNilLog bool
	}{
		{
			name:         "with custom logger",
			logger:       slog.Default(),
			expectNilLog: false,
		},
		{
			name:         "with nil logger (uses default)",
			logger:       nil,
			expectNilLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := &mockKnowledgeQuerier{}
			mockEmbed := &mockEmbedder{}

			store := NewWithQuerier(mockQuerier, mockEmbed, tt.logger)

			if store == nil {
				t.Fatal("NewWithQuerier returned nil")
				return
			}

			if store.queries != mockQuerier {
				t.Error("querier not set correctly")
			}

			// Note: We can't directly compare embedder since it's an interface
			// Just verify it's not nil
			if store.embedder == nil {
				t.Error("embedder should not be nil")
			}

			if store.logger == nil {
				t.Error("logger should never be nil (should use default)")
			}
		})
	}
}

// ============================================================================
// Store.Add Tests
// ============================================================================

func TestStore_Add_Success(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{}
	mockEmbed := &mockEmbedder{
		embeddings: []float32{0.5, 0.6, 0.7},
	}

	store := NewWithQuerier(mockQuerier, mockEmbed, nil)
	ctx := context.Background()

	doc := Document{
		ID:      "test-doc-1",
		Content: "Test content for embedding",
		Metadata: map[string]string{
			"source_type": "test",
			"author":      "test-user",
		},
		CreateAt: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
	}

	err := store.Add(ctx, doc)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Verify embedder was called
	if mockEmbed.callCount != 1 {
		t.Errorf("expected embedder to be called once, got %d", mockEmbed.callCount)
	}

	if mockEmbed.lastInputText != doc.Content {
		t.Errorf("embedder received wrong content: got %q, want %q", mockEmbed.lastInputText, doc.Content)
	}

	// Verify querier was called
	if mockQuerier.upsertCalls != 1 {
		t.Errorf("expected upsert to be called once, got %d", mockQuerier.upsertCalls)
	}

	// Verify upsert params
	params := mockQuerier.lastUpsertParams
	if params.ID != doc.ID {
		t.Errorf("upsert ID mismatch: got %q, want %q", params.ID, doc.ID)
	}

	if params.Content != doc.Content {
		t.Errorf("upsert content mismatch")
	}

	// Verify embedding vector
	if params.Embedding == nil {
		t.Fatal("embedding is nil")
	}

	if len(params.Embedding.Slice()) != 3 {
		t.Errorf("expected 3-dimension embedding, got %d", len(params.Embedding.Slice()))
	}

	// Verify metadata JSON
	var metadata map[string]string
	if err := json.Unmarshal(params.Metadata, &metadata); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	if metadata["source_type"] != "test" {
		t.Error("metadata source_type mismatch")
	}
}

func TestStore_Add_EmbeddingError(t *testing.T) {
	tests := []struct {
		name        string
		embedErr    error
		returnEmpty bool
		returnNil   bool
		expectErr   string
	}{
		{
			name:      "embedding generation fails",
			embedErr:  errors.New("embedding service unavailable"),
			expectErr: "failed to generate embedding",
		},
		{
			name:        "empty embedding returned",
			returnEmpty: true,
			expectErr:   "empty embedding returned",
		},
		{
			name:      "nil embeddings array",
			returnNil: true,
			expectErr: "empty embedding returned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := &mockKnowledgeQuerier{}
			mockEmbed := &mockEmbedder{
				embedErr:    tt.embedErr,
				returnEmpty: tt.returnEmpty,
				returnNil:   tt.returnNil,
			}

			store := NewWithQuerier(mockQuerier, mockEmbed, nil)

			doc := Document{
				ID:      "test-doc",
				Content: "Test content",
			}

			err := store.Add(context.Background(), doc)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !contains(err.Error(), tt.expectErr) {
				t.Errorf("error message %q does not contain %q", err.Error(), tt.expectErr)
			}

			// Verify upsert was not called
			if mockQuerier.upsertCalls > 0 {
				t.Error("upsert should not be called when embedding fails")
			}
		})
	}
}

func TestStore_Add_UpsertError(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{
		upsertErr: errors.New("database connection lost"),
	}
	mockEmbed := &mockEmbedder{}

	store := NewWithQuerier(mockQuerier, mockEmbed, nil)

	doc := Document{
		ID:      "test-doc",
		Content: "Test content",
	}

	err := store.Add(context.Background(), doc)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "failed to upsert document") {
		t.Errorf("unexpected error message: %v", err)
	}

	if !contains(err.Error(), "database connection lost") {
		t.Errorf("error should wrap original error: %v", err)
	}
}

// ============================================================================
// Store.Search Tests
// ============================================================================

func TestStore_Search_Success_WithFilter(t *testing.T) {
	metadataJSON := []byte(`{"source_type":"test","status":"active"}`)

	mockQuerier := &mockKnowledgeQuerier{
		searchResults: []sqlc.SearchDocumentsRow{
			{
				ID:       "doc1",
				Content:  "Test document 1",
				Metadata: metadataJSON,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
					Valid: true,
				},
				Similarity: 0.95,
			},
			{
				ID:       "doc2",
				Content:  "Test document 2",
				Metadata: metadataJSON,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC),
					Valid: true,
				},
				Similarity: 0.87,
			},
		},
	}
	mockEmbed := &mockEmbedder{}

	store := NewWithQuerier(mockQuerier, mockEmbed, nil)

	results, err := store.Search(
		context.Background(),
		"test query",
		WithTopK(10),
		WithFilter("source_type", "test"),
		WithFilter("status", "active"),
	)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify first result
	if results[0].Document.ID != "doc1" {
		t.Errorf("first result ID mismatch: got %q", results[0].Document.ID)
	}

	if results[0].Similarity != 0.95 {
		t.Errorf("first result similarity mismatch: got %f", results[0].Similarity)
	}

	// Verify metadata parsing
	if results[0].Document.Metadata["source_type"] != "test" {
		t.Error("metadata not parsed correctly")
	}

	// Verify search was called with filter
	if mockQuerier.searchCalls != 1 {
		t.Errorf("expected 1 search call, got %d", mockQuerier.searchCalls)
	}

	if mockQuerier.searchAllCalls > 0 {
		t.Error("searchAll should not be called when filter is provided")
	}

	// Verify topK parameter
	if mockQuerier.lastSearchParams.ResultLimit != 10 {
		t.Errorf("expected topK=10, got %d", mockQuerier.lastSearchParams.ResultLimit)
	}
}

func TestStore_Search_Success_WithoutFilter(t *testing.T) {
	metadataJSON := []byte(`{"source_type":"test"}`)

	mockQuerier := &mockKnowledgeQuerier{
		searchAllResults: []sqlc.SearchDocumentsAllRow{
			{
				ID:       "doc1",
				Content:  "Test document",
				Metadata: metadataJSON,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
					Valid: true,
				},
				Similarity: 0.92,
			},
		},
	}
	mockEmbed := &mockEmbedder{}

	store := NewWithQuerier(mockQuerier, mockEmbed, nil)

	results, err := store.Search(context.Background(), "test query")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Verify searchAll was called (not search)
	if mockQuerier.searchAllCalls != 1 {
		t.Errorf("expected 1 searchAll call, got %d", mockQuerier.searchAllCalls)
	}

	if mockQuerier.searchCalls > 0 {
		t.Error("search should not be called without filter")
	}

	// Verify default topK=5
	if mockQuerier.lastSearchAllParams.ResultLimit != 5 {
		t.Errorf("expected default topK=5, got %d", mockQuerier.lastSearchAllParams.ResultLimit)
	}
}

func TestStore_Search_EmbeddingError(t *testing.T) {
	tests := []struct {
		name      string
		embedErr  error
		expectErr string
	}{
		{
			name:      "embedding timeout",
			embedErr:  context.DeadlineExceeded,
			expectErr: "embedding generation timeout",
		},
		{
			name:      "embedding service error",
			embedErr:  errors.New("service unavailable"),
			expectErr: "failed to generate query embedding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := &mockKnowledgeQuerier{}
			mockEmbed := &mockEmbedder{
				embedErr: tt.embedErr,
			}

			store := NewWithQuerier(mockQuerier, mockEmbed, nil)

			_, err := store.Search(context.Background(), "test query")
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !contains(err.Error(), tt.expectErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.expectErr)
			}

			// Verify database queries were not called
			if mockQuerier.searchCalls > 0 || mockQuerier.searchAllCalls > 0 {
				t.Error("database queries should not be called when embedding fails")
			}
		})
	}
}

func TestStore_Search_EmptyEmbedding(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{}
	mockEmbed := &mockEmbedder{
		returnEmpty: true,
	}

	store := NewWithQuerier(mockQuerier, mockEmbed, nil)

	_, err := store.Search(context.Background(), "test query")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "empty embedding returned for query") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStore_Search_QueryError(t *testing.T) {
	tests := []struct {
		name         string
		useFilter    bool
		searchErr    error
		searchAllErr error
		expectErr    string
	}{
		{
			name:      "search with filter timeout",
			useFilter: true,
			searchErr: context.DeadlineExceeded,
			expectErr: "search query timeout",
		},
		{
			name:      "search with filter database error",
			useFilter: true,
			searchErr: errors.New("connection lost"),
			expectErr: "search failed",
		},
		{
			name:         "search all timeout",
			useFilter:    false,
			searchAllErr: context.DeadlineExceeded,
			expectErr:    "search query timeout",
		},
		{
			name:         "search all database error",
			useFilter:    false,
			searchAllErr: errors.New("table does not exist"),
			expectErr:    "search failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := &mockKnowledgeQuerier{
				searchErr:    tt.searchErr,
				searchAllErr: tt.searchAllErr,
			}
			mockEmbed := &mockEmbedder{}

			store := NewWithQuerier(mockQuerier, mockEmbed, nil)

			var opts []SearchOption
			if tt.useFilter {
				opts = append(opts, WithFilter("source_type", "test"))
			}

			_, err := store.Search(context.Background(), "test query", opts...)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !contains(err.Error(), tt.expectErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.expectErr)
			}
		})
	}
}

func TestStore_Search_MetadataParseError(t *testing.T) {
	// Test that invalid metadata JSON is handled gracefully
	mockQuerier := &mockKnowledgeQuerier{
		searchAllResults: []sqlc.SearchDocumentsAllRow{
			{
				ID:         "doc1",
				Content:    "Test",
				Metadata:   []byte(`{invalid json}`), // Invalid JSON
				Similarity: 0.9,
			},
		},
	}
	mockEmbed := &mockEmbedder{}

	store := NewWithQuerier(mockQuerier, mockEmbed, nil)

	results, err := store.Search(context.Background(), "test")
	if err != nil {
		t.Fatalf("Search should not fail on metadata parse error: %v", err)
	}

	// Should still return results with empty metadata
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if len(results[0].Document.Metadata) != 0 {
		t.Error("metadata should be empty map on parse error")
	}
}

// ============================================================================
// Store.Count Tests
// ============================================================================

func TestStore_Count_Success(t *testing.T) {
	tests := []struct {
		name           string
		filter         map[string]string
		mockCount      int64
		expectFiltered bool
	}{
		{
			name: "count with filter",
			filter: map[string]string{
				"source_type": "notion",
				"status":      "active",
			},
			mockCount:      42,
			expectFiltered: true,
		},
		{
			name:           "count all (no filter)",
			filter:         nil,
			mockCount:      100,
			expectFiltered: false,
		},
		{
			name:           "count all (empty filter)",
			filter:         map[string]string{},
			mockCount:      75,
			expectFiltered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := &mockKnowledgeQuerier{
				countResult:    tt.mockCount,
				countAllResult: tt.mockCount,
			}

			store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

			count, err := store.Count(context.Background(), tt.filter)
			if err != nil {
				t.Fatalf("Count failed: %v", err)
			}

			if count != int(tt.mockCount) {
				t.Errorf("count mismatch: got %d, want %d", count, tt.mockCount)
			}

			// Verify correct query method was called
			if tt.expectFiltered {
				if mockQuerier.countCalls != 1 {
					t.Errorf("expected countCalls=1, got %d", mockQuerier.countCalls)
				}
				if mockQuerier.countAllCalls > 0 {
					t.Error("countAll should not be called with filter")
				}
			} else {
				if mockQuerier.countAllCalls != 1 {
					t.Errorf("expected countAllCalls=1, got %d", mockQuerier.countAllCalls)
				}
				if mockQuerier.countCalls > 0 {
					t.Error("count should not be called without filter")
				}
			}
		})
	}
}

func TestStore_Count_Error(t *testing.T) {
	tests := []struct {
		name      string
		filter    map[string]string
		countErr  error
		expectErr string
	}{
		{
			name:      "count with filter error",
			filter:    map[string]string{"key": "value"},
			countErr:  errors.New("database timeout"),
			expectErr: "count failed",
		},
		{
			name:      "count all error",
			filter:    nil,
			countErr:  errors.New("connection lost"),
			expectErr: "count failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := &mockKnowledgeQuerier{
				countErr:    tt.countErr,
				countAllErr: tt.countErr,
			}

			store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

			_, err := store.Count(context.Background(), tt.filter)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !contains(err.Error(), tt.expectErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.expectErr)
			}
		})
	}
}

// ============================================================================
// Store.Delete Tests
// ============================================================================

func TestStore_Delete_Success(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{}
	store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

	err := store.Delete(context.Background(), "test-doc-123")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if mockQuerier.deleteCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", mockQuerier.deleteCalls)
	}

	if mockQuerier.lastDeletedID != "test-doc-123" {
		t.Errorf("wrong document ID deleted: got %q", mockQuerier.lastDeletedID)
	}
}

func TestStore_Delete_Error(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{
		deleteErr: errors.New("document not found"),
	}
	store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

	err := store.Delete(context.Background(), "missing-doc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "failed to delete document") {
		t.Errorf("unexpected error: %v", err)
	}

	if !contains(err.Error(), "document not found") {
		t.Errorf("error should wrap original error: %v", err)
	}
}

// ============================================================================
// Store.Close Tests
// ============================================================================

func TestStore_Close(t *testing.T) {
	store := NewWithQuerier(&mockKnowledgeQuerier{}, &mockEmbedder{}, nil)

	err := store.Close()
	if err != nil {
		t.Errorf("Close should always return nil, got: %v", err)
	}
}

// ============================================================================
// Store.ListBySourceType Tests
// ============================================================================

func TestStore_ListBySourceType_Success(t *testing.T) {
	metadataJSON := []byte(`{"source_type":"notion","page_id":"123"}`)

	mockQuerier := &mockKnowledgeQuerier{
		listBySourceTypeResult: []sqlc.ListDocumentsBySourceTypeRow{
			{
				ID:       "doc1",
				Content:  "Notion page 1",
				Metadata: metadataJSON,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
					Valid: true,
				},
			},
			{
				ID:       "doc2",
				Content:  "Notion page 2",
				Metadata: metadataJSON,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC),
					Valid: true,
				},
			},
		},
	}

	store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

	docs, err := store.ListBySourceType(context.Background(), "notion", 10)
	if err != nil {
		t.Fatalf("ListBySourceType failed: %v", err)
	}

	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}

	// Verify first document
	if docs[0].ID != "doc1" {
		t.Errorf("first doc ID mismatch: got %q", docs[0].ID)
	}

	if docs[0].Metadata["source_type"] != "notion" {
		t.Error("metadata not parsed correctly")
	}

	// Verify method was called correctly
	if mockQuerier.listBySourceTypeCalls != 1 {
		t.Errorf("expected 1 call, got %d", mockQuerier.listBySourceTypeCalls)
	}

	if mockQuerier.lastListSourceType != "notion" {
		t.Errorf("wrong source type passed: got %q", mockQuerier.lastListSourceType)
	}
}

func TestStore_ListBySourceType_Error(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{
		listBySourceTypeErr: errors.New("table does not exist"),
	}

	store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

	_, err := store.ListBySourceType(context.Background(), "notion", 10)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !contains(err.Error(), "failed to list documents") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStore_ListBySourceType_MetadataParseError(t *testing.T) {
	mockQuerier := &mockKnowledgeQuerier{
		listBySourceTypeResult: []sqlc.ListDocumentsBySourceTypeRow{
			{
				ID:       "doc1",
				Content:  "Test",
				Metadata: []byte(`{invalid}`), // Invalid JSON
			},
		},
	}

	store := NewWithQuerier(mockQuerier, &mockEmbedder{}, nil)

	docs, err := store.ListBySourceType(context.Background(), "test", 10)
	if err != nil {
		t.Fatalf("ListBySourceType should not fail on metadata parse error: %v", err)
	}

	// Should still return documents with empty metadata
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}

	if len(docs[0].Metadata) != 0 {
		t.Error("metadata should be empty map on parse error")
	}
}

// ============================================================================
// Existing Tests (Preserved)
// ============================================================================

// TestSearchTimeout tests that Search respects context timeout
func TestSearchTimeout(t *testing.T) {
	// Create embedder with 15 second delay (longer than timeout)
	embedder := &mockEmbedder{delay: 15 * time.Second}

	// Note: We can't create a real Store without a database connection,
	// so this test demonstrates the concept. In real scenarios, you'd use
	// a test database or mock the queries interface.

	ctx := context.Background()

	// Start embedding with timeout
	startTime := time.Now()
	_, err := embedder.Embed(ctx, &ai.EmbedRequest{
		Input: []*ai.Document{
			{Content: []*ai.Part{ai.NewTextPart("test query")}},
		},
	})

	elapsed := time.Since(startTime)

	// Should complete in 15 seconds (the delay)
	if elapsed < 14*time.Second || elapsed > 16*time.Second {
		t.Logf("embedding took %v (expected ~15s)", elapsed)
	}

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSearchTimeoutCancellation tests context cancellation during search
func TestSearchTimeoutCancellation(t *testing.T) {
	// Create embedder with 5 second delay
	embedder := &mockEmbedder{delay: 5 * time.Second}

	// Create context with 1 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	startTime := time.Now()
	_, err := embedder.Embed(ctx, &ai.EmbedRequest{
		Input: []*ai.Document{
			{Content: []*ai.Part{ai.NewTextPart("test query")}},
		},
	})
	elapsed := time.Since(startTime)

	// Should fail with timeout error in ~1 second
	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	// Should complete quickly (within 2 seconds)
	if elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v (expected ~1s)", elapsed)
	}

	t.Logf("timeout correctly triggered after %v", elapsed)
}

// TestDocumentOperations tests basic document operations
func TestDocumentOperations(t *testing.T) {
	// Test Document struct
	doc := Document{
		ID:      "test-doc-1",
		Content: "This is a test document for vector search",
		Metadata: map[string]string{
			"source_type": "test",
			"author":      "test-user",
		},
	}

	if doc.ID == "" {
		t.Error("document ID should not be empty")
	}

	if doc.Content == "" {
		t.Error("document content should not be empty")
	}

	if len(doc.Metadata) != 2 {
		t.Errorf("expected 2 metadata fields, got %d", len(doc.Metadata))
	}
}

// TestResultStruct tests Result structure
func TestResultStruct(t *testing.T) {
	doc := Document{
		ID:      "test-doc-1",
		Content: "Test content",
		Metadata: map[string]string{
			"source_type": "test",
		},
	}

	result := Result{
		Similarity: 0.95,
	}
	// Use the document ID to verify structure
	_ = doc.ID

	// Verify similarity is float64
	var _ float64 = result.Similarity

	if result.Similarity < 0.0 || result.Similarity > 1.0 {
		t.Errorf("similarity should be between 0 and 1, got %f", result.Similarity)
	}

	// Test that float64 provides better precision than float32
	highPrecision := 0.123456789012345
	result.Similarity = highPrecision

	// float64 should maintain precision
	if result.Similarity != highPrecision {
		t.Errorf("float64 lost precision: expected %v, got %v", highPrecision, result.Similarity)
	}
}

// TestSearchOptions tests search option building
func TestSearchOptions(t *testing.T) {
	// Test default config
	cfg := buildSearchConfig(nil)
	if cfg.topK != 5 {
		t.Errorf("default topK should be 5, got %d", cfg.topK)
	}
	if len(cfg.filter) != 0 {
		t.Errorf("default filter should be empty, got %v", cfg.filter)
	}

	// Test WithTopK option
	cfg = buildSearchConfig([]SearchOption{WithTopK(10)})
	if cfg.topK != 10 {
		t.Errorf("expected topK 10, got %d", cfg.topK)
	}

	// Test WithFilter option
	cfg = buildSearchConfig([]SearchOption{
		WithFilter("source_type", "conversation"),
	})
	if cfg.filter["source_type"] != "conversation" {
		t.Errorf("expected filter source_type=conversation, got %v", cfg.filter)
	}

	// Test multiple options
	cfg = buildSearchConfig([]SearchOption{
		WithTopK(20),
		WithFilter("source_type", "notion"),
		WithFilter("status", "active"),
	})
	if cfg.topK != 20 {
		t.Errorf("expected topK 20, got %d", cfg.topK)
	}
	if len(cfg.filter) != 2 {
		t.Errorf("expected 2 filters, got %d", len(cfg.filter))
	}
}

// TestFloat64Precision tests float64 precision for similarity scores
func TestFloat64Precision(t *testing.T) {
	// This test verifies that we're using float64 for similarity scores
	// which provides ~15 decimal digits of precision vs ~6 for float32

	type testCase struct {
		name  string
		value float64
	}

	tests := []testCase{
		{"high precision", 0.987654321098765},
		{"low precision", 0.1},
		{"near one", 0.999999999999999},
		{"near zero", 0.000000000000001},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Result{
				Document:   Document{ID: "test"},
				Similarity: tt.value,
			}

			// Verify type is float64
			var _ float64 = result.Similarity

			// Verify value is preserved
			if result.Similarity != tt.value {
				t.Errorf("precision lost: expected %v, got %v", tt.value, result.Similarity)
			}

			// If this was float32, we'd lose precision
			float32Value := float32(tt.value)
			if float64(float32Value) == tt.value {
				// OK, this particular value doesn't lose precision in float32
			} else {
				t.Logf("float32 would lose precision: %v -> %v", tt.value, float32Value)
			}
		})
	}
}

// BenchmarkSearchConfigBuild benchmarks search config building
func BenchmarkSearchConfigBuild(b *testing.B) {
	options := []SearchOption{
		WithTopK(10),
		WithFilter("source_type", "test"),
		WithFilter("status", "active"),
	}

	b.ResetTimer()
	for b.Loop() {
		_ = buildSearchConfig(options)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// contains checks if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
