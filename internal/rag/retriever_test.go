package rag

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core/api"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// ============================================================================
// Retriever Constructor Tests
// ============================================================================

func TestRetriever_New(t *testing.T) {
	// Test with nil store (should not panic, just store the nil)
	retriever := New(nil)
	if retriever == nil {
		t.Fatal("New returned nil")
		return
	}

	if retriever.store != nil {
		t.Error("expected nil store to be preserved")
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestExtractQueryText(t *testing.T) {
	tests := []struct {
		name     string
		req      *ai.RetrieverRequest
		expected string
	}{
		{
			name: "valid query with text",
			req: &ai.RetrieverRequest{
				Query: &ai.Document{
					Content: []*ai.Part{
						ai.NewTextPart("test query"),
					},
				},
			},
			expected: "test query",
		},
		{
			name: "nil query",
			req: &ai.RetrieverRequest{
				Query: nil,
			},
			expected: "",
		},
		{
			name: "empty content",
			req: &ai.RetrieverRequest{
				Query: &ai.Document{
					Content: []*ai.Part{},
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractQueryText(tt.req)
			if result != tt.expected {
				t.Errorf("extractQueryText() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractTopK(t *testing.T) {
	tests := []struct {
		name     string
		req      *ai.RetrieverRequest
		defaultK int32
		expected int32
	}{
		{
			name: "with k option",
			req: &ai.RetrieverRequest{
				Options: map[string]any{
					"k": 10,
				},
			},
			defaultK: 5,
			expected: 10,
		},
		{
			name: "without k option",
			req: &ai.RetrieverRequest{
				Options: map[string]any{},
			},
			defaultK: 5,
			expected: 5,
		},
		{
			name:     "nil options",
			req:      &ai.RetrieverRequest{},
			defaultK: 3,
			expected: 3,
		},
		{
			name: "k is not int",
			req: &ai.RetrieverRequest{
				Options: map[string]any{
					"k": "not an int",
				},
			},
			defaultK: 5,
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTopK(tt.req, tt.defaultK)
			if result != tt.expected {
				t.Errorf("extractTopK() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestConvertToGenkitDocuments(t *testing.T) {
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "doc1",
				Content: "test content 1",
				Metadata: map[string]string{
					"source_type": "conversation",
					"session_id":  "123",
				},
			},
			Similarity: 0.95,
		},
		{
			Document: knowledge.Document{
				ID:      "doc2",
				Content: "test content 2",
				Metadata: map[string]string{
					"source_type": "notion",
				},
			},
			Similarity: 0.85,
		},
	}

	docs := convertToGenkitDocuments(results)

	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}

	// Check first document
	if docs[0].Content[0].Text != "test content 1" {
		t.Errorf("doc[0] content = %q, want %q", docs[0].Content[0].Text, "test content 1")
	}

	// Check metadata preservation
	if docs[0].Metadata["source_type"] != "conversation" {
		t.Error("metadata not preserved correctly")
	}

	// Check similarity score in metadata (float64 from knowledge.Result)
	if similarity, ok := docs[0].Metadata["similarity"].(float64); !ok || similarity != 0.95 {
		t.Errorf("similarity = %v, want 0.95", docs[0].Metadata["similarity"])
	}

	// Check second document
	if docs[1].Content[0].Text != "test content 2" {
		t.Errorf("doc[1] content = %q, want %q", docs[1].Content[0].Text, "test content 2")
	}
}

// ============================================================================
// Mock Knowledge Querier for Retriever Tests
// ============================================================================

type mockSearchQuerier struct {
	searchDocumentsFunc    func(ctx context.Context, arg sqlc.SearchDocumentsParams) ([]sqlc.SearchDocumentsRow, error)
	searchDocumentsAllFunc func(ctx context.Context, arg sqlc.SearchDocumentsAllParams) ([]sqlc.SearchDocumentsAllRow, error)
	searchError            error
}

func (*mockSearchQuerier) UpsertDocument(_ context.Context, _ sqlc.UpsertDocumentParams) error {
	return nil
}

func (m *mockSearchQuerier) SearchDocuments(ctx context.Context, arg sqlc.SearchDocumentsParams) ([]sqlc.SearchDocumentsRow, error) {
	if m.searchDocumentsFunc != nil {
		return m.searchDocumentsFunc(ctx, arg)
	}
	if m.searchError != nil {
		return nil, m.searchError
	}
	return []sqlc.SearchDocumentsRow{}, nil
}

func (m *mockSearchQuerier) SearchDocumentsAll(ctx context.Context, arg sqlc.SearchDocumentsAllParams) ([]sqlc.SearchDocumentsAllRow, error) {
	if m.searchDocumentsAllFunc != nil {
		return m.searchDocumentsAllFunc(ctx, arg)
	}
	if m.searchError != nil {
		return nil, m.searchError
	}
	return []sqlc.SearchDocumentsAllRow{}, nil
}

func (*mockSearchQuerier) CountDocuments(_ context.Context, _ []byte) (int64, error) {
	return 0, nil
}

func (*mockSearchQuerier) CountDocumentsAll(_ context.Context) (int64, error) {
	return 0, nil
}

func (*mockSearchQuerier) DeleteDocument(_ context.Context, _ string) error {
	return nil
}

func (*mockSearchQuerier) ListDocumentsBySourceType(_ context.Context, _ sqlc.ListDocumentsBySourceTypeParams) ([]sqlc.ListDocumentsBySourceTypeRow, error) {
	return nil, nil
}

// mockEmbedder is a simple embedder that returns fixed-size embeddings for testing
type mockEmbedder struct{}

func (*mockEmbedder) Embed(_ context.Context, _ *ai.EmbedRequest) (*ai.EmbedResponse, error) {
	// Return a simple 3-dimensional vector
	embedding := &ai.Embedding{Embedding: []float32{0.1, 0.2, 0.3}}
	return &ai.EmbedResponse{Embeddings: []*ai.Embedding{embedding}}, nil
}

func (*mockEmbedder) Name() string {
	return "mockEmbedder"
}

func (*mockEmbedder) Register(_ api.Registry) {
	// No-op for testing
}

// createTestKnowledgeStore creates a knowledge.Store with a mock querier for testing
func createTestKnowledgeStore(querier knowledge.Querier) *knowledge.Store {
	return knowledge.New(querier, &mockEmbedder{}, slog.Default())
}

// ============================================================================
// DefineConversation Tests
// ============================================================================

// TestDefineConversation_Success verifies that DefineConversation creates a working retriever.
// Note: Since helper functions (extractQueryText, extractTopK, convertToGenkitDocuments) are
// already tested at 100%, this test focuses on verifying the retriever can be created and invoked.
func TestDefineConversation_Success(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create a simple mock that returns empty results
	mockQuerier := &mockSearchQuerier{}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	conversationRetriever := retriever.DefineConversation(g, "test-conversation-retriever")

	if conversationRetriever == nil {
		t.Fatal("DefineConversation returned nil retriever")
	}

	// Create a retriever request
	req := &ai.RetrieverRequest{
		Query: &ai.Document{
			Content: []*ai.Part{ai.NewTextPart("test query")},
		},
	}

	// Execute retrieval - should not error even with empty results
	resp, err := conversationRetriever.Retrieve(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}

	// Empty results are okay - we're testing the plumbing works
	if resp.Documents == nil {
		t.Error("expected non-nil Documents slice")
	}
}

// TestDefineConversation_WithTopK verifies that retriever works with custom topK option.
func TestDefineConversation_WithTopK(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	mockQuerier := &mockSearchQuerier{}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	conversationRetriever := retriever.DefineConversation(g, "test-topk-retriever")

	// Create request with custom topK
	req := &ai.RetrieverRequest{
		Query: &ai.Document{
			Content: []*ai.Part{ai.NewTextPart("test query")},
		},
		Options: map[string]any{
			"k": 10,
		},
	}

	resp, err := conversationRetriever.Retrieve(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestDefineConversation_SearchError verifies error handling when Search fails.
func TestDefineConversation_SearchError(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	expectedErr := errors.New("database connection failed")
	mockQuerier := &mockSearchQuerier{
		searchError: expectedErr,
	}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	conversationRetriever := retriever.DefineConversation(g, "test-error-retriever")

	req := &ai.RetrieverRequest{
		Query: &ai.Document{
			Content: []*ai.Part{ai.NewTextPart("test query")},
		},
	}

	_, err := conversationRetriever.Retrieve(ctx, req)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Error should be returned from the retriever
}

// TestDefineConversation_EmptyQuery verifies handling of empty query.
func TestDefineConversation_EmptyQuery(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	mockQuerier := &mockSearchQuerier{}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	conversationRetriever := retriever.DefineConversation(g, "test-empty-query")

	// Request with nil query
	req := &ai.RetrieverRequest{
		Query: nil,
	}

	resp, err := conversationRetriever.Retrieve(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}

	// Empty query is handled gracefully
	if resp.Documents == nil {
		t.Error("expected non-nil Documents slice")
	}
}

// ============================================================================
// DefineDocument Tests
// ============================================================================

// TestDefineDocument_Success verifies that DefineDocument creates a working retriever.
// Like DefineConversation tests, this focuses on verifying the retriever works correctly.
func TestDefineDocument_Success(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	mockQuerier := &mockSearchQuerier{}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	documentRetriever := retriever.DefineDocument(g, "test-document-retriever")

	if documentRetriever == nil {
		t.Fatal("DefineDocument returned nil retriever")
	}

	req := &ai.RetrieverRequest{
		Query: &ai.Document{
			Content: []*ai.Part{ai.NewTextPart("search query")},
		},
	}

	resp, err := documentRetriever.Retrieve(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}

	if resp.Documents == nil {
		t.Error("expected non-nil Documents slice")
	}
}

// TestDefineDocument_WithCustomTopK verifies custom topK in document retriever.
func TestDefineDocument_WithCustomTopK(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	mockQuerier := &mockSearchQuerier{}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	documentRetriever := retriever.DefineDocument(g, "test-custom-topk")

	req := &ai.RetrieverRequest{
		Query: &ai.Document{
			Content: []*ai.Part{ai.NewTextPart("query")},
		},
		Options: map[string]any{
			"k": 20,
		},
	}

	resp, err := documentRetriever.Retrieve(ctx, req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// TestDefineDocument_SearchError verifies error handling in document retriever.
func TestDefineDocument_SearchError(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	expectedErr := errors.New("vector search timeout")
	mockQuerier := &mockSearchQuerier{
		searchError: expectedErr,
	}
	store := createTestKnowledgeStore(mockQuerier)

	retriever := New(store)
	documentRetriever := retriever.DefineDocument(g, "test-doc-error")

	req := &ai.RetrieverRequest{
		Query: &ai.Document{
			Content: []*ai.Part{ai.NewTextPart("query")},
		},
	}

	_, err := documentRetriever.Retrieve(ctx, req)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Error is properly propagated from the search layer
}
