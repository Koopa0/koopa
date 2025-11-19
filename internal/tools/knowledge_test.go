package tools

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockKnowledgeStore is a mock implementation of knowledge.Store for testing.
type MockKnowledgeStore struct {
	mock.Mock
}

// Search is the mock implementation of knowledge.Store.Search method.
func (m *MockKnowledgeStore) Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error) {
	args := m.Called(ctx, query, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]knowledge.Result), args.Error(1)
}

// Helper function to create test ToolContext
func createTestToolContext() *ai.ToolContext {
	return &ai.ToolContext{
		Context: context.Background(),
	}
}

// Helper function to create test conversation results
func createConversationResults() []knowledge.Result {
	return []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "conv-1",
				Content: "User: What is Go?\nAssistant: Go is a statically typed, compiled programming language.",
				Metadata: map[string]string{
					"source_type": "conversation",
					"session_id":  "session-123",
					"timestamp":   "2025-11-18T10:00:00Z",
					"turn_number": "1",
					"tool_count":  "0",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.92,
		},
		{
			Document: knowledge.Document{
				ID:      "conv-2",
				Content: "User: How do I handle errors in Go?\nAssistant: Use error return values and check them explicitly.",
				Metadata: map[string]string{
					"source_type": "conversation",
					"session_id":  "session-123",
					"timestamp":   "2025-11-18T10:05:00Z",
					"turn_number": "2",
					"tool_count":  "1",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.85,
		},
	}
}

// Helper function to create test document results
func createDocumentResults() []knowledge.Result {
	return []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "doc-1",
				Content: "Package main implements a command-line tool...",
				Metadata: map[string]string{
					"source_type": "file",
					"file_path":   "/project/main.go",
					"file_name":   "main.go",
					"file_ext":    ".go",
					"file_size":   "1024",
					"indexed_at":  "2025-11-18T09:00:00Z",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.88,
		},
	}
}

// Helper function to create test system results
func createSystemResults() []knowledge.Result {
	return []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "sys-1",
				Content: "Error handling: Always check error returns and handle them appropriately.",
				Metadata: map[string]string{
					"source_type":    "system",
					"knowledge_type": "style_guide",
					"topic":          "error_handling",
					"version":        "1.0",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.95,
		},
	}
}

// =============================================================================
// SearchHistory Tests
// =============================================================================

func TestHandler_SearchHistory_Success(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	expectedResults := createConversationResults()
	mockStore.On("Search", mock.Anything, "golang", mock.Anything).Return(expectedResults, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchHistory(ctx, "golang", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "Found 2 relevant conversation")
	assert.Contains(t, result, "92.0% match")
	assert.Contains(t, result, "85.0% match")
	assert.Contains(t, result, "session-123")
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchHistory_EmptyResults(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "nonexistent", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchHistory(ctx, "nonexistent", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "No relevant conversations found")
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchHistory_DefaultTopK(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	_, err := handler.SearchHistory(ctx, "test", 0) // topK = 0 should default to 3

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchHistory_TopKClamping(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	_, err := handler.SearchHistory(ctx, "test", 15) // topK = 15 should clamp to 10

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchHistory_StoreError(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return(nil, fmt.Errorf("database connection failed"))

	ctx := createTestToolContext()
	result, err := handler.SearchHistory(ctx, "test", 3)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "history search failed")
	assert.Empty(t, result)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchHistory_LongContent(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	// Create result with very long content (>500 chars)
	longContent := strings.Repeat("This is a very long conversation content. ", 20) // ~840 chars
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "conv-long",
				Content: longContent,
				Metadata: map[string]string{
					"source_type": "conversation",
					"session_id":  "session-456",
					"timestamp":   "2025-11-18T11:00:00Z",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.9,
		},
	}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return(results, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchHistory(ctx, "test", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "Content truncated")
	mockStore.AssertExpectations(t)
}

// =============================================================================
// SearchDocuments Tests
// =============================================================================

func TestHandler_SearchDocuments_Success(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	expectedResults := createDocumentResults()
	mockStore.On("Search", mock.Anything, "command-line tool", mock.Anything).Return(expectedResults, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchDocuments(ctx, "command-line tool", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "Found 1 relevant document")
	assert.Contains(t, result, "88.0% relevance")
	assert.Contains(t, result, "main.go")
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchDocuments_EmptyResults(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "nonexistent", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchDocuments(ctx, "nonexistent", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "No relevant documents found")
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchDocuments_DefaultTopK(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	_, err := handler.SearchDocuments(ctx, "test", 0) // topK = 0 should default to 3

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchDocuments_TopKClamping(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	_, err := handler.SearchDocuments(ctx, "test", 20) // topK = 20 should clamp to 10

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchDocuments_StoreError(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return(nil, fmt.Errorf("vector search failed"))

	ctx := createTestToolContext()
	result, err := handler.SearchDocuments(ctx, "test", 3)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "document search failed")
	assert.Empty(t, result)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchDocuments_LongContent(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	// Create result with very long content (>1000 chars to trigger truncation)
	longContent := strings.Repeat("This is a very long document content. ", 30) // ~1140 chars
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "doc-long",
				Content: longContent,
				Metadata: map[string]string{
					"source_type": "file",
					"file_path":   "/project/long.go",
					"file_name":   "long.go",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.87,
		},
	}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return(results, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchDocuments(ctx, "test", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "Content truncated")
	mockStore.AssertExpectations(t)
}

// =============================================================================
// SearchSystemKnowledge Tests
// =============================================================================

func TestHandler_SearchSystemKnowledge_Success(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	expectedResults := createSystemResults()
	mockStore.On("Search", mock.Anything, "error handling", mock.Anything).Return(expectedResults, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchSystemKnowledge(ctx, "error handling", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "Found 1 relevant system knowledge")
	assert.Contains(t, result, "95.0% match")
	assert.Contains(t, result, "error_handling")
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchSystemKnowledge_EmptyResults(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	// First call: user query returns empty
	mockStore.On("Search", mock.Anything, "nonexistent", mock.Anything).Return([]knowledge.Result{}, nil)
	// Second call: system check to verify if system knowledge is indexed (returns empty = not indexed)
	mockStore.On("Search", mock.Anything, "system", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchSystemKnowledge(ctx, "nonexistent", 3)

	assert.NoError(t, err)
	assert.Contains(t, result, "No system knowledge found")
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchSystemKnowledge_DefaultTopK(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return([]knowledge.Result{}, nil)
	// Second call: system check when empty results
	mockStore.On("Search", mock.Anything, "system", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	_, err := handler.SearchSystemKnowledge(ctx, "test", 0) // topK = 0 should default to 3

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchSystemKnowledge_TopKClamping(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return([]knowledge.Result{}, nil)
	// Second call: system check when empty results
	mockStore.On("Search", mock.Anything, "system", mock.Anything).Return([]knowledge.Result{}, nil)

	ctx := createTestToolContext()
	_, err := handler.SearchSystemKnowledge(ctx, "test", 12) // topK = 12 should clamp to 10

	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchSystemKnowledge_StoreError(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return(nil, fmt.Errorf("system knowledge not indexed"))

	ctx := createTestToolContext()
	result, err := handler.SearchSystemKnowledge(ctx, "test", 3)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "system knowledge search failed")
	assert.Empty(t, result)
	mockStore.AssertExpectations(t)
}

func TestHandler_SearchSystemKnowledge_NoTruncation(t *testing.T) {
	mockStore := new(MockKnowledgeStore)
	handler := &Handler{knowledgeStore: mockStore}

	// System knowledge should NOT truncate content (important guidance)
	longContent := strings.Repeat("This is important system knowledge. ", 30) // ~1080 chars
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				ID:      "sys-long",
				Content: longContent,
				Metadata: map[string]string{
					"source_type":    "system",
					"knowledge_type": "style_guide",
					"topic":          "testing",
				},
				CreateAt: time.Now(),
			},
			Similarity: 0.93,
		},
	}

	mockStore.On("Search", mock.Anything, "test", mock.Anything).Return(results, nil)

	ctx := createTestToolContext()
	result, err := handler.SearchSystemKnowledge(ctx, "test", 3)

	assert.NoError(t, err)
	assert.NotContains(t, result, "Content truncated") // System knowledge NOT truncated
	assert.Contains(t, result, longContent)            // Full content present
	mockStore.AssertExpectations(t)
}

// =============================================================================
// Formatting Function Tests
// =============================================================================

func TestFormatHistoryResults_Empty(t *testing.T) {
	result := formatHistoryResults([]knowledge.Result{})
	assert.Equal(t, "No relevant conversations found.", result)
}

func TestFormatHistoryResults_Success(t *testing.T) {
	results := createConversationResults()
	formatted := formatHistoryResults(results)

	assert.Contains(t, formatted, "Found 2 relevant conversation")
	assert.Contains(t, formatted, "92.0% match")
	assert.Contains(t, formatted, "85.0% match")
	assert.Contains(t, formatted, "Session: session-123")
	assert.Contains(t, formatted, "Turn: 1")
	assert.Contains(t, formatted, "Turn: 2")
	assert.Contains(t, formatted, "Tools used: 0")
	assert.Contains(t, formatted, "Tools used: 1")
}

func TestFormatHistoryResults_TimestampParsing(t *testing.T) {
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				Content: "Test conversation",
				Metadata: map[string]string{
					"source_type": "conversation",
					"timestamp":   "2025-11-18T10:00:00Z",
				},
			},
			Similarity: 0.9,
		},
	}

	formatted := formatHistoryResults(results)
	assert.Contains(t, formatted, "Time: 2025-11-18 10:00:00")
}

func TestFormatDocumentResults_Empty(t *testing.T) {
	result := formatDocumentResults([]knowledge.Result{})
	assert.Equal(t, "No relevant documents found in your knowledge base.", result)
}

func TestFormatDocumentResults_Success(t *testing.T) {
	results := createDocumentResults()
	formatted := formatDocumentResults(results)

	assert.Contains(t, formatted, "Found 1 relevant document")
	assert.Contains(t, formatted, "88.0% relevance")
	assert.Contains(t, formatted, "Location: /project/main.go")
	assert.Contains(t, formatted, "Source: main.go")
	assert.Contains(t, formatted, "Content Start")
	assert.Contains(t, formatted, "Content End")
}

func TestFormatDocumentResults_MinimalMetadata(t *testing.T) {
	// Test that new format only shows essential metadata (no indexed_at, file_size, etc.)
	results := []knowledge.Result{
		{
			Document: knowledge.Document{
				Content: "Test document",
				Metadata: map[string]string{
					"source_type": "file",
					"indexed_at":  "2025-11-18T09:00:00Z",
				},
			},
			Similarity: 0.85,
		},
	}

	formatted := formatDocumentResults(results)
	// New format does NOT include indexed_at timestamp or other non-essential metadata
	assert.NotContains(t, formatted, "Indexed:")
	assert.Contains(t, formatted, "85.0% relevance")
	assert.Contains(t, formatted, "Content Start")
}

func TestFormatSystemResults_Empty(t *testing.T) {
	result := formatSystemResults([]knowledge.Result{})
	assert.Equal(t, "No relevant system knowledge found.", result)
}

func TestFormatSystemResults_Success(t *testing.T) {
	results := createSystemResults()
	formatted := formatSystemResults(results)

	assert.Contains(t, formatted, "Found 1 relevant system knowledge")
	assert.Contains(t, formatted, "95.0% match")
	assert.Contains(t, formatted, "Type: style_guide")
	assert.Contains(t, formatted, "Topic: error_handling")
	assert.Contains(t, formatted, "Version: 1.0")
}

func TestTruncateContent_ShortContent(t *testing.T) {
	content := "Short content"
	result := truncateContent(content, 100)
	assert.Equal(t, content, result)
}

func TestTruncateContent_LongContent(t *testing.T) {
	content := strings.Repeat("a", 600)
	result := truncateContent(content, 500)

	// New truncation message: "...\n[Content truncated for length - key information should be in the excerpt above]"
	expectedSuffix := "...\n[Content truncated for length - key information should be in the excerpt above]"
	assert.Equal(t, 500+len(expectedSuffix), len(result))
	assert.Contains(t, result, "Content truncated")
}
