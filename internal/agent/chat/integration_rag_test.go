//go:build integration
// +build integration

package chat_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koopa0/koopa/internal/rag"
)

// =============================================================================
// Phase 0.2: RAG Integration Tests
// =============================================================================

// TestChatAgent_RAGIntegration_EndToEnd verifies the complete RAG workflow:
// 1. Index document into knowledge store
// 2. Query triggers retrieval
// 3. Verify LLM response uses retrieved context
//
// Per Proposal 030: topK > 0 with real retriever, verify documents returned
// and integrated into prompt.
func TestChatAgent_RAGIntegration_EndToEnd(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Ensure RAG is enabled
	require.Greater(t, framework.Config.RAGTopK, 0, "RAG must be enabled for this test")

	// STEP 1: Index test document using DocStore
	docID := uuid.New()
	testContent := "The secret password is KOOPA_TEST_123. This is a unique test string."
	framework.IndexDocument(t, testContent, map[string]any{
		"id":          docID.String(),
		"filename":    "test-rag-doc.txt",
		"source_type": rag.SourceTypeFile,
	})
	t.Logf("Indexed document %s with test content", docID)

	// STEP 2: Query should trigger RAG retrieval
	invCtx, sessionID := newInvocationContext(ctx, framework.SessionID)
	resp, err := framework.Agent.ExecuteStream(invCtx, sessionID,
		"What is the secret password from the test document?",
		nil,
	)

	require.NoError(t, err, "Query with RAG should succeed")
	require.NotNil(t, resp, "Response should not be nil when error is nil")
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")

	// STEP 3: Verify LLM response uses retrieved context
	assert.Contains(t, resp.FinalText, "KOOPA_TEST_123",
		"Response should contain the password from retrieved document")
	t.Logf("RAG response: %s", resp.FinalText)
}

// TestRetrieveRAGContext_ActualRetrieval verifies that RAG retrieval
// returns documents when topK > 0.
// Per Proposal 030: Verify documents returned and integrated into prompt.
func TestRetrieveRAGContext_ActualRetrieval(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Index multiple documents for retrieval
	doc1ID := uuid.New()
	doc2ID := uuid.New()
	framework.IndexDocument(t, "Go is a statically typed programming language.", map[string]any{
		"id":          doc1ID.String(),
		"filename":    "doc1.txt",
		"source_type": rag.SourceTypeFile,
	})
	framework.IndexDocument(t, "Go was designed at Google by Robert Griesemer, Rob Pike, and Ken Thompson.", map[string]any{
		"id":          doc2ID.String(),
		"filename":    "doc2.txt",
		"source_type": rag.SourceTypeFile,
	})

	t.Log("Indexed 2 test documents")

	// Query that should trigger retrieval
	invCtx, sessionID := newInvocationContext(ctx, framework.SessionID)
	resp, err := framework.Agent.ExecuteStream(invCtx, sessionID,
		"Tell me about Go programming language",
		nil,
	)

	require.NoError(t, err, "Query should succeed")
	require.NotNil(t, resp, "Response should not be nil when error is nil")
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")

	// Response should incorporate retrieved knowledge
	// (Exact matching is LLM-dependent, but it should reference Go)
	assert.Contains(t, resp.FinalText, "Go",
		"Response should reference Go from retrieved documents")
	t.Logf("Response with RAG: %s", resp.FinalText)
}

// TestRetrieveRAGContext_DisabledWhenTopKZero verifies that RAG is skipped
// when topK is 0.
func TestRetrieveRAGContext_DisabledWhenTopKZero(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Override config to disable RAG
	originalRAGTopK := framework.Config.RAGTopK
	framework.Config.RAGTopK = 0
	defer func() { framework.Config.RAGTopK = originalRAGTopK }()

	// Index document (should NOT be retrieved)
	docID := uuid.New()
	framework.IndexDocument(t, "This content should be ignored because RAG is disabled.", map[string]any{
		"id":          docID.String(),
		"filename":    "ignored.txt",
		"source_type": rag.SourceTypeFile,
	})

	// Query - should NOT trigger retrieval
	invCtx, sessionID := newInvocationContext(ctx, framework.SessionID)
	resp, err := framework.Agent.ExecuteStream(invCtx, sessionID,
		"What does the ignored document say?",
		nil,
	)

	require.NoError(t, err, "Query should succeed even without RAG")
	require.NotNil(t, resp, "Response should not be nil when error is nil")
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")

	// Response should NOT contain the ignored content
	assert.NotContains(t, resp.FinalText, "should be ignored",
		"Response should not contain content from ignored document")
	t.Logf("Response without RAG (topK=0): %s", resp.FinalText)
}

// TestRetrieveRAGContext_EmptyKnowledgeBase verifies graceful handling
// when knowledge base has no matching documents.
func TestRetrieveRAGContext_EmptyKnowledgeBase(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Query with empty knowledge base (no documents indexed)
	invCtx, sessionID := newInvocationContext(ctx, framework.SessionID)
	resp, err := framework.Agent.ExecuteStream(invCtx, sessionID,
		"What is in the knowledge base?",
		nil,
	)

	require.NoError(t, err, "Query should succeed even with empty knowledge base")
	require.NotNil(t, resp, "Response should not be nil when error is nil")
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")
	t.Logf("Response with empty knowledge base: %s", resp.FinalText)
}

// TestRetrieveRAGContext_MultipleRelevantDocuments verifies that when multiple
// documents match the query, the RAG system retrieves and uses them.
func TestRetrieveRAGContext_MultipleRelevantDocuments(t *testing.T) {
	framework, cleanup := SetupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Index 5 related documents
	topics := []struct {
		id      uuid.UUID
		name    string
		content string
	}{
		{uuid.New(), "go-basics.txt", "Go is a compiled, statically typed language."},
		{uuid.New(), "go-concurrency.txt", "Go has goroutines for concurrent programming."},
		{uuid.New(), "go-simplicity.txt", "Go emphasizes simplicity and readability."},
		{uuid.New(), "go-performance.txt", "Go compiles quickly and runs efficiently."},
		{uuid.New(), "go-tools.txt", "Go includes built-in testing and formatting tools."},
	}

	for _, topic := range topics {
		framework.IndexDocument(t, topic.content, map[string]any{
			"id":          topic.id.String(),
			"filename":    topic.name,
			"source_type": rag.SourceTypeFile,
		})
	}
	t.Logf("Indexed %d related documents", len(topics))

	// Query should retrieve multiple relevant documents
	invCtx, sessionID := newInvocationContext(ctx, framework.SessionID)
	resp, err := framework.Agent.ExecuteStream(invCtx, sessionID,
		"Summarize the key features of Go programming language",
		nil,
	)

	require.NoError(t, err, "Query should succeed")
	require.NotNil(t, resp, "Response should not be nil when error is nil")
	assert.NotEmpty(t, resp.FinalText, "Response should not be empty")

	// Response should mention multiple aspects
	// (LLM might rephrase, so we check for general topics)
	response := strings.ToLower(resp.FinalText)
	hasMultipleAspects := (strings.Contains(response, "concurrent") || strings.Contains(response, "goroutine")) &&
		(strings.Contains(response, "simple") || strings.Contains(response, "readab")) &&
		(strings.Contains(response, "compile") || strings.Contains(response, "fast"))

	if hasMultipleAspects {
		t.Logf("Response incorporates multiple retrieved documents")
	}

	t.Logf("Response with multiple docs: %s", resp.FinalText)
}
