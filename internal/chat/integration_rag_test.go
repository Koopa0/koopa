//go:build integration
// +build integration

package chat_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/rag"
)

// TestChatAgent_RAGIntegration_EndToEnd verifies the complete RAG workflow:
// 1. Index document into knowledge store
// 2. Query triggers retrieval
// 3. Verify LLM response uses retrieved context
//
// Per Proposal 030: topK > 0 with real retriever, verify documents returned
// and integrated into prompt.
func TestChatAgent_RAGIntegration_EndToEnd(t *testing.T) {
	framework := SetupTest(t)
	ctx := context.Background()

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
	resp, err := framework.Agent.ExecuteStream(ctx, framework.SessionID,
		"What is the secret password from the test document?",
		nil,
	)

	if err != nil {
		t.Fatalf("ExecuteStream() with RAG unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("ExecuteStream() response is nil, want non-nil when error is nil")
	}
	if resp.FinalText == "" {
		t.Error("ExecuteStream() response.FinalText is empty, want non-empty")
	}

	// STEP 3: Verify LLM response uses retrieved context
	if !strings.Contains(resp.FinalText, "KOOPA_TEST_123") {
		t.Errorf("ExecuteStream() response = %q, want to contain %q (from retrieved document)", resp.FinalText, "KOOPA_TEST_123")
	}
	t.Logf("RAG response: %s", resp.FinalText)
}

// TestRetrieveRAGContext_ActualRetrieval verifies that RAG retrieval
// returns documents when topK > 0.
// Per Proposal 030: Verify documents returned and integrated into prompt.
func TestRetrieveRAGContext_ActualRetrieval(t *testing.T) {
	framework := SetupTest(t)
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
	resp, err := framework.Agent.ExecuteStream(ctx, framework.SessionID,
		"Tell me about Go programming language",
		nil,
	)

	if err != nil {
		t.Fatalf("ExecuteStream() unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("ExecuteStream() response is nil, want non-nil when error is nil")
	}
	if resp.FinalText == "" {
		t.Error("ExecuteStream() response.FinalText is empty, want non-empty")
	}

	// Response should incorporate retrieved knowledge
	// (Exact matching is LLM-dependent, but it should reference Go)
	if !strings.Contains(resp.FinalText, "Go") {
		t.Errorf("ExecuteStream() response = %q, want to contain %q (from retrieved documents)", resp.FinalText, "Go")
	}
	t.Logf("Response with RAG: %s", resp.FinalText)
}

// TestRetrieveRAGContext_EmptyKnowledgeBase verifies graceful handling
// when knowledge base has no matching documents.
func TestRetrieveRAGContext_EmptyKnowledgeBase(t *testing.T) {
	framework := SetupTest(t)
	ctx := context.Background()

	// Query with empty knowledge base (no documents indexed)
	resp, err := framework.Agent.ExecuteStream(ctx, framework.SessionID,
		"What is in the knowledge base?",
		nil,
	)

	if err != nil {
		t.Fatalf("ExecuteStream() with empty knowledge base unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("ExecuteStream() response is nil, want non-nil when error is nil")
	}
	if resp.FinalText == "" {
		t.Error("ExecuteStream() response.FinalText is empty, want non-empty")
	}
	t.Logf("Response with empty knowledge base: %s", resp.FinalText)
}

// TestRetrieveRAGContext_MultipleRelevantDocuments verifies that when multiple
// documents match the query, the RAG system retrieves and uses them.
func TestRetrieveRAGContext_MultipleRelevantDocuments(t *testing.T) {
	framework := SetupTest(t)
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
	resp, err := framework.Agent.ExecuteStream(ctx, framework.SessionID,
		"Summarize the key features of Go programming language",
		nil,
	)

	if err != nil {
		t.Fatalf("ExecuteStream() unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("ExecuteStream() response is nil, want non-nil when error is nil")
	}
	if resp.FinalText == "" {
		t.Error("ExecuteStream() response.FinalText is empty, want non-empty")
	}

	// Response should mention multiple aspects from different retrieved documents.
	// We use substring matching with synonym alternatives (e.g., "concurrent" OR "goroutine")
	// rather than semantic similarity to keep the test simple and dependency-free.
	// Known limitation: LLM paraphrasing may occasionally miss all synonyms; this is an
	// acceptable trade-off for an integration test focused on retrieval behavior, not output quality.
	response := strings.ToLower(resp.FinalText)
	hasMultipleAspects := (strings.Contains(response, "concurrent") || strings.Contains(response, "goroutine")) &&
		(strings.Contains(response, "simple") || strings.Contains(response, "readab")) &&
		(strings.Contains(response, "compile") || strings.Contains(response, "fast"))

	if !hasMultipleAspects {
		t.Errorf("ExecuteStream() response = %q, want to incorporate multiple aspects from retrieved documents", resp.FinalText)
	}

	t.Logf("Response with multiple docs: %s", resp.FinalText)
}
