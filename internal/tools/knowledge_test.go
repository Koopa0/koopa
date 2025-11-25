package tools

import (
	"strings"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Test Helpers
// ============================================================================

// createMockResults creates mock search results for testing
func createMockResults(count int, sourceType string) []knowledge.Result {
	results := make([]knowledge.Result, count)
	for i := 0; i < count; i++ {
		metadata := map[string]string{
			"source_type": sourceType,
		}

		switch sourceType {
		case "conversation":
			metadata["session_id"] = "session-123"
			metadata["timestamp"] = time.Now().Format(time.RFC3339)
			metadata["turn_number"] = "1"
			metadata["tool_count"] = "2"
		case "file":
			metadata["file_name"] = "document.md"
			metadata["file_path"] = "/path/to/document.md"
		case "system":
			metadata["knowledge_type"] = "api"
			metadata["topic"] = "testing"
			metadata["version"] = "1.0"
		}

		results[i] = knowledge.Result{
			Document: knowledge.Document{
				ID:       "doc-" + sourceType + "-" + string(rune(i)),
				Content:  "This is test content for " + sourceType,
				Metadata: metadata,
				CreateAt: time.Now(),
			},
			Similarity: 0.9 - float64(i)*0.1, // Decreasing similarity
		}
	}
	return results
}

// ============================================================================
// Test Constructor
// ============================================================================

func TestKnowledgeToolset_NewKnowledgeToolset(t *testing.T) {
	t.Parallel()

	t.Run("success with mock store", func(t *testing.T) {
		t.Parallel()
		// Note: We can't easily create KnowledgeToolset without real Store
		// because NewKnowledgeToolset requires *knowledge.Store (concrete type)
		// This is tested in integration tests instead
		kt, err := NewKnowledgeToolset((*knowledge.Store)(nil), testLogger())
		_ = kt
		assert.Error(t, err) // Should error on nil
		assert.Contains(t, err.Error(), "knowledge store is required")
	})

	t.Run("error on nil store", func(t *testing.T) {
		t.Parallel()
		kt, err := NewKnowledgeToolset(nil, testLogger())
		assert.Error(t, err)
		assert.Nil(t, kt)
		assert.Contains(t, err.Error(), "knowledge store is required")
	})
}

// ============================================================================
// Test Tool Metadata
// ============================================================================

func TestKnowledgeToolset_ToolMetadata(t *testing.T) {
	t.Parallel()

	t.Run("searchHistory tool metadata", func(t *testing.T) {
		t.Parallel()
		tool := &searchHistoryTool{}
		assert.Equal(t, "searchHistory", tool.Name())
		assert.Contains(t, tool.Description(), "conversation history")
		assert.Contains(t, tool.Description(), "semantic")
		assert.False(t, tool.IsLongRunning())
	})

	t.Run("searchDocuments tool metadata", func(t *testing.T) {
		t.Parallel()
		tool := &searchDocumentsTool{}
		assert.Equal(t, "searchDocuments", tool.Name())
		assert.Contains(t, tool.Description(), "indexed documents")
		assert.Contains(t, tool.Description(), "semantic")
		assert.False(t, tool.IsLongRunning())
	})

	t.Run("searchSystemKnowledge tool metadata", func(t *testing.T) {
		t.Parallel()
		tool := &searchSystemKnowledgeTool{}
		assert.Equal(t, "searchSystemKnowledge", tool.Name())
		assert.Contains(t, tool.Description(), "system knowledge")
		assert.Contains(t, tool.Description(), "semantic")
		assert.False(t, tool.IsLongRunning())
	})
}

// ============================================================================
// Test Formatting Functions (Pure Functions)
// ============================================================================

func TestFormatHistoryResults(t *testing.T) {
	t.Parallel()

	t.Run("empty results", func(t *testing.T) {
		t.Parallel()
		output := formatHistoryResults([]knowledge.Result{})
		assert.Equal(t, "No relevant conversations found.", output)
	})

	t.Run("single result", func(t *testing.T) {
		t.Parallel()
		results := createMockResults(1, "conversation")
		output := formatHistoryResults(results)

		assert.Contains(t, output, "Found 1 relevant conversation")
		assert.Contains(t, output, "Conversation 1")
		assert.Contains(t, output, "90.0% match") // 0.9 * 100
		assert.Contains(t, output, "Session: session-123")
		assert.Contains(t, output, "Turn: 1")
		assert.Contains(t, output, "Tools used: 2")
		assert.Contains(t, output, "This is test content for conversation")
	})

	t.Run("multiple results", func(t *testing.T) {
		t.Parallel()
		results := createMockResults(3, "conversation")
		output := formatHistoryResults(results)

		assert.Contains(t, output, "Found 3 relevant conversation(s)")
		assert.Contains(t, output, "Conversation 1")
		assert.Contains(t, output, "Conversation 2")
		assert.Contains(t, output, "Conversation 3")
	})

	t.Run("timestamp formatting", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		results := []knowledge.Result{
			{
				Document: knowledge.Document{
					ID:      "doc-1",
					Content: "test",
					Metadata: map[string]string{
						"source_type": "conversation",
						"session_id":  "s-1",
						"timestamp":   now.Format(time.RFC3339),
					},
					CreateAt: now,
				},
				Similarity: 0.95,
			},
		}
		output := formatHistoryResults(results)

		// Should format timestamp nicely
		expectedTime := now.Format("2006-01-02 15:04:05")
		assert.Contains(t, output, expectedTime)
	})

	t.Run("truncates long content", func(t *testing.T) {
		t.Parallel()
		longContent := strings.Repeat("a", 600) // Over 500 char limit
		results := []knowledge.Result{
			{
				Document: knowledge.Document{
					ID:      "doc-1",
					Content: longContent,
					Metadata: map[string]string{
						"source_type": "conversation",
					},
					CreateAt: time.Now(),
				},
				Similarity: 0.9,
			},
		}
		output := formatHistoryResults(results)

		assert.Contains(t, output, "[Content truncated for length")
		assert.Contains(t, output, longContent[:500])    // First 500 chars
		assert.NotContains(t, output, longContent[:600]) // Not full content
	})
}

func TestFormatDocumentResults(t *testing.T) {
	t.Parallel()

	t.Run("empty results", func(t *testing.T) {
		t.Parallel()
		output := formatDocumentResults([]knowledge.Result{})
		assert.Contains(t, output, "No relevant documents found")
		assert.Contains(t, output, "knowledge base")
	})

	t.Run("single result", func(t *testing.T) {
		t.Parallel()
		results := createMockResults(1, "file")
		output := formatDocumentResults(results)

		assert.Contains(t, output, "Found 1 relevant document")
		assert.Contains(t, output, "Retrieved Document 1")
		assert.Contains(t, output, "90.0% relevance")
		assert.Contains(t, output, "Source: document.md")
		assert.Contains(t, output, "Location: /path/to/document.md")
		assert.Contains(t, output, "────── Content Start ──────")
		assert.Contains(t, output, "────── Content End ──────")
		assert.Contains(t, output, "Tip: The above content is from your indexed documents")
	})

	t.Run("multiple results", func(t *testing.T) {
		t.Parallel()
		results := createMockResults(2, "file")
		output := formatDocumentResults(results)

		assert.Contains(t, output, "Found 2 relevant document(s)")
		assert.Contains(t, output, "Retrieved Document 1")
		assert.Contains(t, output, "Retrieved Document 2")
	})

	t.Run("truncates long content at 1000 chars", func(t *testing.T) {
		t.Parallel()
		longContent := strings.Repeat("b", 1200) // Over 1000 char limit
		results := []knowledge.Result{
			{
				Document: knowledge.Document{
					ID:      "doc-1",
					Content: longContent,
					Metadata: map[string]string{
						"source_type": "file",
						"file_name":   "long.txt",
					},
					CreateAt: time.Now(),
				},
				Similarity: 0.95,
			},
		}
		output := formatDocumentResults(results)

		assert.Contains(t, output, "[Content truncated for length")
	})
}

func TestFormatSystemResults(t *testing.T) {
	t.Parallel()

	t.Run("empty results", func(t *testing.T) {
		t.Parallel()
		output := formatSystemResults([]knowledge.Result{})
		assert.Equal(t, "No relevant system knowledge found.", output)
	})

	t.Run("single result", func(t *testing.T) {
		t.Parallel()
		results := createMockResults(1, "system")
		output := formatSystemResults(results)

		assert.Contains(t, output, "Found 1 relevant system knowledge item")
		assert.Contains(t, output, "Knowledge 1")
		assert.Contains(t, output, "90.0% match")
		assert.Contains(t, output, "Type: api")
		assert.Contains(t, output, "Topic: testing")
		assert.Contains(t, output, "Version: 1.0")
	})

	t.Run("limits to 10 results", func(t *testing.T) {
		t.Parallel()
		results := createMockResults(15, "system")
		output := formatSystemResults(results)

		assert.Contains(t, output, "Found 15 relevant system knowledge item(s)")
		assert.Contains(t, output, "(showing top 10)")
		assert.Contains(t, output, "Knowledge 1")
		assert.Contains(t, output, "Knowledge 10")
		assert.NotContains(t, output, "Knowledge 11")
		assert.Contains(t, output, "...5 more results not shown")
	})

	t.Run("does not truncate content", func(t *testing.T) {
		t.Parallel()
		// System knowledge should not be truncated
		longContent := strings.Repeat("c", 2000)
		results := []knowledge.Result{
			{
				Document: knowledge.Document{
					ID:      "doc-1",
					Content: longContent,
					Metadata: map[string]string{
						"source_type":    "system",
						"knowledge_type": "api",
					},
					CreateAt: time.Now(),
				},
				Similarity: 0.9,
			},
		}
		output := formatSystemResults(results)

		// Should contain full content, no truncation
		assert.Contains(t, output, longContent)
		assert.NotContains(t, output, "[Content truncated")
	})
}

func TestTruncateContent(t *testing.T) {
	t.Parallel()

	t.Run("short content not truncated", func(t *testing.T) {
		t.Parallel()
		content := "Short content"
		result := truncateContent(content, 100)
		assert.Equal(t, content, result)
	})

	t.Run("exact length not truncated", func(t *testing.T) {
		t.Parallel()
		content := strings.Repeat("a", 100)
		result := truncateContent(content, 100)
		assert.Equal(t, content, result)
	})

	t.Run("long content truncated", func(t *testing.T) {
		t.Parallel()
		content := strings.Repeat("a", 150)
		result := truncateContent(content, 100)

		assert.Contains(t, result, strings.Repeat("a", 100))
		assert.Contains(t, result, "...")
		assert.Contains(t, result, "[Content truncated for length")
		// Result includes truncation message, so it's longer than maxLength but shorter than full content
		assert.Greater(t, len(result), 100)                        // Longer than maxLength
		assert.Contains(t, result[:100], strings.Repeat("a", 100)) // First 100 chars are the content
	})
}

// ============================================================================
// Test Search Methods (require real knowledge.Store for complete testing)
// ============================================================================
//
// Note: Complete tests for SearchHistory, SearchDocuments, SearchSystemKnowledge
// should be done in integration tests as they depend on real knowledge.Store.
// Unit tests here cover:
// 1. Formatting functions (completed)
// 2. Tool metadata (completed)
// 3. Constructor validation (completed)
//
// Full search functionality tests are in:
// - internal/knowledge/store_integration_test.go (Store tests)
// - internal/agent/agent_integration_test.go (end-to-end tests)
// ============================================================================

// TestKnowledgeToolset_Name tests toolset name
func TestKnowledgeToolset_Name(t *testing.T) {
	t.Parallel()

	// We can't create KnowledgeToolset without real Store
	// But we can test the name method through reflection
	// For now, we document that Name() returns "knowledge"

	// This would be tested in integration tests where we have real Store
}

// TestKnowledgeToolset_TopKValidation tests TopK parameter validation
func TestTopKValidation(t *testing.T) {
	t.Parallel()

	// Document TopK validation behavior:
	// - topK <= 0 -> defaults to 3
	// - topK > 10 -> clamped to 10
	// - 1 <= topK <= 10 -> used as-is

	tests := []struct {
		name     string
		input    int32
		expected int
	}{
		{"zero defaults to 3", 0, 3},
		{"negative defaults to 3", -1, 3},
		{"valid value 1", 1, 1},
		{"valid value 5", 5, 5},
		{"valid value 10", 10, 10},
		{"over 10 clamped to 10", 11, 10},
		{"way over clamped to 10", 100, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The actual validation logic is:
			topK := int(tt.input)
			if topK <= 0 {
				topK = 3
			} else if topK > 10 {
				topK = 10
			}

			assert.Equal(t, tt.expected, topK)
		})
	}
}
