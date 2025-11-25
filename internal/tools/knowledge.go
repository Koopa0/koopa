package tools

// knowledge.go defines knowledge search tools for semantic retrieval.
//
// Provides 3 knowledge tools: searchHistory, searchDocuments, searchSystemKnowledge.
// Each tool searches a specific knowledge source with metadata filtering.
//
// Architecture: Kit methods implement all business logic with knowledge store integration.
// Tools are registered to Genkit via Kit.Register() for use by the Agent.
// Formatting logic uses package-level pure functions for better testability.

import (
	"fmt"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/log"
)

// formatHistoryResults formats conversation search results into a readable string.
// This is a pure function (no side effects) for easier testing.
func formatHistoryResults(results []knowledge.Result) string {
	if len(results) == 0 {
		return "No relevant conversations found."
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Found %d relevant conversation(s):\n\n", len(results)))

	for i, result := range results {
		// Header with similarity score
		output.WriteString(fmt.Sprintf("=== Conversation %d (%.1f%% match) ===\n", i+1, result.Similarity*100))

		// Metadata
		if sessionID, ok := result.Document.Metadata["session_id"]; ok {
			output.WriteString(fmt.Sprintf("Session: %s\n", sessionID))
		}
		if timestamp, ok := result.Document.Metadata["timestamp"]; ok {
			// Try to parse and format timestamp nicely
			if t, err := time.Parse(time.RFC3339, timestamp); err == nil {
				output.WriteString(fmt.Sprintf("Time: %s\n", t.Format("2006-01-02 15:04:05")))
			} else {
				output.WriteString(fmt.Sprintf("Time: %s\n", timestamp))
			}
		}
		if turnNum, ok := result.Document.Metadata["turn_number"]; ok {
			output.WriteString(fmt.Sprintf("Turn: %s\n", turnNum))
		}
		if toolCount, ok := result.Document.Metadata["tool_count"]; ok {
			output.WriteString(fmt.Sprintf("Tools used: %s\n", toolCount))
		}

		// Content (with length limit for readability)
		output.WriteString(fmt.Sprintf("\nContent:\n%s\n\n", truncateContent(result.Document.Content, 500)))
	}

	return output.String()
}

// formatDocumentResults formats document search results into a readable string.
// This is a pure function (no side effects) for easier testing.
// Optimized format: Clear visual boundaries, essential metadata only, emphasis on content.
func formatDocumentResults(results []knowledge.Result) string {
	if len(results) == 0 {
		return "No relevant documents found in your knowledge base."
	}

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Found %d relevant document(s) from your knowledge base:\n\n", len(results)))

	for i, result := range results {
		// Clear header with document information
		output.WriteString(fmt.Sprintf("--- Retrieved Document %d (%.1f%% relevance) ---\n", i+1, result.Similarity*100))

		// Essential metadata only (file name and path for reference)
		if fileName, ok := result.Document.Metadata["file_name"]; ok {
			output.WriteString(fmt.Sprintf("Source: %s\n", fileName))
		}
		if filePath, ok := result.Document.Metadata["file_path"]; ok {
			output.WriteString(fmt.Sprintf("Location: %s\n", filePath))
		}

		// Clear content boundaries with visual separators
		output.WriteString("\n────── Content Start ──────\n")
		// Increased truncation limit to 1000 characters for better context
		output.WriteString(truncateContent(result.Document.Content, 1000))
		output.WriteString("\n────── Content End ──────\n\n")
	}

	output.WriteString("Tip: The above content is from your indexed documents. Use this information to answer the question.\n")

	return output.String()
}

// formatSystemResults formats system knowledge search results into a readable string.
// This is a pure function (no side effects) for easier testing.
func formatSystemResults(results []knowledge.Result) string {
	if len(results) == 0 {
		return "No relevant system knowledge found."
	}

	const maxResults = 10 // Limit to prevent excessively long output

	var output strings.Builder
	resultCount := len(results)
	displayCount := resultCount
	if displayCount > maxResults {
		displayCount = maxResults
	}

	output.WriteString(fmt.Sprintf("Found %d relevant system knowledge item(s)", resultCount))
	if resultCount > maxResults {
		output.WriteString(fmt.Sprintf(" (showing top %d):\n\n", maxResults))
	} else {
		output.WriteString(":\n\n")
	}

	for i := 0; i < displayCount; i++ {
		result := results[i]
		// Header with similarity score
		output.WriteString(fmt.Sprintf("=== Knowledge %d (%.1f%% match) ===\n", i+1, result.Similarity*100))

		// Metadata
		if knowledgeType, ok := result.Document.Metadata["knowledge_type"]; ok {
			output.WriteString(fmt.Sprintf("Type: %s\n", knowledgeType))
		}
		if topic, ok := result.Document.Metadata["topic"]; ok {
			output.WriteString(fmt.Sprintf("Topic: %s\n", topic))
		}
		if version, ok := result.Document.Metadata["version"]; ok {
			output.WriteString(fmt.Sprintf("Version: %s\n", version))
		}

		// Content (no length limit for system knowledge - usually concise and important)
		output.WriteString(fmt.Sprintf("\nContent:\n%s\n\n", result.Document.Content))
	}

	if resultCount > maxResults {
		output.WriteString(fmt.Sprintf("...%d more results not shown (use more specific query to narrow results)\n", resultCount-maxResults))
	}

	return output.String()
}

// truncateContent truncates content to maxLength characters, adding "..." if truncated.
// This is a helper function to keep output readable.
func truncateContent(content string, maxLength int) string {
	if len(content) <= maxLength {
		return content
	}
	return content[:maxLength] + "...\n[Content truncated for length - key information should be in the excerpt above]"
}

// ============================================================================
// Tool Metadata Implementations
// ============================================================================

type searchHistoryTool struct{}

func (t *searchHistoryTool) Name() string { return "searchHistory" }
func (t *searchHistoryTool) Description() string {
	return "Search conversation history using semantic similarity."
}
func (t *searchHistoryTool) IsLongRunning() bool { return false }

type searchDocumentsTool struct{}

func (t *searchDocumentsTool) Name() string { return "searchDocuments" }
func (t *searchDocumentsTool) Description() string {
	return "Search indexed documents using semantic similarity."
}
func (t *searchDocumentsTool) IsLongRunning() bool { return false }

type searchSystemKnowledgeTool struct{}

func (t *searchSystemKnowledgeTool) Name() string { return "searchSystemKnowledge" }
func (t *searchSystemKnowledgeTool) Description() string {
	return "Search system knowledge base using semantic similarity."
}
func (t *searchSystemKnowledgeTool) IsLongRunning() bool { return false }

// ============================================================================
// KnowledgeToolset Implementation
// ============================================================================

// KnowledgeToolsetName is the toolset identifier constant.
const KnowledgeToolsetName = "knowledge"

// SearchHistoryInput defines input for searchHistory tool.
type SearchHistoryInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10, default: 3)"`
}

// SearchDocumentsInput defines input for searchDocuments tool.
type SearchDocumentsInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10, default: 5)"`
}

// SearchSystemKnowledgeInput defines input for searchSystemKnowledge tool.
type SearchSystemKnowledgeInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10, default: 3)"`
}

// KnowledgeToolset implements the Toolset interface for knowledge retrieval tools.
type KnowledgeToolset struct {
	store  *knowledge.Store
	logger log.Logger
}

// NewKnowledgeToolset creates a new KnowledgeToolset.
// Logger is required for debugging and troubleshooting
func NewKnowledgeToolset(store *knowledge.Store, logger log.Logger) (*KnowledgeToolset, error) {
	if store == nil {
		return nil, fmt.Errorf("knowledge store is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &KnowledgeToolset{
		store:  store,
		logger: logger,
	}, nil
}

// Name returns the name of the toolset.
func (k *KnowledgeToolset) Name() string {
	return KnowledgeToolsetName
}

// Tools returns the tool definitions for the KnowledgeToolset.
func (k *KnowledgeToolset) Tools(ctx agent.ReadonlyContext) ([]Tool, error) {
	return []Tool{
		NewTool(
			"searchHistory",
			"Search conversation history using semantic similarity.",
			false,
			k.SearchHistory,
		),
		NewTool(
			"searchDocuments",
			"Search indexed documents using semantic similarity.",
			false,
			k.SearchDocuments,
		),
		NewTool(
			"searchSystemKnowledge",
			"Search system knowledge base using semantic similarity.",
			false,
			k.SearchSystemKnowledge,
		),
	}, nil
}

// SearchHistory searches conversation history using semantic similarity.
func (k *KnowledgeToolset) SearchHistory(ctx *ai.ToolContext, input SearchHistoryInput) (Result, error) {
	k.logger.Info("SearchHistory called", "query", input.Query, "topK", input.TopK)

	// Validate and set defaults for topK
	topK := input.TopK
	if topK <= 0 {
		topK = 3
	} else if topK > 10 {
		topK = 10
	}

	// Build search options with conversation filter
	opts := []knowledge.SearchOption{
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", knowledge.SourceTypeConversation),
	}

	// Execute search
	results, err := k.store.Search(ctx, input.Query, opts...)
	if err != nil {
		k.logger.Error("SearchHistory failed", "query", input.Query, "error", err)
		return Result{
			Status:  StatusError,
			Message: "History search failed",
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("history search failed: %v", err),
			},
		}, nil
	}

	// Format results
	formatted := formatHistoryResults(results)

	k.logger.Info("SearchHistory succeeded", "query", input.Query, "result_count", len(results))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully searched history for: %s", input.Query),
		Data: map[string]any{
			"query":        input.Query,
			"result_count": len(results),
			"results":      results,
			"formatted":    formatted,
		},
	}, nil
}

// SearchDocuments searches indexed documents using semantic similarity.
func (k *KnowledgeToolset) SearchDocuments(ctx *ai.ToolContext, input SearchDocumentsInput) (Result, error) {
	k.logger.Info("SearchDocuments called", "query", input.Query, "topK", input.TopK)

	// Validate and set defaults for topK
	topK := input.TopK
	if topK <= 0 {
		topK = 3
	} else if topK > 10 {
		topK = 10
	}

	// Build search options with file filter
	opts := []knowledge.SearchOption{
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", knowledge.SourceTypeFile),
	}

	// Execute search
	results, err := k.store.Search(ctx, input.Query, opts...)
	if err != nil {
		k.logger.Error("SearchDocuments failed", "query", input.Query, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Document search failed",
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("document search failed: %v", err),
			},
		}, nil
	}

	// Format results
	formatted := formatDocumentResults(results)

	k.logger.Info("SearchDocuments succeeded", "query", input.Query, "result_count", len(results))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully searched documents for: %s", input.Query),
		Data: map[string]any{
			"query":        input.Query,
			"result_count": len(results),
			"results":      results,
			"formatted":    formatted,
		},
	}, nil
}

// SearchSystemKnowledge searches system knowledge base using semantic similarity.
func (k *KnowledgeToolset) SearchSystemKnowledge(ctx *ai.ToolContext, input SearchSystemKnowledgeInput) (Result, error) {
	k.logger.Info("SearchSystemKnowledge called", "query", input.Query, "topK", input.TopK)

	// Validate and set defaults for topK
	topK := input.TopK
	if topK <= 0 {
		topK = 3
	} else if topK > 10 {
		topK = 10
	}

	// Build search options with system filter
	opts := []knowledge.SearchOption{
		knowledge.WithTopK(topK),
		knowledge.WithFilter("source_type", knowledge.SourceTypeSystem),
	}

	// Execute search
	results, err := k.store.Search(ctx, input.Query, opts...)
	if err != nil {
		k.logger.Error("SearchSystemKnowledge failed", "query", input.Query, "error", err)
		return Result{
			Status:  StatusError,
			Message: "System knowledge search failed",
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("system knowledge search failed: %v", err),
			},
		}, nil
	}

	// UX Improvement: Check if system knowledge is indexed when results are empty
	if len(results) == 0 {
		// Use larger TopK to check if ANY system knowledge exists
		checkOpts := []knowledge.SearchOption{
			knowledge.WithTopK(10),
			knowledge.WithFilter("source_type", knowledge.SourceTypeSystem),
		}
		allSystemDocs, checkErr := k.store.Search(ctx, knowledge.SourceTypeSystem, checkOpts...)

		// Provide feedback if the check itself failed
		if checkErr != nil {
			k.logger.Warn("SearchSystemKnowledge check failed", "error", checkErr)
			return Result{
				Status:  StatusSuccess,
				Message: "No system knowledge found (check failed)",
				Data: map[string]any{
					"query":        input.Query,
					"result_count": 0,
					"results":      []knowledge.Result{},
					"formatted": "Unable to check system knowledge status: " + checkErr.Error() + ". " +
						"System knowledge search may be experiencing issues. " +
						"You can try reindexing using `/rag reindex-system` command.",
				},
			}, nil
		}

		// If no system documents found at all, warn the user
		if len(allSystemDocs) == 0 {
			k.logger.Warn("SearchSystemKnowledge no system knowledge indexed")
			return Result{
				Status:  StatusSuccess,
				Message: "No system knowledge found (not indexed)",
				Data: map[string]any{
					"query":        input.Query,
					"result_count": 0,
					"results":      []knowledge.Result{},
					"formatted": "No system knowledge found. System knowledge may not be indexed yet. " +
						"This could happen if the application just started or if indexing failed. " +
						"You can manually reindex using `/rag reindex-system` command.",
				},
			}, nil
		}
	}

	// Format results
	formatted := formatSystemResults(results)

	k.logger.Info("SearchSystemKnowledge succeeded", "query", input.Query, "result_count", len(results))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully searched system knowledge for: %s", input.Query),
		Data: map[string]any{
			"query":        input.Query,
			"result_count": len(results),
			"results":      results,
			"formatted":    formatted,
		},
	}, nil
}
