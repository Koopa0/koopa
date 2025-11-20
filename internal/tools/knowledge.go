package tools

// knowledge.go defines knowledge search tools for semantic retrieval.
//
// Provides 3 knowledge tools: searchHistory, searchDocuments, searchSystemKnowledge.
// Each tool searches a specific knowledge source with metadata filtering.
//
// Architecture: Genkit closures act as thin adapters that convert JSON input
// to Handler method calls. Business logic lives in testable Handler methods.
// Formatting logic uses package-level pure functions for better testability.

import (
	"fmt"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
)

// registerKnowledgeTools registers knowledge search tools with Genkit.
// handler contains all business logic for knowledge operations.
func registerKnowledgeTools(g *genkit.Genkit, handler *Handler) {
	defineSearchHistory(g, handler)
	defineSearchDocuments(g, handler)
	defineSearchSystemKnowledge(g, handler)
}

// defineSearchHistory defines the searchHistory tool for conversation search.
func defineSearchHistory(g *genkit.Genkit, handler *Handler) {
	genkit.DefineTool(
		g,
		"searchHistory",
		"Search conversation history to find previous discussions, topics, or context from past interactions. "+
			"Use this to recall what the user said before, find previous answers you gave, or understand context from earlier in the conversation. "+
			"This searches ONLY conversation history (user messages, assistant responses, and tool calls). "+
			"Returns relevant conversation snippets with similarity scores and metadata (session ID, timestamp, turn number). "+
			"Useful for: recalling user preferences, finding previous answers, understanding conversation context, tracking topic evolution. "+
			"Example queries: 'what programming languages did the user mention?', 'what did I say about error handling?', 'previous discussion about databases'",
		func(ctx *ai.ToolContext, input struct {
			Query string `json:"query" jsonschema_description:"Search query to find relevant conversations. Use natural language to describe what you're looking for. Examples: 'user's favorite programming language', 'discussion about testing', 'what frameworks were mentioned'"`
			TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum number of results to return (1-10). Default: 3. Use higher values (5-10) for broad exploration, lower values (1-3) for focused queries."`
		}) (string, error) {
			return handler.SearchHistory(ctx, input.Query, input.TopK)
		},
	)
}

// defineSearchDocuments defines the searchDocuments tool for document search.
func defineSearchDocuments(g *genkit.Genkit, handler *Handler) {
	genkit.DefineTool(
		g,
		"searchDocuments",
		"Search indexed documents and files to find relevant information from the user's knowledge base. "+
			"Use this to find information from documentation, source code, notes, or any files the user has indexed. "+
			"This searches ONLY indexed documents (files added via /rag commands). "+
			"Returns relevant document snippets with similarity scores and metadata (file path, file name, file type). "+
			"Useful for: answering questions about the codebase, finding API documentation, locating configuration details, searching project notes. "+
			"Example queries: 'how to configure database connection?', 'API endpoint for user authentication', 'error handling best practices in this project'",
		func(ctx *ai.ToolContext, input struct {
			Query string `json:"query" jsonschema_description:"Search query to find relevant documents. Use natural language or technical terms. Examples: 'database configuration', 'authentication implementation', 'error handling patterns', 'API documentation'"`
			TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum number of results to return (1-10). Default: 3. Use higher values (5-10) for comprehensive search, lower values (1-3) for specific lookups."`
		}) (string, error) {
			return handler.SearchDocuments(ctx, input.Query, input.TopK)
		},
	)
}

// defineSearchSystemKnowledge defines the searchSystemKnowledge tool for system knowledge search.
func defineSearchSystemKnowledge(g *genkit.Genkit, handler *Handler) {
	genkit.DefineTool(
		g,
		"searchSystemKnowledge",
		"Search system knowledge base to find best practices, style guides, coding standards, and framework-specific guidance. "+
			"Use this to understand how to write code correctly in this project, follow established patterns, or look up system capabilities. "+
			"This searches ONLY system knowledge (style guides, best practices, capability documentation, framework guides). "+
			"Returns relevant guidance with similarity scores and metadata (knowledge type, topic, version). "+
			"Useful for: following code style conventions, understanding project architecture patterns, learning framework best practices, checking system capabilities. "+
			"Example queries: 'error handling style guide', 'how to structure Go packages?', 'testing best practices', 'what tools are available?'",
		func(ctx *ai.ToolContext, input struct {
			Query string `json:"query" jsonschema_description:"Search query to find relevant system knowledge. Use natural language to describe what guidance you need. Examples: 'error handling conventions', 'package structure guidelines', 'testing patterns', 'available capabilities'"`
			TopK  int32  `json:"topK,omitempty" jsonschema_description:"Maximum number of results to return (1-10). Default: 3. Use higher values (5-10) for comprehensive guidance, lower values (1-3) for specific rules."`
		}) (string, error) {
			return handler.SearchSystemKnowledge(ctx, input.Query, input.TopK)
		},
	)
}

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
	output.WriteString(fmt.Sprintf("📚 Found %d relevant document(s) from your knowledge base:\n\n", len(results)))

	for i, result := range results {
		// Clear header emphasizing this is FROM USER'S KNOWLEDGE BASE
		output.WriteString(fmt.Sprintf("━━━ 📄 Retrieved Document %d (%.1f%% relevance) ━━━\n", i+1, result.Similarity*100))

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
