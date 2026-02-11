package tools

// knowledge.go defines knowledge tools for semantic retrieval and storage.
//
// Provides 4 knowledge tools: search_history, search_documents, search_system_knowledge, knowledge_store.
// Search tools query specific knowledge sources with metadata filtering.
// The store tool indexes new documents for later retrieval.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"

	"github.com/koopa0/koopa/internal/rag"
)

// Tool name constants for knowledge operations registered with Genkit.
const (
	// SearchHistoryName is the Genkit tool name for searching conversation history.
	SearchHistoryName = "search_history"
	// SearchDocumentsName is the Genkit tool name for searching indexed documents.
	SearchDocumentsName = "search_documents"
	// SearchSystemKnowledgeName is the Genkit tool name for searching system knowledge.
	SearchSystemKnowledgeName = "search_system_knowledge"
	// StoreKnowledgeName is the Genkit tool name for storing new knowledge documents.
	StoreKnowledgeName = "knowledge_store"
)

// Default TopK values for knowledge searches.
const (
	DefaultHistoryTopK         = 3
	DefaultDocumentsTopK       = 5
	DefaultSystemKnowledgeTopK = 3
	MaxTopK                    = 10
)

// KnowledgeSearchInput defines input for all knowledge search tools.
// The default TopK varies by tool: history=3, documents=5, system=3.
type KnowledgeSearchInput struct {
	Query string `json:"query" jsonschema_description:"The search query string"`
	TopK  int    `json:"topK,omitempty" jsonschema_description:"Maximum results to return (1-10)"`
}

// KnowledgeStoreInput defines input for the knowledge_store tool.
type KnowledgeStoreInput struct {
	Title   string `json:"title" jsonschema_description:"Short title for the knowledge entry"`
	Content string `json:"content" jsonschema_description:"The knowledge content to store"`
}

// Knowledge holds dependencies for knowledge operation handlers.
type Knowledge struct {
	retriever ai.Retriever
	docStore  *postgresql.DocStore // nil disables knowledge_store tool
	logger    *slog.Logger
}

// HasDocStore reports whether the document store is available.
// Used by MCP server to conditionally register the knowledge_store tool.
func (k *Knowledge) HasDocStore() bool {
	return k.docStore != nil
}

// NewKnowledge creates a Knowledge instance.
// docStore is optional: when nil, the knowledge_store tool is not registered.
func NewKnowledge(retriever ai.Retriever, docStore *postgresql.DocStore, logger *slog.Logger) (*Knowledge, error) {
	if retriever == nil {
		return nil, fmt.Errorf("retriever is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &Knowledge{retriever: retriever, docStore: docStore, logger: logger}, nil
}

// RegisterKnowledge registers all knowledge search tools with Genkit.
// Tools are registered with event emission wrappers for streaming support.
func RegisterKnowledge(g *genkit.Genkit, kt *Knowledge) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if kt == nil {
		return nil, fmt.Errorf("Knowledge is required")
	}

	tools := []ai.Tool{
		genkit.DefineTool(g, SearchHistoryName,
			"Search conversation history using semantic similarity. "+
				"Finds past exchanges that are conceptually related to the query. "+
				"Returns: matched conversation turns with timestamps and similarity scores. "+
				"Use this to: recall past discussions, find context from earlier conversations. "+
				"Default topK: 3. Maximum topK: 10.",
			WithEvents(SearchHistoryName, kt.SearchHistory)),
		genkit.DefineTool(g, SearchDocumentsName,
			"Search indexed documents (PDFs, code files, notes) using semantic similarity. "+
				"Finds document sections that are conceptually related to the query. "+
				"Returns: document titles, content excerpts, and similarity scores. "+
				"Use this to: find relevant documentation, locate code examples, research topics. "+
				"Default topK: 5. Maximum topK: 10.",
			WithEvents(SearchDocumentsName, kt.SearchDocuments)),
		genkit.DefineTool(g, SearchSystemKnowledgeName,
			"Search system knowledge base (tool usage, commands, patterns) using semantic similarity. "+
				"Finds internal system documentation and usage patterns. "+
				"Returns: knowledge entries with descriptions and examples. "+
				"Use this to: understand tool capabilities, find command syntax, learn system patterns. "+
				"Default topK: 3. Maximum topK: 10.",
			WithEvents(SearchSystemKnowledgeName, kt.SearchSystemKnowledge)),
	}

	// Register knowledge_store only when DocStore is available.
	if kt.docStore != nil {
		tools = append(tools, genkit.DefineTool(g, StoreKnowledgeName,
			"Store a knowledge entry for later retrieval via search_documents. "+
				"Use this to save important information, notes, or learnings "+
				"that the user wants to remember across sessions. "+
				"Each entry gets a unique ID and is indexed for semantic search.",
			WithEvents(StoreKnowledgeName, kt.StoreKnowledge)))
	}

	return tools, nil
}

// clampTopK validates topK and returns a value within [1, MaxTopK].
// If topK <= 0, returns defaultVal.
func clampTopK(topK, defaultVal int) int {
	if topK <= 0 {
		return defaultVal
	}
	if topK > MaxTopK {
		return MaxTopK
	}
	return topK
}

// validSourceTypes defines the allowed source types for knowledge search.
// This whitelist prevents SQL injection via the source_type filter.
var validSourceTypes = map[string]bool{
	rag.SourceTypeConversation: true,
	rag.SourceTypeFile:         true,
	rag.SourceTypeSystem:       true,
}

// search performs a knowledge search with the given source type filter.
// Returns error if sourceType is not in the allowed whitelist.
func (k *Knowledge) search(ctx context.Context, query string, topK int, sourceType string) ([]*ai.Document, error) {
	// Validate source type against whitelist (SQL injection prevention)
	if !validSourceTypes[sourceType] {
		return nil, fmt.Errorf("invalid source type: %q", sourceType)
	}

	// Build WHERE clause filter for source_type.
	// SECURITY: sourceType is SQL injection-safe because it's validated against
	// a hardcoded whitelist (validSourceTypes). This filter is passed to the
	// Genkit PostgreSQL retriever which includes it in a SQL query.
	// DO NOT bypass the whitelist validation above.
	filter := fmt.Sprintf("source_type = '%s'", sourceType)

	req := &ai.RetrieverRequest{
		Query: ai.DocumentFromText(query, nil),
		Options: &postgresql.RetrieverOptions{
			Filter: filter,
			K:      topK,
		},
	}

	resp, err := k.retriever.Retrieve(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("retrieve %s: %w", sourceType, err)
	}

	return resp.Documents, nil
}

// SearchHistory searches conversation history using semantic similarity.
func (k *Knowledge) SearchHistory(ctx *ai.ToolContext, input KnowledgeSearchInput) (Result, error) {
	k.logger.Info("SearchHistory called", "query", input.Query, "topK", input.TopK)

	topK := clampTopK(input.TopK, DefaultHistoryTopK)

	results, err := k.search(ctx, input.Query, topK, rag.SourceTypeConversation)
	if err != nil {
		k.logger.Error("SearchHistory failed", "query", input.Query, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("searching history: %v", err),
			},
		}, nil
	}

	k.logger.Info("SearchHistory succeeded", "query", input.Query, "result_count", len(results))
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"query":        input.Query,
			"result_count": len(results),
			"results":      results,
		},
	}, nil
}

// SearchDocuments searches indexed documents using semantic similarity.
func (k *Knowledge) SearchDocuments(ctx *ai.ToolContext, input KnowledgeSearchInput) (Result, error) {
	k.logger.Info("SearchDocuments called", "query", input.Query, "topK", input.TopK)

	topK := clampTopK(input.TopK, DefaultDocumentsTopK)

	results, err := k.search(ctx, input.Query, topK, rag.SourceTypeFile)
	if err != nil {
		k.logger.Error("SearchDocuments failed", "query", input.Query, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("searching documents: %v", err),
			},
		}, nil
	}

	k.logger.Info("SearchDocuments succeeded", "query", input.Query, "result_count", len(results))
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"query":        input.Query,
			"result_count": len(results),
			"results":      results,
		},
	}, nil
}

// StoreKnowledge stores a new knowledge document for later retrieval.
func (k *Knowledge) StoreKnowledge(ctx *ai.ToolContext, input KnowledgeStoreInput) (Result, error) {
	k.logger.Info("StoreKnowledge called", "title", input.Title)

	if k.docStore == nil {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: "knowledge store is not available",
			},
		}, nil
	}

	if input.Title == "" {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: "title is required",
			},
		}, nil
	}
	if input.Content == "" {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: "content is required",
			},
		}, nil
	}

	// Generate a deterministic document ID from the title using SHA-256.
	// Changing the title creates a new document; the old entry remains.
	// Prefix "user:" namespaces user-created knowledge (vs "system:" for built-in).
	docID := fmt.Sprintf("user:%x", sha256.Sum256([]byte(input.Title)))

	doc := ai.DocumentFromText(input.Content, map[string]any{
		"id":          docID,
		"source_type": rag.SourceTypeFile,
		"title":       input.Title,
	})

	if err := k.docStore.Index(ctx, []*ai.Document{doc}); err != nil {
		k.logger.Error("StoreKnowledge failed", "title", input.Title, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("storing knowledge: %v", err),
			},
		}, nil
	}

	k.logger.Info("StoreKnowledge succeeded", "title", input.Title)
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"title":   input.Title,
			"message": "Knowledge stored successfully. It can now be found via search_documents.",
		},
	}, nil
}

// SearchSystemKnowledge searches system knowledge base using semantic similarity.
func (k *Knowledge) SearchSystemKnowledge(ctx *ai.ToolContext, input KnowledgeSearchInput) (Result, error) {
	k.logger.Info("SearchSystemKnowledge called", "query", input.Query, "topK", input.TopK)

	topK := clampTopK(input.TopK, DefaultSystemKnowledgeTopK)

	results, err := k.search(ctx, input.Query, topK, rag.SourceTypeSystem)
	if err != nil {
		k.logger.Error("SearchSystemKnowledge failed", "query", input.Query, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("searching system knowledge: %v", err),
			},
		}, nil
	}

	k.logger.Info("SearchSystemKnowledge succeeded", "query", input.Query, "result_count", len(results))
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"query":        input.Query,
			"result_count": len(results),
			"results":      results,
		},
	}, nil
}
