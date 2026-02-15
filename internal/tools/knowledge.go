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
	"github.com/google/uuid"

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

// MaxKnowledgeContentSize is the maximum allowed content size for knowledge_store (10KB).
// Prevents DoS via large document ingestion and embedding computation.
const MaxKnowledgeContentSize = 10_000

// MaxKnowledgeTitleLength is the maximum allowed title length for knowledge_store.
const MaxKnowledgeTitleLength = 500

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

// sourceTypeFilters maps validated source types to pre-computed SQL filter strings.
// This eliminates string interpolation in the query path (defense-in-depth for CWE-89).
// The whitelist check (validSourceTypes) remains as the primary gate; this map ensures
// no fmt.Sprintf is ever called with user-influenced values in the SQL filter path.
var sourceTypeFilters = map[string]string{
	rag.SourceTypeConversation: "source_type = 'conversation'",
	rag.SourceTypeFile:         "source_type = 'file'",
	rag.SourceTypeSystem:       "source_type = 'system'",
}

// ownerFilter composes a SQL WHERE clause with source_type and optional owner_id filtering.
// When ownerID is empty, only source_type filtering is applied.
// When ownerID is valid, includes documents owned by the user OR legacy documents (NULL owner_id).
//
// SECURITY: ownerID is validated as UUID via uuid.Parse before interpolation.
// UUID format guarantees only [0-9a-f-] characters reach the SQL filter,
// preventing SQL injection via the owner_id parameter (CWE-89 defense-in-depth).
func ownerFilter(sourceType, ownerID string) (string, error) {
	base, ok := sourceTypeFilters[sourceType]
	if !ok {
		return "", fmt.Errorf("invalid source type: %q", sourceType)
	}
	if ownerID == "" {
		return base, nil
	}
	// Validate UUID format — only allows [0-9a-f-] characters.
	if _, err := uuid.Parse(ownerID); err != nil {
		return "", fmt.Errorf("invalid owner ID format: %w", err)
	}
	return base + " AND (owner_id = '" + ownerID + "' OR owner_id IS NULL)", nil
}

// search performs a knowledge search with the given source type filter.
// Returns error if sourceType is not in the allowed whitelist.
// When owner ID is present in context, filters results to the owner's documents
// and legacy documents (NULL owner_id) for RAG poisoning prevention.
func (k *Knowledge) search(ctx context.Context, query string, topK int, sourceType string) ([]*ai.Document, error) {
	// Validate source type against whitelist (SQL injection prevention)
	if !validSourceTypes[sourceType] {
		return nil, fmt.Errorf("invalid source type: %q", sourceType)
	}

	// Compose filter with optional owner isolation.
	ownerID := OwnerIDFromContext(ctx)
	filter, err := ownerFilter(sourceType, ownerID)
	if err != nil {
		return nil, fmt.Errorf("building filter: %w", err)
	}

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
		k.logger.Warn("SearchHistory failed", "query", input.Query, "error", err)
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
		k.logger.Warn("SearchDocuments failed", "query", input.Query, "error", err)
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
	if len(input.Title) > MaxKnowledgeTitleLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("title length %d exceeds maximum %d characters", len(input.Title), MaxKnowledgeTitleLength),
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
	if len(input.Content) > MaxKnowledgeContentSize {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("content size %d exceeds maximum %d bytes", len(input.Content), MaxKnowledgeContentSize),
			},
		}, nil
	}

	// Generate a deterministic document ID from the title using SHA-256.
	// Changing the title creates a new document; the old entry remains.
	// Prefix "user:" namespaces user-created knowledge (vs "system:" for built-in).
	docID := fmt.Sprintf("user:%x", sha256.Sum256([]byte(input.Title)))

	metadata := map[string]any{
		"id":          docID,
		"source_type": rag.SourceTypeFile,
		"title":       input.Title,
	}

	// Tag document with owner for per-user isolation (RAG poisoning prevention).
	if ownerID := OwnerIDFromContext(ctx); ownerID != "" {
		metadata["owner_id"] = ownerID
	}

	doc := ai.DocumentFromText(input.Content, metadata)

	if err := k.docStore.Index(ctx, []*ai.Document{doc}); err != nil {
		k.logger.Warn("StoreKnowledge failed", "title", input.Title, "error", err)
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
		k.logger.Warn("SearchSystemKnowledge failed", "query", input.Query, "error", err)
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
