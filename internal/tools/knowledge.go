package tools

// knowledge.go defines knowledge search tools for semantic retrieval.
//
// Provides 3 knowledge tools: searchHistory, searchDocuments, searchSystemKnowledge.
// Each tool searches a specific knowledge source with metadata filtering.

import (
	"context"
	"fmt"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"

	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/rag"
)

const (
	ToolSearchHistory         = "search_history"
	ToolSearchDocuments       = "search_documents"
	ToolSearchSystemKnowledge = "search_system_knowledge"
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

// KnowledgeTools holds dependencies for knowledge operation handlers.
type KnowledgeTools struct {
	retriever ai.Retriever
	logger    log.Logger
}

// NewKnowledgeTools creates a KnowledgeTools instance.
func NewKnowledgeTools(retriever ai.Retriever, logger log.Logger) (*KnowledgeTools, error) {
	if retriever == nil {
		return nil, fmt.Errorf("retriever is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &KnowledgeTools{retriever: retriever, logger: logger}, nil
}

// RegisterKnowledgeTools registers all knowledge search tools with Genkit.
// Tools are registered with event emission wrappers for streaming support.
func RegisterKnowledgeTools(g *genkit.Genkit, kt *KnowledgeTools) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if kt == nil {
		return nil, fmt.Errorf("KnowledgeTools is required")
	}

	return []ai.Tool{
		genkit.DefineTool(g, ToolSearchHistory,
			"Search conversation history using semantic similarity. Default topK: 3.",
			WithEvents(ToolSearchHistory, kt.SearchHistory)),
		genkit.DefineTool(g, ToolSearchDocuments,
			"Search indexed documents using semantic similarity. Default topK: 5.",
			WithEvents(ToolSearchDocuments, kt.SearchDocuments)),
		genkit.DefineTool(g, ToolSearchSystemKnowledge,
			"Search system knowledge base using semantic similarity. Default topK: 3.",
			WithEvents(ToolSearchSystemKnowledge, kt.SearchSystemKnowledge)),
	}, nil
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
func (k *KnowledgeTools) search(ctx context.Context, query string, topK int, sourceType string) ([]*ai.Document, error) {
	// Validate source type against whitelist (SQL injection prevention)
	if !validSourceTypes[sourceType] {
		return nil, fmt.Errorf("invalid source type: %q", sourceType)
	}

	// Build WHERE clause filter for source_type (safe: sourceType is validated)
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
func (k *KnowledgeTools) SearchHistory(ctx *ai.ToolContext, input KnowledgeSearchInput) (Result, error) {
	k.logger.Info("SearchHistory called", "query", input.Query, "topK", input.TopK)

	topK := clampTopK(input.TopK, DefaultHistoryTopK)

	results, err := k.search(ctx, input.Query, topK, rag.SourceTypeConversation)
	if err != nil {
		k.logger.Error("SearchHistory failed", "query", input.Query, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("history search failed: %v", err),
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
func (k *KnowledgeTools) SearchDocuments(ctx *ai.ToolContext, input KnowledgeSearchInput) (Result, error) {
	k.logger.Info("SearchDocuments called", "query", input.Query, "topK", input.TopK)

	topK := clampTopK(input.TopK, DefaultDocumentsTopK)

	results, err := k.search(ctx, input.Query, topK, rag.SourceTypeFile)
	if err != nil {
		k.logger.Error("SearchDocuments failed", "query", input.Query, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("document search failed: %v", err),
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

// SearchSystemKnowledge searches system knowledge base using semantic similarity.
func (k *KnowledgeTools) SearchSystemKnowledge(ctx *ai.ToolContext, input KnowledgeSearchInput) (Result, error) {
	k.logger.Info("SearchSystemKnowledge called", "query", input.Query, "topK", input.TopK)

	topK := clampTopK(input.TopK, DefaultSystemKnowledgeTopK)

	results, err := k.search(ctx, input.Query, topK, rag.SourceTypeSystem)
	if err != nil {
		k.logger.Error("SearchSystemKnowledge failed", "query", input.Query, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("system knowledge search failed: %v", err),
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
