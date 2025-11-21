package rag

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
)

// TopK retrieval limits define the valid range and defaults for document retrieval.
// These limits balance result quality with query performance and resource usage.
//
// Design rationale:
//   - MaxTopK=10: Vector similarity search performance degrades significantly beyond
//     10 results. Most RAG applications achieve optimal context quality within this range.
//   - MinTopK=1: Minimum valid value for a meaningful search.
//   - DefaultConversationTopK=3: Conversations need fewer, more recent messages for context.
//   - DefaultDocumentTopK=5: Document searches benefit from slightly more context for
//     comprehensive answers while maintaining manageable context window size.
const (
	// MaxTopK is the maximum number of documents retrievable in a single query.
	// This hard limit prevents expensive queries and maintains reasonable performance.
	MaxTopK = 10

	// MinTopK is the minimum valid topK value.
	// Requests below this threshold will use the default value instead.
	MinTopK = 1

	// DefaultConversationTopK is the default number of conversation messages to retrieve.
	// Optimized for conversation context where recent messages are most relevant.
	DefaultConversationTopK = 3

	// DefaultDocumentTopK is the default number of documents to retrieve.
	// Optimized for document search where more context improves answer quality.
	DefaultDocumentTopK = 5
)

// Retriever bridges knowledge.Store to Genkit ai.Retriever interface.
// It provides different types of retrievers for various knowledge sources.
type Retriever struct {
	store *knowledge.Store
}

// New creates a new Retriever with the given knowledge store.
func New(store *knowledge.Store) *Retriever {
	return &Retriever{
		store: store,
	}
}

// DefineConversation defines a Genkit retriever for conversation history.
// It searches only messages (source_type="conversation") from the knowledge store.
//
// Usage:
//
//	r := retriever.New(knowledgeStore)
//	conversationRetriever := r.DefineConversation(g, "conversation-retriever")
func (r *Retriever) DefineConversation(g *genkit.Genkit, name string) ai.Retriever {
	return genkit.DefineRetriever(
		g, name, nil,
		func(ctx context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
			// Extract query text from request
			queryText := extractQueryText(req)

			// Extract topK from options (use conversation-optimized default)
			topK := extractTopK(req, DefaultConversationTopK)

			// Build search options using functional options pattern
			searchOpts := []knowledge.SearchOption{
				knowledge.WithTopK(topK),
				knowledge.WithFilter("source_type", "conversation"),
			}

			// Search in knowledge store
			results, err := r.store.Search(ctx, queryText, searchOpts...)
			if err != nil {
				return nil, err
			}

			// Convert to Genkit documents
			docs := convertToGenkitDocuments(results)

			return &ai.RetrieverResponse{
				Documents: docs,
			}, nil
		},
	)
}

// DefineDocument defines a Genkit retriever for documents (files, etc.).
// It searches only documents (excludes conversations) from the knowledge store.
func (r *Retriever) DefineDocument(g *genkit.Genkit, name string) ai.Retriever {
	return genkit.DefineRetriever(
		g, name, nil,
		func(ctx context.Context, req *ai.RetrieverRequest) (*ai.RetrieverResponse, error) {
			queryText := extractQueryText(req)
			// Extract topK from options (use document-optimized default)
			topK := extractTopK(req, DefaultDocumentTopK)

			// Search documents (primarily files) by filtering out conversations
			// We search for source_type="file" to exclude conversations
			searchOpts := []knowledge.SearchOption{
				knowledge.WithTopK(topK),
				knowledge.WithFilter("source_type", "file"),
			}

			results, err := r.store.Search(ctx, queryText, searchOpts...)
			if err != nil {
				return nil, err
			}

			docs := convertToGenkitDocuments(results)

			return &ai.RetrieverResponse{
				Documents: docs,
			}, nil
		},
	)
}

// extractQueryText extracts text from RetrieverRequest.Query
func extractQueryText(req *ai.RetrieverRequest) string {
	if req.Query != nil && len(req.Query.Content) > 0 {
		return req.Query.Content[0].Text
	}
	return ""
}

// extractTopK extracts topK from request options with validation.
//
// It validates that k is within [MinTopK, MaxTopK] range. If the requested
// value is invalid or missing, it returns defaultK.
//
// Supports multiple numeric types (int, int32, int64, float32, float64) and
// string for flexibility in client calls.
//
// Design: Uses package-level constants for range validation, making the
// business logic explicit and maintainable.
func extractTopK(req *ai.RetrieverRequest, defaultK int32) int32 {
	if opts, ok := req.Options.(map[string]any); ok {
		if k, exists := opts["k"]; exists {
			var kInt int

			// Handle multiple numeric types and string
			switch v := k.(type) {
			case int:
				kInt = v
			case int32:
				kInt = int(v)
			case int64:
				kInt = int(v)
			case float64:
				kInt = int(v)
			case float32:
				kInt = int(v)
			case string:
				// Try to parse string as int
				if parsed := parseIntSafe(v); parsed > 0 {
					kInt = parsed
				} else {
					return defaultK
				}
			default:
				// Unsupported type, use default
				return defaultK
			}

			// Validate range using package constants
			if kInt >= MinTopK && kInt <= MaxTopK {
				return int32(kInt) // #nosec G115 -- validated range [MinTopK, MaxTopK]
			}
		}
	}
	return defaultK
}

// parseIntSafe safely parses a string to int with topK-specific validation.
//
// This function is designed specifically for parsing topK values and enforces
// the [MinTopK, MaxTopK] range. It rejects:
//   - Non-numeric strings
//   - Negative numbers
//   - Values exceeding MaxTopK
//
// Returns 0 for invalid input, which extractTopK treats as "use default".
//
// Design: Uses MaxTopK constant to align with extractTopK's range validation.
// If topK limits change, only the constants need updating.
func parseIntSafe(s string) int {
	var result int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0 // Non-digit character
		}
		result = result*10 + int(ch-'0')

		// Early exit for values exceeding limit (using constant)
		if result > MaxTopK {
			return 0
		}
	}
	return result
}

// convertToGenkitDocuments converts knowledge.Result to Genkit ai.Document
func convertToGenkitDocuments(results []knowledge.Result) []*ai.Document {
	docs := make([]*ai.Document, len(results))
	for i, result := range results {
		// Convert map[string]string to map[string]any for Genkit
		metadata := make(map[string]any, len(result.Document.Metadata)+1)
		for k, v := range result.Document.Metadata {
			metadata[k] = v
		}
		// Add similarity score to metadata
		metadata["similarity"] = result.Similarity

		docs[i] = ai.DocumentFromText(result.Document.Content, metadata)
	}
	return docs
}
