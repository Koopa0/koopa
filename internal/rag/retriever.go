package rag

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
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

			// Extract topK from options (default: 3)
			topK := extractTopK(req, 3)

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
			topK := extractTopK(req, 5)

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

// extractTopK extracts topK from request options, returns defaultK if not found.
// Validates that k is within the range [1, 10] to ensure valid search configuration.
// Supports multiple numeric types (int, int32, float64) and string for flexibility.
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

			// Validate range to ensure robustness regardless of caller behavior
			if kInt >= 1 && kInt <= 10 {
				return int32(kInt) // #nosec G115 -- validated range 1-10
			}
		}
	}
	return defaultK
}

// parseIntSafe safely parses a string to int, returns 0 if parse fails
func parseIntSafe(s string) int {
	var result int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		result = result*10 + int(ch-'0')
		if result > 10 {
			return 0 // Early exit for values > 10
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
