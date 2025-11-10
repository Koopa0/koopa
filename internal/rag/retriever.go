package rag

import (
	"context"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/knowledge"
)

// Retriever bridges knowledge.Store to Genkit ai.Retriever interface.
// It provides different types of retrievers for various knowledge sources.
type Retriever struct {
	store     *knowledge.Store
	sessionID string // Optional: if set, filters results to this session only
}

// New creates a new Retriever with the given knowledge store.
// For session-specific retrieval, use NewWithSession instead.
func New(store *knowledge.Store) *Retriever {
	return &Retriever{
		store:     store,
		sessionID: "",
	}
}

// NewWithSession creates a new Retriever that filters results by session ID.
// This is useful for chat mode where you only want to retrieve from current session.
func NewWithSession(store *knowledge.Store, sessionID string) *Retriever {
	return &Retriever{
		store:     store,
		sessionID: sessionID,
	}
}

// DefineConversation defines a Genkit retriever for conversation history.
// It searches only messages (source_type="conversation") from the knowledge store.
// If the Retriever was created with NewWithSession, it additionally filters by session_id.
//
// Usage:
//
//	r := retriever.NewWithSession(knowledgeStore, sessionID)
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

			// If sessionID is set, add session filter
			if r.sessionID != "" {
				searchOpts = append(searchOpts, knowledge.WithFilter("session_id", r.sessionID))
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

			// Search documents only (not conversations)
			results, err := r.store.SearchExceptConversations(ctx, queryText, topK)
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

// extractTopK extracts topK from request options, returns defaultK if not found
func extractTopK(req *ai.RetrieverRequest, defaultK int) int {
	if opts, ok := req.Options.(map[string]any); ok {
		if k, exists := opts["k"]; exists {
			if kInt, ok := k.(int); ok {
				return kInt
			}
		}
	}
	return defaultK
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
