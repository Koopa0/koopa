// Package knowledge provides document storage and vector-based semantic search.
//
// Store manages documents with embedding vectors using PostgreSQL + pgvector.
// It supports metadata filtering and similarity search for conversation history
// and document retrieval.
package knowledge

import "time"

// Document represents a knowledge document.
// It contains the textual content and optional metadata.
// Metadata must be map[string]string to comply with chromem-go requirements.
type Document struct {
	ID       string            // Unique identifier
	Content  string            // Document text content
	Metadata map[string]string // Optional metadata (source, type, etc.)
	CreateAt time.Time         // Creation timestamp
}

// Result represents a single search result with similarity score.
type Result struct {
	Document   Document
	Similarity float64 // Cosine similarity score (0-1)
}

// SearchOption configures search behavior using the functional options pattern.
// This follows Go best practices as seen in context.WithTimeout, grpc.Dial, etc.
type SearchOption func(*searchConfig)

// searchConfig holds internal search configuration.
type searchConfig struct {
	topK   int32
	filter map[string]string
}

// WithTopK sets the maximum number of results to return.
// Default is 5 if not specified.
func WithTopK(k int32) SearchOption {
	return func(c *searchConfig) {
		c.topK = k
	}
}

// WithFilter adds a metadata filter to restrict search results.
// Multiple calls to WithFilter add additional filters (AND logic).
// Example: WithFilter("source_type", "conversation")
func WithFilter(key, value string) SearchOption {
	return func(c *searchConfig) {
		if c.filter == nil {
			c.filter = make(map[string]string)
		}
		c.filter[key] = value
	}
}

// buildSearchConfig applies search options and returns the final configuration.
func buildSearchConfig(opts []SearchOption) *searchConfig {
	cfg := &searchConfig{
		topK:   5, // Default
		filter: nil,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
