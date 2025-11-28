// Package knowledge provides document storage and vector-based semantic search.
//
// Store manages documents with embedding vectors using PostgreSQL + pgvector.
// It supports metadata filtering and similarity search for conversation history
// and document retrieval.
package knowledge

import (
	"time"
)

// DefaultSearchTimeout is the default timeout for Search operations (10 seconds).
// This prevents long-running vector searches from blocking indefinitely.
const DefaultSearchTimeout = 10 * time.Second

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
	topK    int32
	filter  map[string]string
	timeout time.Duration
}

// WithTopK sets the maximum number of results to return.
// Default is 5 if not specified.
// If k < 1, it will be clamped to 1 to ensure valid search configuration.
func WithTopK(k int32) SearchOption {
	return func(c *searchConfig) {
		// Input validation: ensure topK is at least 1
		if k < 1 {
			k = 1
		}
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

// WithTimeout sets a custom timeout for the search operation.
// Default is DefaultSearchTimeout (10 seconds) if not specified.
// If d <= 0, the default timeout is used.
//
// Example:
//
//	results, err := store.Search(ctx, "query", knowledge.WithTimeout(5*time.Second))
func WithTimeout(d time.Duration) SearchOption {
	return func(c *searchConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// buildSearchConfig applies search options and returns the final configuration.
func buildSearchConfig(opts []SearchOption) *searchConfig {
	cfg := &searchConfig{
		topK:    5, // Default
		filter:  nil,
		timeout: DefaultSearchTimeout, // Default 10s
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
