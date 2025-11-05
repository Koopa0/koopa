package knowledge

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/firebase/genkit/go/ai"
	chromem "github.com/philippgille/chromem-go"
)

// VectorStore defines the interface for vector storage operations.
// Following Go best practice: "Accept interfaces, return structs".
type VectorStore interface {
	Add(ctx context.Context, doc Document) error
	Search(ctx context.Context, query string, opts ...SearchOption) ([]Result, error)
	Count(ctx context.Context, filter map[string]string) (int, error)
	Close() error
}

// Store provides persistent vector storage for knowledge documents.
// It uses chromem-go as the embedded vector database.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	db         *chromem.DB
	collection *chromem.Collection
	logger     *slog.Logger
}

// New creates a new Store with persistent storage at the given path.
// The embedder is used to generate vector embeddings for documents.
// If logger is nil, a default logger will be used.
//
// The Store automatically persists data to disk. Call Close() when done
// to ensure clean shutdown, though chromem-go handles auto-persistence.
func New(path string, collectionName string, embedder ai.Embedder, logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}

	db, err := chromem.NewPersistentDB(path, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create chromem DB: %w", err)
	}

	embeddingFunc := NewEmbeddingFunc(embedder)

	collection, err := db.GetOrCreateCollection(collectionName, nil, embeddingFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection %q: %w", collectionName, err)
	}

	return &Store{
		db:         db,
		collection: collection,
		logger:     logger,
	}, nil
}

// Add adds a document to the knowledge store.
// The document's content is automatically embedded using the configured embedder.
func (s *Store) Add(ctx context.Context, doc Document) error {
	// Prepare metadata with create_at timestamp
	metadata := make(map[string]string, len(doc.Metadata)+1)
	if doc.Metadata != nil {
		for k, v := range doc.Metadata {
			metadata[k] = v
		}
	}
	metadata["create_at"] = doc.CreateAt.Format(time.RFC3339)

	err := s.collection.AddDocument(ctx, chromem.Document{
		ID:       doc.ID,
		Content:  doc.Content,
		Metadata: metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to add document %q: %w", doc.ID, err)
	}

	return nil
}

// Search performs semantic search on the knowledge store using functional options.
// It returns the most similar documents to the query, ordered by similarity score.
//
// Example usage:
//
//	results, err := store.Search(ctx, "AI safety",
//	    knowledge.WithTopK(10),
//	    knowledge.WithFilter("source_type", "conversation"))
func (s *Store) Search(ctx context.Context, query string, opts ...SearchOption) ([]Result, error) {
	cfg := buildSearchConfig(opts)

	results, err := s.collection.Query(ctx, query, cfg.topK, cfg.filter, nil)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	out := make([]Result, 0, len(results))
	for _, r := range results {
		// Parse create_at timestamp (handle errors properly)
		var createAt time.Time
		if ts := r.Metadata["create_at"]; ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				createAt = t
			} else {
				s.logger.Warn("failed to parse timestamp",
					"document_id", r.ID,
					"timestamp", ts,
					"error", err)
			}
		}

		// Copy metadata (excluding create_at as it's stored in CreateAt field)
		metadata := make(map[string]string, len(r.Metadata)-1)
		for k, v := range r.Metadata {
			if k != "create_at" {
				metadata[k] = v
			}
		}

		out = append(out, Result{
			Document: Document{
				ID:       r.ID,
				Content:  r.Content,
				Metadata: metadata,
				CreateAt: createAt,
			},
			Similarity: r.Similarity,
		})
	}

	return out, nil
}

// Count returns the number of documents matching the given filter.
// If filter is nil or empty, it returns the total count of all documents.
//
// Parameters:
//   - ctx: Context for the operation
//   - filter: Metadata filter (e.g., map[string]string{"source_type": "notion"})
//
// Returns:
//   - int: Number of documents matching the filter
//   - error: If count fails
//
// Implementation note: chromem-go doesn't have a native Count API,
// so we use a workaround by querying with nResults and estimating.
// For exact counts, we use a reasonable limit (1000) which should cover
// most use cases. If the result count equals the limit, the actual count
// may be higher.
func (s *Store) Count(ctx context.Context, filter map[string]string) (int, error) {
	// chromem-go doesn't have a direct Count API.
	// We use Query with a reasonable limit to avoid performance issues.
	// For most use cases, 1000 documents should be sufficient.
	const maxResults = 1000

	// Use a generic query that should match most documents
	const genericQuery = "document"

	results, err := s.collection.Query(ctx, genericQuery, maxResults, filter, nil)
	if err != nil {
		return 0, fmt.Errorf("count failed: %w", err)
	}

	return len(results), nil
}

// Close closes the Store and releases resources.
// Although chromem-go auto-persists, calling Close ensures clean shutdown.
func (s *Store) Close() error {
	// chromem-go auto-persists, but calling Close is good practice
	// for future compatibility and explicit resource management.
	return nil
}
