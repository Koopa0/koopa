package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"

	"github.com/koopa0/koopa/internal/sqlc"
)

// Store manages knowledge documents with vector search capabilities.
// It handles embedding generation and vector similarity search using PostgreSQL + pgvector.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	queries  *sqlc.Queries
	embedder ai.Embedder
	logger   *slog.Logger
}

// New creates a new Store instance
//
// Parameters:
//   - dbPool: PostgreSQL connection pool (pgxpool)
//   - embedder: AI embedder for generating vector embeddings
//   - logger: Logger for debugging (nil = use default)
//
// Example:
//
//	store := knowledge.New(dbPool, embedder, slog.Default())
func New(dbPool *pgxpool.Pool, embedder ai.Embedder, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}

	return &Store{
		queries:  sqlc.New(dbPool),
		embedder: embedder,
		logger:   logger,
	}
}

// Add adds a document to the knowledge store.
// The document's content is automatically embedded using the configured embedder.
// Uses UPSERT (ON CONFLICT DO UPDATE) to handle both inserts and updates.
func (s *Store) Add(ctx context.Context, doc Document) error {
	// 1. Generate embedding
	embeddingResp, err := s.embedder.Embed(ctx, &ai.EmbedRequest{
		Input: []*ai.Document{
			{
				Content: []*ai.Part{ai.NewTextPart(doc.Content)},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}

	if len(embeddingResp.Embeddings) == 0 || len(embeddingResp.Embeddings[0].Embedding) == 0 {
		return fmt.Errorf("empty embedding returned for document %q", doc.ID)
	}

	embedding := pgvector.NewVector(embeddingResp.Embeddings[0].Embedding)

	// 2. Prepare metadata
	metadataJSON, err := json.Marshal(doc.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// 3. Convert time.Time to pgtype.Timestamptz
	createdAt := pgtype.Timestamptz{
		Time:  doc.CreateAt,
		Valid: !doc.CreateAt.IsZero(),
	}

	// 4. Upsert document using sqlc generated method
	err = s.queries.UpsertDocument(ctx, sqlc.UpsertDocumentParams{
		ID:        doc.ID,
		Content:   doc.Content,
		Embedding: &embedding,
		Metadata:  metadataJSON,
		CreatedAt: createdAt,
	})
	if err != nil {
		return fmt.Errorf("failed to upsert document %q: %w", doc.ID, err)
	}

	s.logger.Debug("added document", "id", doc.ID, "content_length", len(doc.Content))
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

	// 1. Generate query embedding
	embeddingResp, err := s.embedder.Embed(ctx, &ai.EmbedRequest{
		Input: []*ai.Document{
			{
				Content: []*ai.Part{ai.NewTextPart(query)},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate query embedding: %w", err)
	}

	if len(embeddingResp.Embeddings) == 0 || len(embeddingResp.Embeddings[0].Embedding) == 0 {
		return nil, fmt.Errorf("empty embedding returned for query")
	}

	queryEmbedding := pgvector.NewVector(embeddingResp.Embeddings[0].Embedding)

	// 2. Execute search using sqlc generated methods
	if len(cfg.filter) > 0 {
		filterJSON, _ := json.Marshal(cfg.filter)
		rows, err := s.queries.SearchDocuments(ctx, sqlc.SearchDocumentsParams{
			QueryEmbedding: &queryEmbedding,
			FilterMetadata: filterJSON,
			ResultLimit:    cfg.topK,
		})
		if err != nil {
			return nil, fmt.Errorf("search failed: %w", err)
		}
		return s.rowsToResults(rows), nil
	} else {
		rows, err := s.queries.SearchDocumentsAll(ctx, sqlc.SearchDocumentsAllParams{
			QueryEmbedding: &queryEmbedding,
			ResultLimit:    cfg.topK,
		})
		if err != nil {
			return nil, fmt.Errorf("search failed: %w", err)
		}
		return s.rowsToResultsAll(rows), nil
	}
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
func (s *Store) Count(ctx context.Context, filter map[string]string) (int, error) {
	var count int64
	var err error

	if len(filter) > 0 {
		filterJSON, _ := json.Marshal(filter)
		count, err = s.queries.CountDocuments(ctx, filterJSON)
	} else {
		count, err = s.queries.CountDocumentsAll(ctx)
	}

	if err != nil {
		return 0, fmt.Errorf("count failed: %w", err)
	}

	return int(count), nil
}

// Delete removes a document from the knowledge store.
//
// Parameters:
//   - ctx: Context for the operation
//   - docID: Document ID to delete
//
// Returns:
//   - error: If deletion fails
func (s *Store) Delete(ctx context.Context, docID string) error {
	if err := s.queries.DeleteDocument(ctx, docID); err != nil {
		return fmt.Errorf("failed to delete document %q: %w", docID, err)
	}

	s.logger.Debug("deleted document", "id", docID)
	return nil
}

// Close closes the Store (no-op, database connection managed externally)
func (s *Store) Close() error {
	// Database connection is managed by the caller, nothing to close here
	return nil
}

// rowsToResults converts sqlc search results to business model Results
func (s *Store) rowsToResults(rows []sqlc.SearchDocumentsRow) []Result {
	results := make([]Result, 0, len(rows))

	for _, row := range rows {
		// Parse metadata
		var metadata map[string]string
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			s.logger.Warn("failed to parse metadata", "document_id", row.ID, "error", err)
			metadata = make(map[string]string)
		}

		// Use native created_at column from database
		var createAt time.Time
		if row.CreatedAt.Valid {
			createAt = row.CreatedAt.Time
		}

		results = append(results, Result{
			Document: Document{
				ID:       row.ID,
				Content:  row.Content,
				Metadata: metadata,
				CreateAt: createAt,
			},
			Similarity: float32(row.Similarity),
		})
	}

	return results
}

// rowsToResultsAll converts sqlc search results (all) to business model Results
func (s *Store) rowsToResultsAll(rows []sqlc.SearchDocumentsAllRow) []Result {
	results := make([]Result, 0, len(rows))

	for _, row := range rows {
		// Parse metadata
		var metadata map[string]string
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			s.logger.Warn("failed to parse metadata", "document_id", row.ID, "error", err)
			metadata = make(map[string]string)
		}

		// Use native created_at column from database
		var createAt time.Time
		if row.CreatedAt.Valid {
			createAt = row.CreatedAt.Time
		}

		results = append(results, Result{
			Document: Document{
				ID:       row.ID,
				Content:  row.Content,
				Metadata: metadata,
				CreateAt: createAt,
			},
			Similarity: float32(row.Similarity),
		})
	}

	return results
}

// ListBySourceType lists all documents by source type without similarity calculation.
// This is useful for listing indexed files without needing embeddings.
//
// Parameters:
//   - ctx: Context for the operation
//   - sourceType: Source type to filter by (e.g., "file", "notion", "conversation")
//   - limit: Maximum number of documents to return
//
// Returns:
//   - []Document: List of documents ordered by creation time (newest first)
//   - error: If listing fails
func (s *Store) ListBySourceType(ctx context.Context, sourceType string, limit int) ([]Document, error) {
	rows, err := s.queries.ListDocumentsBySourceType(ctx, sqlc.ListDocumentsBySourceTypeParams{
		SourceType:  sourceType,
		ResultLimit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list documents: %w", err)
	}

	documents := make([]Document, 0, len(rows))
	for _, row := range rows {
		// Parse metadata
		var metadata map[string]string
		if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
			s.logger.Warn("failed to parse metadata", "doc_id", row.ID, "error", err)
			metadata = make(map[string]string)
		}

		// Use native created_at column from database
		var createAt time.Time
		if row.CreatedAt.Valid {
			createAt = row.CreatedAt.Time
		}

		documents = append(documents, Document{
			ID:       row.ID,
			Content:  row.Content,
			Metadata: metadata,
			CreateAt: createAt,
		})
	}

	return documents, nil
}
