package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pgvector/pgvector-go"

	"github.com/koopa0/koopa-cli/internal/sqlc"
)

// Source type constants for knowledge documents.
// These define the categories of knowledge stored in the system.
const (
	// SourceTypeConversation represents chat message history.
	SourceTypeConversation = "conversation"

	// SourceTypeFile represents indexed file content.
	SourceTypeFile = "file"

	// SourceTypeSystem represents system knowledge (best practices, coding standards).
	SourceTypeSystem = "system"
)

// Querier defines the interface for database operations on knowledge documents.
// Following Go best practices: interfaces are defined by the consumer, not the provider
// (similar to http.RoundTripper, sql.Driver, io.Reader).
//
// This interface allows Store to depend on abstraction rather than concrete implementation,
// improving testability and flexibility.
type Querier interface {
	// UpsertDocument inserts or updates a document
	UpsertDocument(ctx context.Context, arg sqlc.UpsertDocumentParams) error

	// SearchDocuments performs filtered vector search
	SearchDocuments(ctx context.Context, arg sqlc.SearchDocumentsParams) ([]sqlc.SearchDocumentsRow, error)

	// SearchDocumentsAll performs unfiltered vector search
	SearchDocumentsAll(ctx context.Context, arg sqlc.SearchDocumentsAllParams) ([]sqlc.SearchDocumentsAllRow, error)

	// CountDocuments counts documents matching filter
	CountDocuments(ctx context.Context, filterMetadata []byte) (int64, error)

	// CountDocumentsAll counts all documents
	CountDocumentsAll(ctx context.Context) (int64, error)

	// DeleteDocument deletes a document by ID
	DeleteDocument(ctx context.Context, id string) error

	// ListDocumentsBySourceType lists documents by source type
	ListDocumentsBySourceType(ctx context.Context, arg sqlc.ListDocumentsBySourceTypeParams) ([]sqlc.ListDocumentsBySourceTypeRow, error)
}

// Store manages knowledge documents with vector search capabilities.
// It handles embedding generation and vector similarity search using PostgreSQL + pgvector.
//
// Store is safe for concurrent use by multiple goroutines.
type Store struct {
	queries  Querier
	embedder ai.Embedder
	logger   *slog.Logger
}

// New creates a new Store instance.
//
// Parameters:
//   - querier: Database querier implementing Querier interface
//   - embedder: AI embedder for generating vector embeddings
//   - logger: Logger for debugging (nil = use default)
//
// Example (production with Wire):
//
//	store := knowledge.New(sqlc.New(dbPool), embedder, slog.Default())
//
// Example (testing with mock):
//
//	store := knowledge.New(mockQuerier, mockEmbedder, slog.Default())
func New(querier Querier, embedder ai.Embedder, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}

	return &Store{
		queries:  querier,
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
// Automatically applies 10-second timeout for vector search queries to prevent blocking.
//
// Example usage:
//
//	results, err := store.Search(ctx, "AI safety",
//	    knowledge.WithTopK(10),
//	    knowledge.WithFilter("source_type", "conversation"))
func (s *Store) Search(ctx context.Context, query string, opts ...SearchOption) ([]Result, error) {
	cfg := buildSearchConfig(opts)

	// Add query timeout to prevent long-running vector searches from blocking
	queryCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	// 1. Generate query embedding
	embeddingResp, err := s.embedder.Embed(queryCtx, &ai.EmbedRequest{
		Input: []*ai.Document{
			{
				Content: []*ai.Part{ai.NewTextPart(query)},
			},
		},
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("embedding generation timeout: %w", err)
		}
		return nil, fmt.Errorf("failed to generate query embedding: %w", err)
	}

	if len(embeddingResp.Embeddings) == 0 || len(embeddingResp.Embeddings[0].Embedding) == 0 {
		return nil, fmt.Errorf("empty embedding returned for query")
	}

	queryEmbedding := pgvector.NewVector(embeddingResp.Embeddings[0].Embedding)

	// 2. Execute search using sqlc generated methods (with timeout context)
	// SECURITY NOTE (SQL Injection Prevention):
	// - filterJSON is ALWAYS generated by json.Marshal (never user input directly)
	// - sqlc uses parameterized queries (sqlc.arg) preventing injection
	// - JSONB @> operator is safe when used with proper parameters
	// - Future developers: ALWAYS use json.Marshal for filter metadata
	if len(cfg.filter) > 0 {
		filterJSON, marshalErr := json.Marshal(cfg.filter)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to marshal filter: %w", marshalErr)
		}
		rows, searchErr := s.queries.SearchDocuments(queryCtx, sqlc.SearchDocumentsParams{
			QueryEmbedding: &queryEmbedding,
			FilterMetadata: filterJSON,
			ResultLimit:    cfg.topK,
		})
		if searchErr != nil {
			if errors.Is(searchErr, context.DeadlineExceeded) {
				return nil, fmt.Errorf("search query timeout: %w", searchErr)
			}
			return nil, fmt.Errorf("search failed: %w", searchErr)
		}
		return s.rowsToResults(rows), nil
	}

	rows, err := s.queries.SearchDocumentsAll(queryCtx, sqlc.SearchDocumentsAllParams{
		QueryEmbedding: &queryEmbedding,
		ResultLimit:    cfg.topK,
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("search query timeout: %w", err)
		}
		return nil, fmt.Errorf("search failed: %w", err)
	}
	return s.rowsToResultsAll(rows), nil
}

// Count returns the number of documents matching the given filter.
// If filter is nil or empty, it returns the total count of all documents.
//
// Parameters:
//   - ctx: Context for the operation
//   - filter: Metadata filter (e.g., map[string]string{"source_type": "conversation"})
//
// Returns:
//   - int: Number of documents matching the filter
//   - error: If count fails
func (s *Store) Count(ctx context.Context, filter map[string]string) (int, error) {
	var count int64
	var err error

	if len(filter) > 0 {
		filterJSON, marshalErr := json.Marshal(filter)
		if marshalErr != nil {
			return 0, fmt.Errorf("failed to marshal filter: %w", marshalErr)
		}
		count, err = s.queries.CountDocuments(ctx, filterJSON)
	} else {
		count, err = s.queries.CountDocumentsAll(ctx)
	}

	if err != nil {
		return 0, fmt.Errorf("count failed: %w", err)
	}

	// Overflow protection for 32-bit systems
	// On 64-bit systems, int is 64 bits and this check is always false (optimized away)
	// On 32-bit systems, this prevents silent overflow
	if count > math.MaxInt {
		return 0, fmt.Errorf("document count %d exceeds platform int capacity", count)
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
func (*Store) Close() error {
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
			Similarity: row.Similarity,
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
			Similarity: row.Similarity,
		})
	}

	return results
}

// ListBySourceType lists all documents by source type without similarity calculation.
// This is useful for listing indexed files without needing embeddings.
//
// Parameters:
//   - ctx: Context for the operation
//   - sourceType: Source type to filter by (e.g., "file", "conversation")
//   - limit: Maximum number of documents to return
//
// Returns:
//   - []Document: List of documents ordered by creation time (newest first)
//   - error: If listing fails
func (s *Store) ListBySourceType(ctx context.Context, sourceType string, limit int32) ([]Document, error) {
	// Input validation to prevent invalid queries and resource exhaustion
	const maxListLimit = 1000
	if limit <= 0 || limit > maxListLimit {
		s.logger.Warn("invalid list limit", "limit", limit, "max", maxListLimit)
		return nil, fmt.Errorf("limit must be between 1 and %d, got %d", maxListLimit, limit)
	}
	if sourceType == "" {
		return nil, fmt.Errorf("sourceType must not be empty")
	}

	// Validate sourceType against known production values to prevent misuse
	// Known source types defined as constants at package level
	validSourceTypes := map[string]struct{}{
		SourceTypeConversation: {},
		SourceTypeFile:         {},
		SourceTypeSystem:       {},
	}
	if _, ok := validSourceTypes[sourceType]; !ok {
		s.logger.Warn("invalid sourceType requested", "sourceType", sourceType)
		return nil, fmt.Errorf("invalid sourceType: %q, must be one of: conversation, file, system", sourceType)
	}

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
