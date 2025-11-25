// Package knowledge provides semantic search and document management.
//
// The knowledge package manages a vector-based knowledge store with PostgreSQL + pgvector backend.
// It provides document indexing, semantic similarity search, and metadata filtering capabilities
// for RAG (Retrieval-Augmented Generation) applications.
//
// # Overview
//
// The knowledge package consists of two main components:
//
//   - Store: Manages document persistence and semantic search
//   - SystemKnowledgeIndexer: Provides built-in knowledge about system capabilities and best practices
//
// Documents are automatically embedded using an AI embedder, enabling semantic search
// across the knowledge base.
//
// # Architecture
//
// Document Storage and Retrieval Flow:
//
//	Document (content + metadata)
//	     |
//	     v
//	Embedding Generation (via AI Embedder)
//	     |
//	     v
//	Vector Storage (PostgreSQL + pgvector)
//	     |
//	     | (when searching)
//	     v
//	Query Embedding
//	     |
//	     v
//	Vector Similarity Search
//	     |
//	     v
//	Ranked Results (with similarity scores)
//
// # Store: Vector Database Operations
//
// The Store type provides the following operations:
//
//	Add(ctx, document)       - Index document with automatic embedding
//	Search(ctx, query, opts) - Semantic search with filters
//	Count(ctx, filter)       - Count documents matching filter
//	Delete(ctx, docID)       - Remove document from store
//	ListBySourceType(ctx, sourceType, limit) - List documents without search
//
// The Store uses a KnowledgeQuerier interface for database operations, enabling
// dependency injection and testability. The interface abstracts sqlc-generated
// database code, following Go's "accept interfaces, return structs" principle.
//
// # Document Types and Metadata
//
// Documents support flexible metadata for filtering and categorization:
//
//	Document {
//	    ID:       string                 // Unique identifier
//	    Content:  string                 // Document content (auto-embedded)
//	    Metadata: map[string]string      // Filtereable metadata
//	    CreateAt: time.Time              // Creation timestamp
//	}
//
// Common metadata fields:
//
//	source_type: "file", "conversation", or "system"
//	category:    Content category (e.g., "golang", "capabilities")
//	topic:       Subtopic for filtering (e.g., "error-handling")
//
// # Search Operations
//
// The Search method provides semantic search with filtering:
//
//	results, err := store.Search(ctx, "golang best practices",
//	    knowledge.WithTopK(5),
//	    knowledge.WithFilter("source_type", "system"))
//
// Search returns ranked results with similarity scores. Results are ordered
// by semantic similarity, with scores from 0 to 1 (higher = more similar).
//
// Filters use metadata-based matching. Multiple filters can be combined
// for precise queries. Search uses 10-second timeout to prevent blocking.
//
// # SystemKnowledgeIndexer: Built-in Knowledge
//
// The SystemKnowledgeIndexer manages pre-defined knowledge documents:
//
//   - Go best practices (error handling, concurrency, naming)
//   - Agent capabilities (available tools, limitations)
//   - Architecture principles (design patterns, structure)
//
// System documents use fixed IDs (e.g., "system:golang-errors") for consistency.
// They use UPSERT semantics, updating existing documents automatically.
//
//	// Index all system knowledge at startup
//	indexer := knowledge.NewSystemKnowledgeIndexer(store, logger)
//	count, err := indexer.IndexAll(ctx)
//	if err != nil {
//	    panic(err)
//	}
//	println(count, "system documents indexed")
//
// # Database Backend
//
// The knowledge store requires PostgreSQL with pgvector extension:
//
//   - PostgreSQL 12+
//   - pgvector 0.4.0+ for vector operations
//   - JSONB support for metadata storage
//
// Database schema includes:
//
//	documents table:
//	    id          TEXT PRIMARY KEY
//	    content     TEXT NOT NULL
//	    embedding   vector(1536)
//	    metadata    JSONB (indexed for filter queries)
//	    created_at  TIMESTAMPTZ
//
// # Security Considerations
//
// The knowledge store implements several security practices:
//
//   - SQL Injection Prevention: Uses parameterized queries via sqlc
//   - Metadata Filtering: Only accepts JSONB operators with proper validation
//   - Input Validation: Validates source types and list limits
//   - Error Sanitization: Logs full errors, returns user-friendly messages
//
// Future developers should always use json.Marshal for filter metadata
// and never pass user input directly to database queries.
//
// # Example Usage
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/firebase/genkit/go/ai"
//	    "github.com/jackc/pgx/v5/pgxpool"
//	    "github.com/koopa0/koopa-cli/internal/knowledge"
//	    "log/slog"
//	)
//
//	func main() {
//	    ctx := context.Background()
//
//	    // Connect to PostgreSQL
//	    dbPool, _ := pgxpool.New(ctx, "postgresql://...")
//	    defer dbPool.Close()
//
//	    // Create embedder (e.g., from Genkit)
//	    embedder := googleai.NewEmbedder()
//
//	    // Create knowledge store
//	    store := knowledge.New(sqlc.New(dbPool), embedder, slog.Default())
//
//	    // Index system knowledge
//	    indexer := knowledge.NewSystemKnowledgeIndexer(store, slog.Default())
//	    indexer.IndexAll(ctx)
//
//	    // Index user documents
//	    doc := knowledge.Document{
//	        ID:      "user-doc-1",
//	        Content: "Important information about the project",
//	        Metadata: map[string]string{
//	            "source_type": "file",
//	            "category":    "project",
//	        },
//	        CreateAt: time.Now(),
//	    }
//	    store.Add(ctx, doc)
//
//	    // Search knowledge base
//	    results, _ := store.Search(ctx, "project information",
//	        knowledge.WithTopK(5),
//	        knowledge.WithFilter("source_type", "file"))
//
//	    for _, result := range results {
//	        println(result.Document.ID, "similarity:", result.Similarity)
//	    }
//	}
//
// # Testing
//
// The knowledge package is designed for testability:
//
//   - Store accepts KnowledgeQuerier interface for mock database
//   - Indexer accepts IndexerStore interface for mock storage
//   - New() accepts interface, pass mock querier directly for tests
//   - Integration tests use real PostgreSQL database
//
// # Thread Safety
//
// Both Store and SystemKnowledgeIndexer are safe for concurrent use:
//
//   - Store: Thread-safe via concurrent database connections
//   - SystemKnowledgeIndexer: Thread-safe via mutex protection on IndexAll/ClearAll
//   - Database: PostgreSQL handles concurrent access safely
//
// # Performance Considerations
//
// - Vector search performance depends on embedding dimension (typically 768-1536)
// - JSONB filtering is indexed for fast metadata queries
// - TopK limits (default 5-10) balance quality and latency
// - 10-second timeout prevents runaway queries
// - Batch operations (multiple documents) may be more efficient
package knowledge
