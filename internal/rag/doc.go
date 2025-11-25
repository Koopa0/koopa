// Package rag implements Retrieval-Augmented Generation (RAG) for Koopa.
//
// The rag package provides document indexing and knowledge base integration for LLM applications.
// It consists of two main components: Indexer for adding documents to the knowledge base,
// and Retriever for integrating the knowledge base with Genkit's retrieval interface.
//
// # Overview
//
// RAG enhances LLM responses by augmenting prompts with relevant context from a knowledge base.
// The rag package manages:
//
//   - Local file indexing with vector embeddings
//   - Semantic search and filtering
//   - Integration with Genkit's retriever interface
//   - Multiple retrieval strategies (conversations, documents, system knowledge)
//
// # Architecture
//
// RAG Pipeline:
//
//	Local Files / Directory
//	     |
//	     v
//	Indexer
//	     |
//	     +-- File validation (extension, size)
//	     +-- Content extraction
//	     +-- Metadata generation
//	     |
//	     v
//	Knowledge Store
//	     |
//	     +-- Vector embedding (via AI Embedder)
//	     +-- Vector storage (PostgreSQL + pgvector)
//	     |
//	     v
//	Retriever (Genkit interface)
//	     |
//	     +-- Conversation retriever (source_type=conversation)
//	     +-- Document retriever (source_type=file)
//	     +-- System knowledge retriever (source_type=system)
//	     |
//	     v
//	LLM (with augmented context)
//
// # Indexer: Local File Management
//
// The Indexer type provides file indexing operations:
//
//	AddFile(ctx, filePath)         - Index single file
//	AddDirectory(ctx, dirPath)     - Recursively index directory
//	ListDocuments(ctx)             - List indexed documents
//	RemoveDocument(ctx, docID)     - Delete indexed document
//	GetStats(ctx)                  - Statistics (count, file types, size)
//
// The Indexer manages:
//
//   - Supported file types (txt, md, go, py, js, ts, java, etc.)
//   - Gitignore patterns (skips ignored files)
//   - Security validation (path traversal prevention via os.Root)
//   - Metadata generation (file path, name, extension, size)
//   - Error recovery (continues on individual file failures)
//
// # Supported File Types
//
// By default, the Indexer supports:
//
//	Text files:       .txt
//	Documentation:    .md
//	Code:             .go, .py, .js, .ts, .java, .c, .cpp, .h, .hpp, .rs, .rb, .php, .sh
//	Configuration:    .yaml, .yml, .json, .xml
//	Web:              .html, .css
//	Database:         .sql
//
// Custom file type lists can be provided during initialization.
//
// # Indexing Operations
//
// Example: Index a single file
//
//	indexer := rag.NewIndexer(knowledgeStore, nil)
//	err := indexer.AddFile(ctx, "/path/to/README.md")
//
// Example: Index entire directory
//
//	indexer := rag.NewIndexer(knowledgeStore, nil)
//	result, err := indexer.AddDirectory(ctx, "/path/to/project")
//	println(result.FilesAdded, "files indexed")
//	println(result.FilesFailed, "files failed")
//	println(result.TotalSize, "bytes indexed")
//
// # Document Identification
//
// Documents are identified by hash of their absolute path:
//
//	docID = "file_" + SHA256(filepath)[0:16]
//
// This ensures:
//   - Stable IDs across invocations
//   - No duplicate indexing of same file
//   - Deterministic document IDs for testing
//
// # Security Measures
//
// The Indexer enforces security via os.Root (Go 1.24+):
//
//   - Prevents path traversal (e.g., "../../../etc/passwd")
//   - Prevents symlink escapes
//   - Confines file access to specified directory
//   - Validates file types before reading
//
// Example: Reading files safely
//
//	root, _ := os.OpenRoot("/path/to/directory")
//	defer root.Close()
//	content, _ := root.ReadFile("file.txt")  // Safe relative path
//
// # Retriever: Genkit Integration
//
// The Retriever type bridges knowledge.Store to Genkit's ai.Retriever interface:
//
//	DefineConversation(g, name)  - Retriever for conversation history
//	DefineDocument(g, name)      - Retriever for indexed documents
//
// Each retriever can be registered with Genkit and used in flows:
//
//	r := rag.New(knowledgeStore)
//	convRetriever := r.DefineConversation(g, "conversation-search")
//	docRetriever := r.DefineDocument(g, "document-search")
//
// # TopK Configuration
//
// The Retriever respects TopK limits for result quantity:
//
//	MaxTopK = 10                      // Hard limit on results per query
//	MinTopK = 1                       // Minimum valid value
//	DefaultConversationTopK = 3       // Default for conversation history
//	DefaultDocumentTopK = 5           // Default for document search
//
// These constants balance quality and performance. Requests are validated
// against these bounds, with invalid values falling back to defaults.
//
// # Retriever Features
//
// Both retrievers support:
//
//   - Query text extraction from Genkit requests
//   - Configurable TopK parameter (via request options)
//   - Metadata filtering (source_type, category, etc.)
//   - Similarity scoring in results
//   - Type conversion to Genkit format
//
// Example: Using in a Genkit flow
//
//	result, _ := docRetriever.Retrieve(ctx, &ai.RetrieverRequest{
//	    Query: &ai.Message{
//	        Content: []*ai.Part{ai.NewTextPart("golang error handling")},
//	    },
//	    Options: map[string]any{"k": 5},
//	})
//
//	for _, doc := range result.Documents {
//	    println(doc.Content)
//	}
//
// # Example: Complete RAG Setup
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/firebase/genkit/go/genkit"
//	    "github.com/firebase/genkit/go/plugins/googlegenai"
//	    "github.com/jackc/pgx/v5/pgxpool"
//	    "github.com/koopa0/koopa-cli/internal/knowledge"
//	    "github.com/koopa0/koopa-cli/internal/rag"
//	    "log/slog"
//	)
//
//	func main() {
//	    ctx := context.Background()
//
//	    // Initialize Genkit
//	    g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))
//
//	    // Connect to PostgreSQL
//	    dbPool, _ := pgxpool.New(ctx, "postgresql://...")
//	    defer dbPool.Close()
//
//	    // Create knowledge store with embedder
//	    embedder := googleai.NewEmbedder()
//	    knowledgeStore := knowledge.New(sqlc.New(dbPool), embedder, slog.Default())
//
//	    // Index documents
//	    indexer := rag.NewIndexer(knowledgeStore, nil)
//	    indexer.AddDirectory(ctx, "./docs")
//
//	    // Create retrievers
//	    retriever := rag.New(knowledgeStore)
//	    docRetriever := retriever.DefineDocument(g, "docs")
//
//	    // Use in flows
//	    genkit.DefineFlow(g, "rag-flow",
//	        func(ctx context.Context, query string) (string, error) {
//	            // Retrieve documents
//	            results, _ := docRetriever.Retrieve(ctx, &ai.RetrieverRequest{
//	                Query: &ai.Message{
//	                    Content: []*ai.Part{ai.NewTextPart(query)},
//	                },
//	            })
//
//	            // Generate with context
//	            resp, _ := genkit.Generate(ctx, g,
//	                ai.WithModelName("gemini-pro"),
//	                ai.WithPrompt(query),
//	                ai.WithDocuments(results.Documents...),
//	            )
//	            return resp.Text(), nil
//	        },
//	    )
//	}
//
// # Error Handling
//
// Both Indexer and Retriever handle errors gracefully:
//
//	Indexer errors:
//	- Unsupported file types are skipped
//	- Individual file failures don't stop directory indexing
//	- Returns IndexResult with counts (added, skipped, failed)
//
//	Retriever errors:
//	- Timeout errors return empty results
//	- Invalid parameters fall back to defaults
//	- Returns structured error messages
//
// # Performance Considerations
//
//   - Vector indexing latency: 100-500ms per document
//   - Vector search latency: 50-200ms per query
//   - TopK limits prevent expensive queries
//   - Batch directory indexing more efficient than single files
//   - Gitignore support reduces unnecessary indexing
//
// # Testing
//
// The rag package is designed for testability:
//
//   - Indexer accepts IndexerStore interface for mocks
//   - Retriever is pure function composition
//   - No external state or side effects
//   - Integration tests with real knowledge store
//
// # Thread Safety
//
// Both Indexer and Retriever are safe for concurrent use:
//
//   - Indexer: Thread-safe via underlying knowledge.Store
//   - Retriever: Stateless, no shared mutable state
//   - PostgreSQL: Handles concurrent vector search safely
package rag
