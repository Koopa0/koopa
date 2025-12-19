package testutil

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
)

// RAGSetup contains all resources needed for RAG-enabled integration tests.
// This uses the Genkit PostgreSQL plugin for DocStore and Retriever.
type RAGSetup struct {
	// Genkit instance with both GoogleAI and PostgreSQL plugins
	Genkit *genkit.Genkit

	// Embedder for creating vector embeddings
	Embedder ai.Embedder

	// DocStore for indexing documents (from Genkit PostgreSQL plugin)
	DocStore *postgresql.DocStore

	// Retriever for semantic search (from Genkit PostgreSQL plugin)
	Retriever ai.Retriever
}

// SetupRAG creates a complete RAG test environment using Genkit PostgreSQL plugin.
//
// This function sets up:
//   - Genkit with GoogleAI plugin (for embeddings)
//   - PostgreSQL plugin wrapping the provided connection pool
//   - DocStore for indexing documents
//   - Retriever for semantic search
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - PostgreSQL pool must be initialized (from SetupTestDB)
//   - Migrations must be run (SetupTestDB does this automatically)
//
// Example:
//
//	func TestRAGFeature(t *testing.T) {
//	    db, dbCleanup := testutil.SetupTestDB(t)
//	    defer dbCleanup()
//
//	    rag := testutil.SetupRAG(t, db.Pool)
//
//	    // Index documents
//	    doc := ai.DocumentFromText("test content", map[string]any{
//	        "source_type": "file",
//	    })
//	    rag.DocStore.Index(ctx, []*ai.Document{doc})
//
//	    // Query using retriever
//	    req := &ai.RetrieverRequest{Query: ai.DocumentFromText("query", nil)}
//	    resp, _ := rag.Retriever.Retrieve(ctx, req)
//	}
func SetupRAG(tb testing.TB, pool *pgxpool.Pool) *RAGSetup {
	tb.Helper()

	// Check for API key (SetupGoogleAI skips test if not set)
	// We don't use the returned setup because we need to create a
	// Genkit instance with both GoogleAI and PostgreSQL plugins
	_ = SetupGoogleAI(tb)

	ctx := context.Background()

	// Create PostgreSQL engine wrapping the test pool
	pEngine, err := postgresql.NewPostgresEngine(ctx,
		postgresql.WithPool(pool),
		postgresql.WithDatabase("koopa_test"),
	)
	if err != nil {
		tb.Fatalf("Failed to create PostgresEngine: %v", err)
	}

	// Create PostgreSQL plugin
	postgres := &postgresql.Postgres{Engine: pEngine}

	// Re-initialize Genkit with both plugins
	// We need to create a new Genkit instance that has both plugins
	projectRoot, err := findProjectRoot()
	if err != nil {
		tb.Fatalf("Failed to find project root: %v", err)
	}

	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
		genkit.WithPromptDir(projectRoot+"/prompts"),
	)
	if g == nil {
		tb.Fatal("Failed to initialize Genkit with PostgreSQL plugin")
	}

	// Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, config.DefaultEmbedderModel)
	if embedder == nil {
		tb.Fatalf("Failed to create embedder for model %q", config.DefaultEmbedderModel)
	}

	// Create DocStore and Retriever using shared config factory
	cfg := rag.NewDocStoreConfig(embedder)
	docStore, retriever, err := postgresql.DefineRetriever(ctx, g, postgres, cfg)
	if err != nil {
		tb.Fatalf("Failed to define retriever: %v", err)
	}

	return &RAGSetup{
		Genkit:    g,
		Embedder:  embedder,
		DocStore:  docStore,
		Retriever: retriever,
	}
}
