package agent

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/testutil"
)

// TestAgentFramework provides a complete test environment for Agent integration tests.
//
// Includes all components needed for full-stack agent testing:
//   - PostgreSQL database with test data
//   - Genkit AI framework
//   - Knowledge store with embeddings
//   - Session management
//   - Configured Agent instance
//
// Usage:
//
//	framework, cleanup := SetupTestAgent(t)
//	defer cleanup()
//	resp, err := framework.Agent.Execute(ctx, "test query")
type TestAgentFramework struct {
	// Database
	DBContainer *testutil.TestDBContainer

	// Core components
	Agent          *Agent
	KnowledgeStore *knowledge.Store
	SystemIndexer  *knowledge.SystemKnowledgeIndexer
	SessionStore   *session.Store
	Genkit         *genkit.Genkit
	Embedder       ai.Embedder
	Retriever      ai.Retriever
	Config         *config.Config

	// Test session
	SessionID uuid.UUID

	// Cleanup function
	cleanup func()
}

// SetupTestAgent creates a complete Agent test environment with testcontainers.
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - Docker daemon must be running (for testcontainers)
//
// Creates:
//  1. PostgreSQL container with pgvector
//  2. Genkit instance with Google AI plugin
//  3. Embedder for vector operations
//  4. Knowledge store for RAG
//  5. Session store for conversation persistence
//  6. Fully configured Agent instance
//
// Returns:
//   - TestAgentFramework: Complete test environment
//   - cleanup function: Must be called to terminate containers
//
// Example:
//
//	func TestAgentFeature(t *testing.T) {
//	    framework, cleanup := SetupTestAgent(t)
//	    defer cleanup()
//
//	    resp, err := framework.Agent.Execute(ctx, "What is Go?")
//	    require.NoError(t, err)
//	    assert.NotEmpty(t, resp.FinalText)
//	}
func SetupTestAgent(t *testing.T) (*TestAgentFramework, func()) {
	t.Helper()

	// Check for required API key
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()

	// 1. Setup test database using testutil
	dbContainer, dbCleanup := testutil.SetupTestDB(t)

	// 2. Setup embedder using testutil
	embedder, g := testutil.SetupEmbedder(t)

	// 3. Create knowledge store
	knowledgeStore := knowledge.New(dbContainer.Pool, embedder, slog.Default())

	// 4. Create system knowledge indexer
	systemIndexer := knowledge.NewSystemKnowledgeIndexer(knowledgeStore, slog.Default())

	// 5. Create config
	cfg := &config.Config{
		ModelName:        "gemini-2.5-flash",
		EmbedderModel:    "text-embedding-004",
		Temperature:      0.7,
		MaxTokens:        8192,
		RAGTopK:          5,
		PostgresHost:     "localhost",
		PostgresPort:     5432,
		PostgresUser:     "koopa_test",
		PostgresPassword: "test_password",
		PostgresDBName:   "koopa_test",
		PostgresSSLMode:  "disable",
		MaxTurns:         10,
		Language:         "English",
	}

	// 6. Create session store
	sessionStore := session.New(dbContainer.Pool, slog.Default())

	// 7. Create test session
	testSession, err := sessionStore.CreateSession(ctx, "Integration Test Session", cfg.ModelName, "")
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create test session: %v", err)
	}
	sessionID := testSession.ID

	// 8. Create retriever for RAG
	retrieverBuilder := rag.New(knowledgeStore)
	retriever := retrieverBuilder.DefineConversation(g, "integration-test-retriever")

	// 9. Create Agent
	agent, err := New(ctx, cfg, g, retriever,
		WithSessionStore(sessionStore),
		WithKnowledgeStore(knowledgeStore),
		WithLogger(slog.Default()),
	)
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create agent: %v", err)
	}

	// 10. Switch to test session to ensure Agent state is synced
	if err := agent.SwitchSession(ctx, sessionID); err != nil {
		dbCleanup()
		t.Fatalf("Failed to switch to test session: %v", err)
	}

	framework := &TestAgentFramework{
		DBContainer:    dbContainer,
		Agent:          agent,
		KnowledgeStore: knowledgeStore,
		SystemIndexer:  systemIndexer,
		SessionStore:   sessionStore,
		Genkit:         g,
		Embedder:       embedder,
		Retriever:      retriever,
		Config:         cfg,
		SessionID:      sessionID,
		cleanup:        dbCleanup,
	}

	cleanup := func() {
		dbCleanup()
	}

	return framework, cleanup
}

// IndexSystemKnowledge indexes system knowledge for testing.
//
// Indexes all 6 system knowledge documents (coding standards, error handling, etc.)
// into the knowledge store for RAG testing.
//
// Example:
//
//	framework, cleanup := SetupTestAgent(t)
//	defer cleanup()
//	framework.IndexSystemKnowledge(t)
//	// Now system knowledge is available for RAG queries
func (f *TestAgentFramework) IndexSystemKnowledge(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	count, err := f.SystemIndexer.IndexAll(ctx)
	if err != nil {
		t.Fatalf("Failed to index system knowledge: %v", err)
	}
	t.Logf("Indexed %d system knowledge documents", count)
}
