//go:build integration
// +build integration

// Package chat_test provides test fixtures for chat agent integration tests.
//
// It uses testutil primitives (Layer 1) to build chat-specific test fixtures (Layer 2).
//
// Benefits over testutil.AgentTestFramework:
// - No circular dependency risk
// - Chat package controls its own test setup
// - Can evolve independently without affecting other packages
package chat_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/google/uuid"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
	"github.com/koopa0/koopa-cli/internal/tools"
)

// TestFramework provides a complete test environment for chat integration tests.
// This is the chat-specific equivalent of testutil.AgentTestFramework.
type TestFramework struct {
	// Core components
	Agent          *chat.Chat
	Flow           *chat.Flow
	KnowledgeStore *knowledge.Store
	SystemIndexer  *knowledge.SystemKnowledgeIndexer
	SessionStore   *session.Store
	Retriever      *rag.Retriever
	Config         *config.Config

	// Infrastructure
	DBContainer *testutil.TestDBContainer
	Genkit      *genkit.Genkit
	Embedder    ai.Embedder

	// Test session (fresh per framework instance)
	SessionID uuid.UUID

	cleanup func()
}

// SetupTest creates a complete chat test environment.
//
// This function assembles all dependencies needed for chat agent testing
// using testutil primitives. It's the canonical way to set up chat integration tests.
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - Docker daemon must be running (for testcontainers)
//
// Example:
//
//	func TestChatFeature(t *testing.T) {
//	    framework, cleanup := SetupTest(t)
//	    defer cleanup()
//
//	    resp, err := framework.Agent.Execute(ctx, "test query")
//	}
func SetupTest(t *testing.T) (*TestFramework, func()) {
	t.Helper()

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()

	// Layer 1: Use testutil primitives
	dbContainer, dbCleanup := testutil.SetupTestDB(t)
	aiSetup := testutil.SetupGoogleAI(t)

	// Layer 2: Build chat-specific dependencies
	queries := sqlc.New(dbContainer.Pool)
	knowledgeStore := knowledge.New(queries, aiSetup.Embedder, aiSetup.Logger)
	sessionStore := session.New(queries, dbContainer.Pool, slog.Default())
	systemIndexer := knowledge.NewSystemKnowledgeIndexer(knowledgeStore, slog.Default())

	cfg := &config.Config{
		ModelName:        "googleai/gemini-2.5-flash",
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

	// Create test session
	testSession, err := sessionStore.CreateSession(ctx, "Chat Integration Test", cfg.ModelName, "")
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Create retriever
	retriever := rag.New(knowledgeStore)
	if err := retriever.DefineConversation(aiSetup.Genkit, "chat-test-retriever"); err != nil {
		dbCleanup()
		t.Fatalf("Failed to define retriever: %v", err)
	}

	// Create toolsets
	pathValidator, err := security.NewPath([]string{os.TempDir()})
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create path validator: %v", err)
	}
	fileToolset, err := tools.NewFileToolset(pathValidator, slog.Default())
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create file toolset: %v", err)
	}

	// Create Chat Agent
	chatAgent, err := chat.New(chat.Deps{
		Config:         cfg,
		Genkit:         aiSetup.Genkit,
		Retriever:      retriever,
		SessionStore:   sessionStore,
		KnowledgeStore: knowledgeStore,
		Logger:         slog.Default(),
		Toolsets:       []tools.Toolset{fileToolset},
	})
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create chat agent: %v", err)
	}

	// Get Flow singleton
	flow := chat.GetFlow(aiSetup.Genkit, chatAgent)

	framework := &TestFramework{
		Agent:          chatAgent,
		Flow:           flow,
		KnowledgeStore: knowledgeStore,
		SystemIndexer:  systemIndexer,
		SessionStore:   sessionStore,
		Retriever:      retriever,
		Config:         cfg,
		DBContainer:    dbContainer,
		Genkit:         aiSetup.Genkit,
		Embedder:       aiSetup.Embedder,
		SessionID:      testSession.ID,
		cleanup:        dbCleanup,
	}

	return framework, dbCleanup
}

// CreateTestSession creates a new isolated session for test isolation.
func (f *TestFramework) CreateTestSession(t *testing.T, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sess, err := f.SessionStore.CreateSession(ctx, name, f.Config.ModelName, "")
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}
	return sess.ID
}

// IndexSystemKnowledge indexes system knowledge for RAG testing.
func (f *TestFramework) IndexSystemKnowledge(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	count, err := f.SystemIndexer.IndexAll(ctx)
	if err != nil {
		t.Fatalf("Failed to index system knowledge: %v", err)
	}
	t.Logf("Indexed %d system knowledge documents", count)
}
