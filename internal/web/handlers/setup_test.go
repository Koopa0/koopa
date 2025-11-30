//go:build integration

// Package handlers_test provides test fixtures for web handler integration tests.
//
// It uses testutil primitives (Layer 1) to build handler-specific test fixtures (Layer 2).
//
// Benefits over testutil.AgentTestFramework:
// - No circular dependency risk
// - Handlers package controls its own test setup
// - Can evolve independently without affecting other packages
package handlers_test

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

// TestFramework provides a complete test environment for handler integration tests.
// This is the handler-specific equivalent of testutil.AgentTestFramework.
type TestFramework struct {
	// Handler dependencies
	Flow           *chat.Flow
	SessionStore   *session.Store
	KnowledgeStore *knowledge.Store

	// Infrastructure
	DBContainer *testutil.TestDBContainer
	Genkit      *genkit.Genkit
	Embedder    ai.Embedder
	Config      *config.Config

	// Test session
	SessionID uuid.UUID

	cleanup func()
}

// SetupTest creates a complete handler test environment.
//
// This function assembles all dependencies needed for handler testing
// using testutil primitives. It's the canonical way to set up handler integration tests.
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - Docker daemon must be running (for testcontainers)
//
// Example:
//
//	func TestChatHandler(t *testing.T) {
//	    framework, cleanup := SetupTest(t)
//	    defer cleanup()
//
//	    handler := handlers.NewChat(testutil.DiscardLogger(), framework.Flow)
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

	// Layer 2: Build handler-specific dependencies
	queries := sqlc.New(dbContainer.Pool)
	knowledgeStore := knowledge.New(queries, aiSetup.Embedder, aiSetup.Logger)
	sessionStore := session.New(queries, dbContainer.Pool, slog.Default())

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
	testSession, err := sessionStore.CreateSession(ctx, "Handler Integration Test", cfg.ModelName, "")
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Create retriever (required for chat agent)
	retriever := rag.New(knowledgeStore)
	_ = retriever.DefineConversation(aiSetup.Genkit, "handler-test-retriever")

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

	// Create Chat Agent (needed to get Flow)
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

	// Get Flow singleton (this is what handlers need)
	flow := chat.GetFlow(aiSetup.Genkit, chatAgent)

	framework := &TestFramework{
		Flow:           flow,
		SessionStore:   sessionStore,
		KnowledgeStore: knowledgeStore,
		DBContainer:    dbContainer,
		Genkit:         aiSetup.Genkit,
		Embedder:       aiSetup.Embedder,
		Config:         cfg,
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
