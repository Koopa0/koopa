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
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/agent/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
	"github.com/koopa0/koopa/internal/tools"
)

// TestFramework provides a complete test environment for handler integration tests.
// This is the handler-specific equivalent of testutil.AgentTestFramework.
type TestFramework struct {
	// Handler dependencies
	Flow         *chat.Flow
	SessionStore *session.Store
	DocStore     *postgresql.DocStore // For indexing documents in tests

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

	// Setup RAG with Genkit PostgreSQL plugin
	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)

	// Layer 2: Build handler-specific dependencies
	queries := sqlc.New(dbContainer.Pool)
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

	// Create toolsets
	pathValidator, err := security.NewPath([]string{os.TempDir()})
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create path validator: %v", err)
	}

	// Create and register file tools
	fileTools, err := tools.NewFileTools(pathValidator, slog.Default())
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create file tools: %v", err)
	}

	registeredTools, err := tools.RegisterFileTools(ragSetup.Genkit, fileTools)
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to register file tools: %v", err)
	}

	// Create Chat Agent (needed to get Flow)
	chatAgent, err := chat.New(chat.Config{
		Genkit:       ragSetup.Genkit,
		Retriever:    ragSetup.Retriever,
		SessionStore: sessionStore,
		Logger:       slog.Default(),
		Tools:        registeredTools,
		MaxTurns:     cfg.MaxTurns,
		RAGTopK:      cfg.RAGTopK,
		Language:     cfg.Language,
	})
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create chat agent: %v", err)
	}

	// Initialize Flow singleton (reset first for test isolation)
	chat.ResetFlowForTesting()
	flow, err := chat.InitFlow(ragSetup.Genkit, chatAgent)
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to init chat flow: %v", err)
	}

	framework := &TestFramework{
		Flow:         flow,
		SessionStore: sessionStore,
		DocStore:     ragSetup.DocStore,
		DBContainer:  dbContainer,
		Genkit:       ragSetup.Genkit,
		Embedder:     ragSetup.Embedder,
		Config:       cfg,
		SessionID:    testSession.ID,
		cleanup:      dbCleanup,
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
