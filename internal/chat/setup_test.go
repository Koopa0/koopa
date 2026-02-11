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
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
	"github.com/koopa0/koopa/internal/tools"
)

// TestFramework provides a complete test environment for chat integration tests.
// This is the chat-specific equivalent of testutil.AgentTestFramework.
// Cleanup is automatic via tb.Cleanup — no manual cleanup needed.
type TestFramework struct {
	// Core components
	Agent        *chat.Agent
	Flow         *chat.Flow
	DocStore     *postgresql.DocStore // For indexing documents in tests
	Retriever    ai.Retriever         // Genkit Retriever for RAG
	SessionStore *session.Store
	Config       *config.Config

	// Infrastructure
	DBContainer *testutil.TestDBContainer
	Genkit      *genkit.Genkit
	Embedder    ai.Embedder

	// Test session (fresh per framework instance)
	SessionID uuid.UUID
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
//	    framework := SetupTest(t)
//
//	    ctx, sessionID := newInvocationContext(context.Background(), framework.SessionID)
//	    resp, err := framework.Agent.Execute(ctx, sessionID, "test query")
//	}
func SetupTest(t *testing.T) *TestFramework {
	t.Helper()

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	ctx := context.Background()

	// Layer 1: Use testutil primitives (cleanup is automatic via tb.Cleanup)
	dbContainer := testutil.SetupTestDB(t)

	// Setup RAG with Genkit PostgreSQL plugin
	ragSetup := testutil.SetupRAG(t, dbContainer.Pool)

	// Layer 2: Build chat-specific dependencies
	queries := sqlc.New(dbContainer.Pool)
	sessionStore := session.New(queries, dbContainer.Pool, slog.Default())

	cfg := &config.Config{
		ModelName:        "googleai/gemini-2.5-flash",
		EmbedderModel:    "gemini-embedding-001",
		Temperature:      0.7,
		MaxTokens:        8192,
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
	testSession, err := sessionStore.CreateSession(ctx, "Chat Integration Test")
	if err != nil {
		t.Fatalf("creating test session: %v", err)
	}

	// Create toolsets
	pathValidator, err := security.NewPath([]string{os.TempDir()})
	if err != nil {
		t.Fatalf("creating path validator: %v", err)
	}

	// Create file tools instance
	fileToolset, err := tools.NewFile(pathValidator, slog.Default())
	if err != nil {
		t.Fatalf("creating file tools: %v", err)
	}

	// Register file tools with Genkit
	fileTools, err := tools.RegisterFile(ragSetup.Genkit, fileToolset)
	if err != nil {
		t.Fatalf("registering file tools: %v", err)
	}

	// Create Chat Agent
	chatAgent, err := chat.New(chat.Config{
		Genkit:       ragSetup.Genkit,
		SessionStore: sessionStore,
		Logger:       slog.Default(),
		Tools:        fileTools,
		MaxTurns:     cfg.MaxTurns,
		Language:     cfg.Language,
	})
	if err != nil {
		t.Fatalf("creating chat agent: %v", err)
	}

	// Initialize Flow singleton (reset first for test isolation)
	chat.ResetFlowForTesting()
	flow := chat.NewFlow(ragSetup.Genkit, chatAgent)

	return &TestFramework{
		Agent:        chatAgent,
		Flow:         flow,
		DocStore:     ragSetup.DocStore,
		Retriever:    ragSetup.Retriever,
		SessionStore: sessionStore,
		Config:       cfg,
		DBContainer:  dbContainer,
		Genkit:       ragSetup.Genkit,
		Embedder:     ragSetup.Embedder,
		SessionID:    testSession.ID,
	}
}

// CreateTestSession creates a new isolated session for test isolation.
func (f *TestFramework) CreateTestSession(t *testing.T, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sess, err := f.SessionStore.CreateSession(ctx, name)
	if err != nil {
		t.Fatalf("creating test session: %v", err)
	}
	return sess.ID
}

// IndexDocument indexes a document using the Genkit DocStore.
// This is a test helper for adding documents to the RAG knowledge base.
func (f *TestFramework) IndexDocument(t *testing.T, content string, metadata map[string]any) {
	t.Helper()
	ctx := context.Background()

	// Ensure source_type is set
	if metadata == nil {
		metadata = make(map[string]any)
	}
	if _, ok := metadata["source_type"]; !ok {
		metadata["source_type"] = rag.SourceTypeFile
	}

	doc := ai.DocumentFromText(content, metadata)
	if err := f.DocStore.Index(ctx, []*ai.Document{doc}); err != nil {
		t.Fatalf("indexing document: %v", err)
	}
}
