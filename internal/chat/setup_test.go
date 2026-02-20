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
	"fmt"
	"log"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/google/uuid"

	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/memory"
	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
	"github.com/koopa0/koopa/internal/tools"
)

var sharedDB *testutil.TestDBContainer

func TestMain(m *testing.M) {
	// All chat integration tests require GEMINI_API_KEY.
	if os.Getenv("GEMINI_API_KEY") == "" {
		fmt.Println("GEMINI_API_KEY not set - skipping chat integration tests")
		os.Exit(0)
	}

	var cleanup func()
	var err error
	sharedDB, cleanup, err = testutil.SetupTestDBForMain()
	if err != nil {
		log.Fatalf("starting test database: %v", err)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

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
	MemoryStore  *memory.Store
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
//   - GEMINI_API_KEY environment variable must be set (checked in TestMain)
//   - Docker daemon must be running (shared container started in TestMain)
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

	ctx := context.Background()

	// Clean tables for test isolation using the shared container.
	testutil.CleanTables(t, sharedDB.Pool)

	// Setup RAG with Genkit PostgreSQL plugin (uses shared pool).
	// Each test gets a fresh Genkit instance because Genkit has
	// global state (registered flows, tools) that cannot be shared safely.
	ragSetup := testutil.SetupRAG(t, sharedDB.Pool)

	// Layer 2: Build chat-specific dependencies
	queries := sqlc.New(sharedDB.Pool)
	sessionStore := session.New(queries, sharedDB.Pool, slog.Default())

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
	testSession, err := sessionStore.CreateSession(ctx, "test-user", "Chat Integration Test")
	if err != nil {
		t.Fatalf("creating test session: %v", err)
	}

	// Create toolsets
	pathValidator, err := security.NewPath([]string{os.TempDir()}, nil)
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

	// Create Memory Store (uses shared pool and embedder from RAG)
	memoryStore, err := memory.NewStore(sharedDB.Pool, ragSetup.Embedder, slog.Default())
	if err != nil {
		t.Fatalf("creating memory store: %v", err)
	}

	// Create Chat Agent
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait) // Wait for background goroutines on test cleanup
	chatAgent, err := chat.New(chat.Config{
		Genkit:       ragSetup.Genkit,
		SessionStore: sessionStore,
		MemoryStore:  memoryStore,
		Logger:       slog.Default(),
		Tools:        fileTools,
		ModelName:    cfg.ModelName,
		MaxTurns:     cfg.MaxTurns,
		Language:     cfg.Language,
		WG:           &wg,
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
		MemoryStore:  memoryStore,
		Config:       cfg,
		DBContainer:  sharedDB,
		Genkit:       ragSetup.Genkit,
		Embedder:     ragSetup.Embedder,
		SessionID:    testSession.ID,
	}
}

// CreateTestSession creates a new isolated session for test isolation.
func (f *TestFramework) CreateTestSession(t *testing.T, name string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	sess, err := f.SessionStore.CreateSession(ctx, "test-user", name)
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
