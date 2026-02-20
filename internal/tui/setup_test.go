//go:build integration

// Package tui_test provides test fixtures for TUI integration tests.
//
// It uses testutil primitives (Layer 1) to build TUI-specific test fixtures (Layer 2).
//
// Benefits over inline setup in integration_test.go:
// - Separates test setup from test logic (Layer 2 vs Layer 3)
// - Reusable across multiple TUI integration tests
// - Follows same pattern as ui/web/handlers/setup_test.go
package tui

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/rag"
	"github.com/koopa0/koopa/internal/security"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
	"github.com/koopa0/koopa/internal/tools"
)

// chatFlowSetup contains all resources needed for chat flow integration tests.
type chatFlowSetup struct {
	Flow         *chat.Flow
	Genkit       *genkit.Genkit
	SessionStore *session.Store
	Ctx          context.Context
	Cancel       context.CancelFunc
}

// setupChatFlow creates a complete chat flow setup for integration testing.
//
// This function assembles all dependencies needed for TUI integration tests.
// It's the canonical way to set up TUI tests that need a full chat flow.
//
// Requirements:
//   - GEMINI_API_KEY environment variable must be set
//   - DATABASE_URL environment variable must be set
//   - Timeout is set to 120 seconds for long-running tests
//
// Example:
//
//	func TestTUIChat(t *testing.T) {
//	    setup, cleanup := setupChatFlow(t)
//	    defer cleanup()
//
//	    sessionID, cleanup := createTestSession(t, setup)
//	    defer cleanup()
//	    tui := New(setup.Ctx, setup.Flow, sessionID)
//	}
func setupChatFlow(t *testing.T) (*chatFlowSetup, func()) {
	t.Helper()

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set - skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)

	projectRoot, err := testutil.FindProjectRoot()
	if err != nil || projectRoot == "" {
		cancel()
		t.Fatalf("FindProjectRoot() error: %v", err)
	}
	promptsDir := filepath.Join(projectRoot, "prompts")

	// Create database pool
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		cancel()
		t.Fatalf("pgxpool.New() error: %v", err)
	}

	// Create PostgreSQL engine for Genkit
	pEngine, err := postgresql.NewPostgresEngine(ctx,
		postgresql.WithPool(pool),
		postgresql.WithDatabase("koopa_test"),
	)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("NewPostgresEngine() error: %v", err)
	}

	postgres := &postgresql.Postgres{Engine: pEngine}

	// Initialize Genkit with both GoogleAI and PostgreSQL plugins
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
		genkit.WithPromptDir(promptsDir))

	if g == nil {
		pool.Close()
		cancel()
		t.Fatal("genkit.Init() returned nil")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := &config.Config{
		ModelName:     "gemini-2.0-flash",
		EmbedderModel: "gemini-embedding-001",
		MaxTurns:      10,
	}

	// Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)
	if embedder == nil {
		pool.Close()
		cancel()
		t.Fatalf("GoogleAIEmbedder(%q) returned nil", cfg.EmbedderModel)
	}

	// Create DocStore and Retriever using shared config factory
	ragCfg := rag.NewDocStoreConfig(embedder)
	_, retriever, err := postgresql.DefineRetriever(ctx, g, postgres, ragCfg)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("DefineRetriever() error: %v", err)
	}

	queries := sqlc.New(pool)
	sessionStore := session.New(queries, pool, logger)

	pathValidator, err := security.NewPath([]string{"."}, nil)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("NewPath() error: %v", err)
	}

	// Create and register file tools
	ft, err := tools.NewFile(pathValidator, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("NewFile() error: %v", err)
	}
	fileTools, err := tools.RegisterFile(g, ft)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("RegisterFile() error: %v", err)
	}

	// Create and register system tools
	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	st, err := tools.NewSystem(cmdValidator, envValidator, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("NewSystem() error: %v", err)
	}
	systemTools, err := tools.RegisterSystem(g, st)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("RegisterSystem() error: %v", err)
	}

	// Create and register knowledge tools
	kt, err := tools.NewKnowledge(retriever, nil, nil, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("NewKnowledge() error: %v", err)
	}
	knowledgeTools, err := tools.RegisterKnowledge(g, kt)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("RegisterKnowledge() error: %v", err)
	}

	// Combine all tools
	allTools := append(append(fileTools, systemTools...), knowledgeTools...)

	chatAgent, err := chat.New(chat.Config{
		Genkit:       g,
		SessionStore: sessionStore,
		Logger:       logger,
		Tools:        allTools,
		MaxTurns:     cfg.MaxTurns,
	})
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("chat.New() error: %v", err)
	}

	// Initialize Flow singleton (reset first for test isolation)
	chat.ResetFlowForTesting()
	flow := chat.NewFlow(g, chatAgent)

	setup := &chatFlowSetup{
		Flow:         flow,
		Genkit:       g,
		SessionStore: sessionStore,
		Ctx:          ctx,
		Cancel:       cancel,
	}

	cleanup := func() {
		pool.Close()
		cancel()
	}

	return setup, cleanup
}
