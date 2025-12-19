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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/firebase/genkit/go/plugins/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/tools"
)

// chatFlowSetup contains all resources needed for chat flow integration tests.
type chatFlowSetup struct {
	Flow         *chat.Flow
	Genkit       *genkit.Genkit
	SessionStore *session.Store
	Ctx          context.Context
	Cancel       context.CancelFunc
}

// findProjectRoot finds the project root directory by looking for go.mod.
func findProjectRoot() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed to get caller info")
	}

	dir := filepath.Dir(filename)
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found in any parent directory of %s", filename)
		}
		dir = parent
	}
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
//	    tui := New(setup.Ctx, setup.Flow, "test-session-id")
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

	projectRoot, err := findProjectRoot()
	if err != nil || projectRoot == "" {
		cancel()
		t.Fatalf("Failed to find project root: %v", err)
	}
	promptsDir := filepath.Join(projectRoot, "prompts")

	// Create database pool
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		cancel()
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Create PostgreSQL engine for Genkit
	pEngine, err := postgresql.NewPostgresEngine(ctx,
		postgresql.WithPool(pool),
		postgresql.WithDatabase("koopa_test"),
	)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create PostgresEngine: %v", err)
	}

	postgres := &postgresql.Postgres{Engine: pEngine}

	// Initialize Genkit with both GoogleAI and PostgreSQL plugins
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
		genkit.WithPromptDir(promptsDir))

	if g == nil {
		pool.Close()
		cancel()
		t.Fatal("Failed to initialize Genkit")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := &config.Config{
		ModelName:     "gemini-2.0-flash",
		EmbedderModel: "text-embedding-004",
		RAGTopK:       5,
		MaxTurns:      10,
	}

	// Create embedder
	embedder := googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)
	if embedder == nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create embedder for model %q", cfg.EmbedderModel)
	}

	// Create DocStore and Retriever using shared config factory
	ragCfg := rag.NewDocStoreConfig(embedder)
	_, retriever, err := postgresql.DefineRetriever(ctx, g, postgres, ragCfg)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to define retriever: %v", err)
	}

	queries := sqlc.New(pool)
	sessionStore := session.New(queries, pool, logger)

	pathValidator, err := security.NewPath([]string{"."})
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create path validator: %v", err)
	}

	// Register file tools
	fileTools, err := tools.RegisterFileTools(g, pathValidator, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to register file tools: %v", err)
	}

	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	systemTools, err := tools.RegisterSystemTools(g, cmdValidator, envValidator, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to register system tools: %v", err)
	}

	knowledgeTools, err := tools.RegisterKnowledgeTools(g, retriever, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to register knowledge tools: %v", err)
	}

	// Combine all tools
	allTools := append(append(fileTools, systemTools...), knowledgeTools...)

	chatAgent, err := chat.New(chat.Deps{
		Config:       cfg,
		Genkit:       g,
		Retriever:    retriever,
		SessionStore: sessionStore,
		Logger:       logger,
		Tools:        allTools,
	})
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create chat agent: %v", err)
	}

	// Initialize Flow singleton (reset first for test isolation)
	chat.ResetFlowForTesting()
	flow, err := chat.InitFlow(g, chatAgent)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to init chat flow: %v", err)
	}

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
