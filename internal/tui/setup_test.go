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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/knowledge"
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

	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir(promptsDir))

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := &config.Config{
		ModelName:     "gemini-2.0-flash",
		EmbedderModel: "text-embedding-004",
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		cancel()
		t.Fatalf("Failed to connect to database: %v", err)
	}

	queries := sqlc.New(pool)
	sessionStore := session.New(queries, pool, logger)
	knowledgeStore := knowledge.New(queries, googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel), logger)
	retriever := rag.New(knowledgeStore)

	pathValidator, err := security.NewPath([]string{"."})
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create path validator: %v", err)
	}

	fileToolset, err := tools.NewFileToolset(pathValidator, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create file toolset: %v", err)
	}

	cmdValidator := security.NewCommand()
	envValidator := security.NewEnv()
	systemToolset, err := tools.NewSystemToolset(cmdValidator, envValidator, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create system toolset: %v", err)
	}

	knowledgeToolset, err := tools.NewKnowledgeToolset(knowledgeStore, logger)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create knowledge toolset: %v", err)
	}

	chatAgent, err := chat.New(chat.Deps{
		Config:         cfg,
		Genkit:         g,
		Retriever:      retriever,
		SessionStore:   sessionStore,
		KnowledgeStore: knowledgeStore,
		Logger:         logger,
		Toolsets:       []tools.Toolset{fileToolset, systemToolset, knowledgeToolset},
	})
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("Failed to create chat agent: %v", err)
	}

	flow := chat.GetFlow(g, chatAgent)

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
