//go:build integration
// +build integration

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/testutil"
	"github.com/koopa0/koopa/internal/tui"
)

// setupApp is a test helper that creates an App instance.
func setupApp(t *testing.T) *app.App {
	t.Helper()

	chat.ResetFlowForTesting()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}

	projectRoot, err := testutil.FindProjectRoot()
	if err != nil {
		t.Fatalf("testutil.FindProjectRoot() error: %v", err)
	}
	cfg.PromptDir = filepath.Join(projectRoot, "prompts")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	a, err := app.Setup(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("app.Setup() error: %v", err)
	}

	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Logf("app close error: %v", err)
		}
		cancel()
	})

	return a
}

// TestTUI_Integration tests the TUI can be created with real dependencies.
// Note: Bubble Tea TUI cannot be fully tested without a real TTY.
// These tests verify initialization and component wiring.
func TestTUI_Integration(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	a := setupApp(t)

	agent, err := a.CreateAgent()
	if err != nil {
		t.Fatalf("CreateAgent() error: %v", err)
	}

	flow := chat.NewFlow(a.Genkit, agent)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tuiModel, err := tui.New(ctx, flow, uuid.New())
	if err != nil {
		t.Fatalf("tui.New() error: %v", err)
	}

	cmd := tuiModel.Init()
	if cmd == nil {
		t.Error("Init should return a command (blink + spinner)")
	}
}
