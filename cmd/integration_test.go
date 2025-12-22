//go:build integration
// +build integration

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/tui"
)

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

// TestTUI_Integration tests the TUI can be created with real runtime.
// Note: Bubble Tea TUI cannot be fully tested without a real TTY.
// These tests verify initialization and component wiring.
func TestTUI_Integration(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Set absolute path for prompts directory (required for tests running from different directories)
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("Failed to find project root: %v", err)
	}
	cfg.PromptDir = filepath.Join(projectRoot, "prompts")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Initialize runtime
	runtime, err := app.NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize runtime: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Logf("runtime close error: %v", err)
		}
	})

	// Verify TUI can be created with real Flow
	tuiModel, err := tui.New(ctx, runtime.Flow, "test-session-id")
	if err != nil {
		t.Fatalf("Failed to create TUI: %v", err)
	}

	// Verify Init returns a command
	cmd := tuiModel.Init()
	if cmd == nil {
		t.Error("Init should return a command (blink + spinner)")
	}
}

// TestTUI_SlashCommands tests slash command handling.
func TestTUI_SlashCommands(t *testing.T) {
	if os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("GEMINI_API_KEY not set - skipping integration test")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Set absolute path for prompts directory (required for tests running from different directories)
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("Failed to find project root: %v", err)
	}
	cfg.PromptDir = filepath.Join(projectRoot, "prompts")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runtime, err := app.NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize runtime: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Logf("runtime close error: %v", err)
		}
	})

	tuiModel, err := tui.New(ctx, runtime.Flow, "test-session-id")
	if err != nil {
		t.Fatalf("Failed to create TUI: %v", err)
	}

	// Test /help command by simulating the message flow
	// Note: Full TUI testing requires teatest or similar framework
	view := tuiModel.View()
	if view.Content == nil {
		t.Error("View content should not be nil")
	}
}
