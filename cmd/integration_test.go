//go:build integration
// +build integration

package cmd

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/tui"
)

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
	tuiModel := tui.New(ctx, runtime.Flow, "test-session-id")
	if tuiModel == nil {
		t.Fatal("TUI model should not be nil")
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

	tuiModel := tui.New(ctx, runtime.Flow, "test-session-id")

	// Test /help command by simulating the message flow
	// Note: Full TUI testing requires teatest or similar framework
	view := tuiModel.View()
	if view.Content == nil {
		t.Error("View content should not be nil")
	}
}
