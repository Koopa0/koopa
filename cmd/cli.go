package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	tea "charm.land/bubbletea/v2"

	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/tui"
)

// runCLI initializes and starts the interactive CLI with Bubble Tea TUI.
func runCLI() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	a, err := app.Setup(ctx, cfg)
	if err != nil {
		return fmt.Errorf("initializing application: %w", err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			slog.Warn("shutdown error", "error", closeErr)
		}
	}()

	agent, err := a.CreateAgent()
	if err != nil {
		return fmt.Errorf("creating agent: %w", err)
	}

	flow := chat.NewFlow(a.Genkit, agent)

	sessionID, err := a.SessionStore.ResolveCurrentSession(ctx)
	if err != nil {
		return fmt.Errorf("resolving session: %w", err)
	}

	model, err := tui.New(ctx, flow, sessionID)
	if err != nil {
		return fmt.Errorf("creating TUI: %w", err)
	}
	program := tea.NewProgram(model, tea.WithContext(ctx))

	if _, err = program.Run(); err != nil {
		return fmt.Errorf("running TUI: %w", err)
	}
	return nil
}
