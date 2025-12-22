package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	tea "charm.land/bubbletea/v2"

	"github.com/koopa0/koopa/internal/app"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/tui"
)

// runCLI initializes and starts the interactive CLI with Bubble Tea TUI.
func runCLI() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runtime, err := app.NewRuntime(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize runtime: %w", err)
	}
	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			slog.Warn("runtime close error", "error", closeErr)
		}
	}()

	sessionID, err := getOrCreateSessionID(ctx, runtime.App.SessionStore, cfg)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	model, err := tui.New(ctx, runtime.Flow, sessionID)
	if err != nil {
		return fmt.Errorf("failed to create TUI: %w", err)
	}
	program := tea.NewProgram(model, tea.WithContext(ctx))

	if _, err = program.Run(); err != nil {
		return fmt.Errorf("TUI exited: %w", err)
	}
	return nil
}

// getOrCreateSessionID returns a valid session ID, creating a new session if needed.
func getOrCreateSessionID(ctx context.Context, store *session.Store, cfg *config.Config) (string, error) {
	currentID, err := session.LoadCurrentSessionID()
	if err != nil {
		return "", fmt.Errorf("failed to load session: %w", err)
	}

	if currentID != nil {
		if _, err = store.GetSession(ctx, *currentID); err == nil {
			return currentID.String(), nil
		}
		if !errors.Is(err, session.ErrSessionNotFound) {
			return "", fmt.Errorf("failed to validate session: %w", err)
		}
	}

	newSess, err := store.CreateSession(ctx, "New Session", cfg.ModelName, "You are a helpful assistant.")
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	if err := session.SaveCurrentSessionID(newSess.ID); err != nil {
		slog.Warn("failed to save session state", "error", err)
	}

	return newSess.ID.String(), nil
}
