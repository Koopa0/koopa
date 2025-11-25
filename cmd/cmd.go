package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/agent/chat"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/ui"
)

// Run starts the interactive chat mode
func Run(ctx context.Context, cfg *config.Config, version string, term ui.IO) error {
	// Create cancellable context for this session
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Initialize application using Wire DI
	application, cleanup, err := app.InitializeApp(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	defer cleanup()
	defer func() {
		if err := application.Close(); err != nil {
			slog.Warn("failed to close application", "error", err)
		}
	}()

	// Create retriever for documents
	ret := rag.New(application.Knowledge)
	_ = ret.DefineDocument(application.Genkit, "documents")

	// Create Chat Agent
	chatAgent, err := application.CreateAgent(ctx, ret)
	if err != nil {
		return fmt.Errorf("error creating agent: %w", err)
	}

	// Define Flow for the agent (provides observability and structured I/O)
	chatAgent.DefineFlow(application.Genkit)

	// Display welcome message
	printWelcome(version, term)

	// Start conversation loop
	for {
		term.Print("> ")

		// Read user input
		if !term.Scan() {
			// EOF (Ctrl+D) or error
			term.Println("\nGoodbye!")
			break
		}

		input := strings.TrimSpace(term.Text())
		if input == "" {
			continue
		}

		// Handle slash commands
		if strings.HasPrefix(input, "/") {
			if shouldExit := handleSlashCommand(ctx, input, application, term); shouldExit {
				break
			}
			continue
		}

		// Send message to AI
		term.Print("Koopa> ")

		// Get current session ID
		var sessionIDStr string
		currentSessionID, err := session.LoadCurrentSessionID()
		if err != nil {
			slog.Error("failed to load session", "error", err)
			term.Printf("Error: %v\n", err)
			continue
		}
		if currentSessionID != nil {
			sessionIDStr = currentSessionID.String()
		} else {
			// Create a new session if none exists
			newSess, err := application.SessionStore.CreateSession(ctx, "New Session", cfg.ModelName, "You are a helpful assistant.")
			if err != nil {
				slog.Error("failed to create session", "error", err)
				term.Printf("Error: %v\n", err)
				continue
			}
			if err := session.SaveCurrentSessionID(newSess.ID); err != nil {
				slog.Warn("failed to save session state", "error", err)
			}
			sessionIDStr = newSess.ID.String()
			term.Printf("(Created new session: %s)\n", newSess.Title)
		}

		// Execute chat agent
		invocationID := uuid.New().String()
		sessionID, err := agent.NewSessionID(sessionIDStr)
		if err != nil {
			slog.Error("invalid session ID", "session_id", sessionIDStr, "error", err)
			term.Printf("Error: invalid session ID\n")
			continue
		}
		invCtx := agent.NewInvocationContext(
			ctx,
			invocationID,
			chat.Name,
			sessionID,
			chat.Name,
		)

		output, err := chatAgent.Execute(invCtx, input)
		if err != nil {
			slog.Error("chat execution failed", "error", err, "invocation_id", invocationID)
			term.Printf("Error: %v\n", err)
			term.Println()
			continue
		}

		// Display response
		if strings.TrimSpace(output.FinalText) == "" {
			term.Printf("Warning: Agent response is empty\n")
		} else {
			term.Println(output.FinalText)
		}
		term.Println()
	}

	return nil
}

// printWelcome displays the welcome message
func printWelcome(version string, term ui.IO) {
	term.Println("Koopa - Your terminal AI personal assistant")
	term.Printf("v%s\n", version)
	term.Println()
	term.Println("Tips for getting started:")
	term.Println("1. Ask questions, edit files, or run commands.")
	term.Println("2. Be specific for the best results.")
	term.Println("3. /help for more information.")
	term.Println()
}

// handleSlashCommand processes slash commands, returns true if should exit
func handleSlashCommand(ctx context.Context, cmd string, application *app.App, term ui.IO) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "/help":
		printInteractiveHelp(term)
		return false

	case "/version":
		term.Printf("Koopa v%s\n", AppVersion)
		term.Printf("Build: %s\n", BuildTime)
		term.Printf("Commit: %s\n", GitCommit)
		term.Println()
		return false

	case "/clear":
		currentID, err := session.LoadCurrentSessionID()
		if err == nil && currentID != nil {
			sess, err := application.SessionStore.GetSession(ctx, *currentID)
			if err == nil {
				newSess, err := application.SessionStore.CreateSession(ctx, sess.Title, sess.ModelName, sess.SystemPrompt)
				if err == nil {
					_ = session.SaveCurrentSessionID(newSess.ID)
					term.Println("Started new session (history cleared)")
				} else {
					term.Printf("Failed to create new session: %v\n", err)
				}
			} else {
				term.Println("No active session to clear")
			}
		} else {
			term.Println("No active session")
		}
		term.Println()
		return false

	case "/exit", "/quit":
		term.Println("Goodbye!")
		return true

	default:
		term.Printf("Unknown command: %s\n", cmd)
		term.Println("Type /help to see available commands")
		term.Println()
		return false
	}
}

// printInteractiveHelp displays help for interactive mode
func printInteractiveHelp(term ui.IO) {
	term.Println()
	term.Println("Available Commands:")
	term.Println()
	term.Println("  /help              Show this help")
	term.Println("  /version           Show version information")
	term.Println("  /clear             Clear conversation history")
	term.Println("  /exit, /quit       Exit Koopa")
	term.Println()
	term.Println("Shortcuts:")
	term.Println("  Ctrl+C             Cancel current input")
	term.Println("  Ctrl+D             Exit (same as /exit)")
	term.Println()
	term.Println("Learn more: https://github.com/koopa0/koopa-cli")
	term.Println()
}
