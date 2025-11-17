package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/ui"
)

// Run starts the interactive chat mode
func Run(ctx context.Context, cfg *config.Config, version string) error {
	// Create cancellable context for this session
	// This allows us to properly clean up resources on timeout or cancellation
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Initialize application using Wire DI
	application, cleanup, err := app.InitializeApp(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}
	defer cleanup()
	defer application.Close()

	// Create retriever for documents (files, not conversations)
	ret := rag.New(application.Knowledge)
	retrieverRef := ret.DefineDocument(application.Genkit, "documents")

	// Create Agent with RAG support
	ag, err := application.CreateAgent(ctx, retrieverRef)
	if err != nil {
		return fmt.Errorf("error creating agent: %w", err)
	}

	// Display welcome message
	printWelcome(version)

	// Start conversation loop
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")

		// Read user input
		if !scanner.Scan() {
			// EOF (Ctrl+D)
			fmt.Println("\nGoodbye!")
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		// Handle slash commands
		if strings.HasPrefix(input, "/") {
			if shouldExit := handleSlashCommand(ctx, input, ag, application, version); shouldExit {
				break
			}
			continue
		}

		// TODO: Handle @file syntax here (future enhancement)

		// Send message to AI (new event-driven execution)
		fmt.Print("Koopa> ")
		_ = os.Stdout.Sync()

		eventCh := ag.Execute(ctx, input)
	event_loop:
		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					// Channel closed, exit loop
					break event_loop
				}

				switch event.Type {
				case agent.EventTypeText:
					fmt.Print(event.TextChunk)
					_ = os.Stdout.Sync()
				case agent.EventTypeInterrupt:
					fmt.Println() // Newline for cleaner prompt
					fmt.Printf("[ACTION REQUIRED] Agent wants to run: %s\n", event.Interrupt.ToolName)
					fmt.Printf("Reason: %s\n", event.Interrupt.Reason)

					// Improved input validation with retry loop
					approved := false
					for {
						fmt.Print("Approve? [y/n]: ")
						_ = os.Stdout.Sync()

						if scanner.Scan() {
							input := strings.ToLower(strings.TrimSpace(scanner.Text()))
							if input == "y" {
								approved = true
								break
							} else if input == "n" {
								approved = false
								break
							} else {
								fmt.Println("Invalid input. Please enter 'y' or 'n'.")
								continue
							}
						} else {
							// Scanner error or EOF, default to reject for safety
							if err := scanner.Err(); err != nil {
								fmt.Fprintf(os.Stderr, "Scanner error: %v\n", err)
							}
							break
						}
					}

					// Send confirmation with timeout protection (P3-1 optional)
					// This prevents hanging if the agent's channel is blocked
					select {
					case event.Interrupt.ResumeChannel <- agent.ConfirmationResponse{Approved: approved}:
						// Successfully sent confirmation
					case <-ctx.Done():
						fmt.Fprintf(os.Stderr, "\nContext canceled while sending confirmation\n")
						break event_loop
					case <-time.After(5 * time.Second):
						fmt.Fprintf(os.Stderr, "\nTimeout sending confirmation to agent\n")
						break event_loop
					}

					fmt.Print("Koopa> ")
					_ = os.Stdout.Sync()

				case agent.EventTypeError:
					fmt.Fprintf(os.Stderr, "\nError: %v\n", event.Error)
					break event_loop // Break inner loop on error
				case agent.EventTypeComplete:
					fmt.Println()
					break event_loop // Exit inner loop on completion
				}

			case <-ctx.Done():
				// Context cancelled, exit gracefully
				fmt.Println("\nOperation cancelled.")
				break event_loop

			case <-time.After(5 * time.Minute):
				// Timeout after 5 minutes to prevent indefinite hanging
			cancel() // Cancel context to stop agent goroutines (P1-1 fix)
				fmt.Fprintf(os.Stderr, "\nAgent response timed out after 5 minutes.\n")
				break event_loop
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("error reading input: %w", err)
	}

	return nil
}

// printWelcome displays the welcome message with KOOPA banner
func printWelcome(version string) {
	ui.Print()

	fmt.Printf("v%s\n", version)
	fmt.Println()

	fmt.Println("Tips for getting started:")
	fmt.Println("1. Ask questions, edit files, or run commands.")
	fmt.Println("2. Be specific for the best results.")
	fmt.Println("3. /help for more information.")
	fmt.Println()
}

// handleSlashCommand processes slash commands, returns true if should exit
func handleSlashCommand(ctx context.Context, cmd string, ag *agent.Agent, application *app.App, version string) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "/help":
		printInteractiveHelp()
		return false

	case "/version":
		// Show full version information (matching cobra version command)
		fmt.Printf("Koopa v%s\n", version)
		fmt.Printf("Build: %s\n", BuildTime)
		fmt.Printf("Commit: %s\n", GitCommit)
		fmt.Println()
		return false

	case "/clear":
		ag.ClearHistory()
		fmt.Println("Conversation history cleared")
		fmt.Println()
		return false

	case "/exit", "/quit":
		fmt.Println("Goodbye!")
		return true

	case "/rag":
		handleRAGCommand(ctx, parts[1:], application)
		return false

	case "/session":
		handleSessionCommand(ctx, parts[1:], ag, application)
		return false

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		fmt.Println("Type /help to see available commands")
		fmt.Println()
		return false
	}
}

// printInteractiveHelp displays help for interactive mode
func printInteractiveHelp() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  Available Commands                                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("System:")
	fmt.Println("  /help              Show this help")
	fmt.Println("  /version           Show version information")
	fmt.Println("  /clear             Clear conversation history")
	fmt.Println("  /exit, /quit       Exit Koopa")
	fmt.Println()
	fmt.Println("RAG (Knowledge Management):")
	fmt.Println("  /rag add <file>        Add file to knowledge base")
	fmt.Println("  /rag add <directory>   Add directory to knowledge base")
	fmt.Println("  /rag list              List all indexed documents")
	fmt.Println("  /rag remove <id>       Remove document from knowledge base")
	fmt.Println("  /rag status            Show RAG status and statistics")
	fmt.Println()
	fmt.Println("Session Management:")
	fmt.Println("  /session               Show current session")
	fmt.Println("  /session list [N]      List sessions (default: 10)")
	fmt.Println("  /session new <title>   Create new session")
	fmt.Println("  /session switch <id>   Switch to session")
	fmt.Println("  /session delete <id>   Delete session")
	fmt.Println()
	fmt.Println("Shortcuts:")
	fmt.Println("  Ctrl+C             Cancel current input")
	fmt.Println("  Ctrl+D             Exit (same as /exit)")
	fmt.Println()
	fmt.Println("Learn more: https://github.com/koopa0/koopa-cli")
	fmt.Println()
}

// handleRAGCommand processes /rag subcommands
func handleRAGCommand(ctx context.Context, args []string, application *app.App) {
	if len(args) == 0 {
		fmt.Println("Usage: /rag <subcommand>")
		fmt.Println()
		fmt.Println("Available subcommands:")
		fmt.Println("  add <file|directory>   Add file or directory to knowledge base")
		fmt.Println("  list                   List all indexed documents")
		fmt.Println("  remove <id>            Remove document from knowledge base")
		fmt.Println("  status                 Show RAG status and statistics")
		fmt.Println()
		return
	}

	switch args[0] {
	case "add":
		handleRAGAdd(ctx, args[1:], application)
	case "list":
		handleRAGList(ctx, application)
	case "remove":
		handleRAGRemove(ctx, args[1:], application)
	case "status":
		handleRAGStatus(ctx, application)
	default:
		fmt.Printf("Unknown /rag subcommand: %s\n", args[0])
		fmt.Println("Type /rag to see available subcommands")
		fmt.Println()
	}
}

// handleRAGAdd adds files or directories to the knowledge base
func handleRAGAdd(ctx context.Context, args []string, application *app.App) {
	if len(args) == 0 {
		fmt.Println("Error: Please specify a file or directory to add")
		fmt.Println("Usage: /rag add <file|directory>")
		fmt.Println()
		return
	}

	path := args[0]

	// Validate path using PathValidator (deep defense)
	safePath, err := application.PathValidator.Validate(path)
	if err != nil {
		fmt.Printf("Error: Invalid path: %v\n", err)
		fmt.Println()
		return
	}

	// Check if path exists
	info, err := os.Stat(safePath)
	if err != nil {
		fmt.Printf("Error: Path not found: %s\n", safePath)
		fmt.Println()
		return
	}

	indexer := rag.NewIndexer(application.Knowledge)

	if info.IsDir() {
		// Index directory
		fmt.Printf("Indexing directory: %s\n", safePath)
		fmt.Println()

		result, err := indexer.AddDirectory(ctx, safePath)
		if err != nil {
			fmt.Printf("Error: Failed to index directory: %v\n", err)
			fmt.Println()
			return
		}

		// Display results
		fmt.Println("╔══════════════════════════════════════════════════════════╗")
		fmt.Println("║  Indexing Results                                        ║")
		fmt.Println("╚══════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Printf("  Files added:    %d\n", result.FilesAdded)
		fmt.Printf("  Files skipped:  %d\n", result.FilesSkipped)
		fmt.Printf("  Files failed:   %d\n", result.FilesFailed)
		fmt.Printf("  Total size:     %d bytes\n", result.TotalSize)
		fmt.Printf("  Duration:       %s\n", result.Duration)
		fmt.Println()
	} else {
		// Index single file
		fmt.Printf("Indexing file: %s\n", safePath)

		err := indexer.AddFile(ctx, safePath)
		if err != nil {
			fmt.Printf("Error: Failed to index file: %v\n", err)
			fmt.Println()
			return
		}

		fmt.Println("✓ File indexed successfully")
		fmt.Println()
	}
}

// handleRAGList lists all indexed documents
func handleRAGList(ctx context.Context, application *app.App) {
	indexer := rag.NewIndexer(application.Knowledge)

	docs, err := indexer.ListDocuments(ctx)
	if err != nil {
		fmt.Printf("Error: Failed to list documents: %v\n", err)
		fmt.Println()
		return
	}

	if len(docs) == 0 {
		fmt.Println("No documents indexed yet")
		fmt.Println()
		fmt.Println("Use '/rag add <file>' to add documents")
		fmt.Println()
		return
	}

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  Indexed Documents                                       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	for i, doc := range docs {
		fileName := doc.Metadata["file_name"]
		filePath := doc.Metadata["file_path"]
		fileSize := doc.Metadata["file_size"]
		indexedAt := doc.Metadata["indexed_at"]

		fmt.Printf("%d. %s\n", i+1, fileName)
		fmt.Printf("   Path: %s\n", filePath)
		fmt.Printf("   Size: %s bytes\n", fileSize)
		fmt.Printf("   Indexed: %s\n", indexedAt)
		fmt.Printf("   ID: %s\n", doc.ID)
		fmt.Println()
	}

	fmt.Printf("Total: %d documents\n", len(docs))
	fmt.Println()
}

// handleRAGRemove removes a document from the knowledge base
func handleRAGRemove(ctx context.Context, args []string, application *app.App) {
	if len(args) == 0 {
		fmt.Println("Error: Please specify a document ID to remove")
		fmt.Println("Usage: /rag remove <doc_id>")
		fmt.Println()
		return
	}

	docID := args[0]
	indexer := rag.NewIndexer(application.Knowledge)

	err := indexer.RemoveDocument(ctx, docID)
	if err != nil {
		fmt.Printf("Error: Failed to remove document: %v\n", err)
		fmt.Println()
		return
	}

	fmt.Printf("✓ Document removed: %s\n", docID)
	fmt.Println()
}

// handleRAGStatus shows RAG status and statistics
func handleRAGStatus(ctx context.Context, application *app.App) {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  RAG Status                                              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Check database connection
	if application.DBPool != nil {
		fmt.Println("  Database:       Connected ✓")
	} else {
		fmt.Println("  Database:       Not connected")
	}

	// Check embedder
	if application.Embedder != nil {
		fmt.Println("  Embedder:       Configured ✓")
	} else {
		fmt.Println("  Embedder:       Not configured")
	}

	// Get indexed document stats
	indexer := rag.NewIndexer(application.Knowledge)
	stats, err := indexer.GetStats(ctx)
	if err == nil {
		totalDocs, ok := stats["total_documents"].(int)
		if !ok {
			fmt.Println("  Documents:      Error getting stats")
		} else {
			fmt.Printf("  Documents:      %d indexed\n", totalDocs)

			if totalDocs > 0 {
				if totalSize, ok := stats["total_size"].(int64); ok {
					fmt.Printf("  Total Size:     %d bytes\n", totalSize)
				}

				if fileTypes, ok := stats["file_types"].(map[string]int); ok && len(fileTypes) > 0 {
					fmt.Println("  File Types:")
					for ext, count := range fileTypes {
						fmt.Printf("    %s: %d\n", ext, count)
					}
				}
			}
		}
	} else {
		fmt.Println("  Documents:      Error getting stats")
	}

	fmt.Println()
	fmt.Println("Use '/rag add <file>' to add documents to knowledge base")
	fmt.Println()
}
// ============================================================================
// Session Management Commands
// ============================================================================

// handleSessionCommand processes /session subcommands
func handleSessionCommand(ctx context.Context, args []string, ag *agent.Agent, application *app.App) {
	if len(args) == 0 {
		handleSessionShow(ctx, ag)
		return
	}

	switch args[0] {
	case "list":
		handleSessionList(ctx, args[1:], application)
	case "new":
		handleSessionNew(ctx, args[1:], ag)
	case "switch":
		handleSessionSwitch(ctx, args[1:], ag)
	case "delete":
		handleSessionDelete(ctx, args[1:], ag, application)
	default:
		fmt.Printf("Unknown /session subcommand: %s\n", args[0])
		fmt.Println("Type /session to see usage")
		fmt.Println()
	}
}

// handleSessionShow displays the current active session
func handleSessionShow(ctx context.Context, ag *agent.Agent) {
	currentSession, err := ag.GetCurrentSession(ctx)
	if err != nil || currentSession == nil {
		fmt.Println("No active session")
		fmt.Println()
		fmt.Println("Create a new session:  /session new <title>")
		fmt.Println("Switch to a session:   /session switch <id>")
		fmt.Println("List all sessions:     /session list")
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║  Current Session                                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Session ID:      %s\n", currentSession.ID)
	fmt.Printf("  Title:           %s\n", currentSession.Title)
	if currentSession.ModelName != "" {
		fmt.Printf("  Model:           %s\n", currentSession.ModelName)
	}
	fmt.Printf("  Messages:        %d\n", currentSession.MessageCount)
	fmt.Printf("  Created:         %s\n", currentSession.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Last Updated:    %s\n", currentSession.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Println("Use '/session list' to see all sessions")
	fmt.Println("Use '/session switch <id>' to switch sessions")
	fmt.Println()
}

// handleSessionList lists all sessions with pagination
func handleSessionList(ctx context.Context, args []string, application *app.App) {
	// Parse limit (default 10)
	limit := 10
	if len(args) > 0 {
		if parsedLimit, err := strconv.Atoi(args[0]); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	sessions, err := application.SessionStore.ListSessions(ctx, limit, 0)
	if err != nil {
		fmt.Printf("Error: Failed to list sessions: %v\n", err)
		fmt.Println()
		return
	}

	if len(sessions) == 0 {
		fmt.Println("No sessions found")
		fmt.Println()
		fmt.Println("Create your first session with: /session new <title>")
		fmt.Println()
		return
	}

	// Get current session ID for highlighting
	var currentID uuid.UUID
	currentSessionIDPtr, err := session.LoadCurrentSessionID()
	if err == nil && currentSessionIDPtr != nil {
		currentID = *currentSessionIDPtr
	}

	fmt.Println()
	fmt.Printf("╔══════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Sessions (%d most recent)                               ║\n", min(limit, len(sessions)))
	fmt.Printf("╚══════════════════════════════════════════════════════════╝\n")
	fmt.Println()

	for i, sess := range sessions {
		isActive := sess.ID == currentID
		activeMarker := " "
		activeLabel := ""
		if isActive {
			activeMarker = "▶"
			activeLabel = "  [ACTIVE]"
		}

		fmt.Printf(" %s %d. %s%s\n", activeMarker, i+1, sess.Title, activeLabel)
		fmt.Printf("    ID: %s\n", sess.ID)
		fmt.Printf("    Messages: %d  |  Updated: %s\n",
			sess.MessageCount,
			sess.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	fmt.Printf("Total: %d sessions\n", len(sessions))
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  /session switch <id>    Switch to a session")
	fmt.Println("  /session new <title>    Create new session")
	fmt.Println("  /session delete <id>    Delete a session")
	fmt.Println()
}

// handleSessionNew creates a new session
func handleSessionNew(ctx context.Context, args []string, ag *agent.Agent) {
	if len(args) == 0 {
		fmt.Println("Error: Please provide a session title")
		fmt.Println("Usage: /session new <title>")
		fmt.Println()
		return
	}

	title := strings.Join(args, " ")
	title = strings.TrimSpace(title)

	if title == "" {
		fmt.Println("Error: Session title cannot be empty")
		fmt.Println("Usage: /session new <title>")
		fmt.Println()
		return
	}

	newSession, err := ag.NewSession(ctx, title)
	if err != nil {
		fmt.Printf("Error: Failed to create session: %v\n", err)
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Printf("✓ Created new session: %s\n", newSession.Title)
	fmt.Printf("  Session ID: %s\n", newSession.ID)
	fmt.Println()
	fmt.Println("Conversation history cleared. You can now start a fresh conversation.")
	fmt.Println()
}

// handleSessionSwitch switches to a different session
func handleSessionSwitch(ctx context.Context, args []string, ag *agent.Agent) {
	if len(args) == 0 {
		fmt.Println("Error: Please provide a session ID")
		fmt.Println("Usage: /session switch <id>")
		fmt.Println()
		return
	}

	idStr := args[0]

	// Parse UUID
	sessionID, err := parseSessionID(idStr)
	if err != nil {
		fmt.Printf("Error: Invalid session ID format: %s\n", idStr)
		fmt.Println("Usage: /session switch <id>")
		fmt.Println()
		return
	}

	// Attempt to switch
	err = ag.SwitchSession(ctx, sessionID)
	if err != nil {
		fmt.Printf("Error: Failed to switch session: %v\n", err)
		fmt.Println("Use '/session list' to see available sessions")
		fmt.Println()
		return
	}

	// Get session details for confirmation
	currentSession, err := ag.GetCurrentSession(ctx)
	if err != nil || currentSession == nil {
		fmt.Println("✓ Switched to session")
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Printf("✓ Switched to session: %s\n", currentSession.Title)
	fmt.Printf("  Session ID: %s\n", currentSession.ID)
	fmt.Printf("  Messages: %d\n", currentSession.MessageCount)
	fmt.Println()
	fmt.Printf("Conversation history loaded (%d messages)\n", currentSession.MessageCount)
	fmt.Println()
}

// handleSessionDelete deletes a session
func handleSessionDelete(ctx context.Context, args []string, ag *agent.Agent, application *app.App) {
	if len(args) == 0 {
		fmt.Println("Error: Please provide a session ID")
		fmt.Println("Usage: /session delete <id>")
		fmt.Println()
		return
	}

	idStr := args[0]

	sessionID, err := parseSessionID(idStr)
	if err != nil {
		fmt.Printf("Error: Invalid session ID format: %s\n", idStr)
		fmt.Println("Usage: /session delete <id>")
		fmt.Println()
		return
	}

	// Check if deleting current session
	currentSession, _ := ag.GetCurrentSession(ctx)
	isDeletingCurrent := currentSession != nil && currentSession.ID == sessionID

	// Get session details before deletion
	sessionToDelete, err := application.SessionStore.GetSession(ctx, sessionID)
	if err != nil {
		fmt.Printf("Error: Session not found: %s\n", sessionID)
		fmt.Println("Use '/session list' to see available sessions")
		fmt.Println()
		return
	}

	// Delete session
	err = application.SessionStore.DeleteSession(ctx, sessionID)
	if err != nil {
		fmt.Printf("Error: Failed to delete session: %v\n", err)
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Printf("✓ Deleted session: %s\n", sessionToDelete.Title)
	fmt.Printf("  Session ID: %s\n", sessionID)
	fmt.Println()
	fmt.Println("Session and all its messages have been permanently deleted.")

	if isDeletingCurrent {
		// Clear current session reference
		_ = session.ClearCurrentSessionID()
		ag.ClearHistory()
		fmt.Println()
		fmt.Println("Conversation history cleared. Create a new session with '/session new <title>'")
	}

	fmt.Println()
}

// ============================================================================
// Helper Functions
// ============================================================================

// parseSessionID parses a full UUID string
func parseSessionID(idStr string) (uuid.UUID, error) {
	// Try to parse as UUID
	id, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid UUID: %s", idStr)
	}
	return id, nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
