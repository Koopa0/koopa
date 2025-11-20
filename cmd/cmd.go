package cmd

import (
	"context"
	"fmt"
	"io"
	"os" // Re-added for os.Stat in handleRAGAdd, as app.OSStat is not directly available in the snippet
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
func Run(ctx context.Context, cfg *config.Config, version string, term ui.IO) error {
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
			if shouldExit := handleSlashCommand(ctx, input, ag, application, version, term); shouldExit {
				break
			}
			continue
		}

		// TODO: Handle @file syntax here (future enhancement)

		// Send message to AI (new event-driven execution)
		term.Print("Koopa> ")

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
					term.Stream(event.TextChunk)
				case agent.EventTypeInterrupt:
					term.Println() // Newline for cleaner prompt
					term.Printf("[ACTION REQUIRED] Agent wants to run: %s\n", event.Interrupt.ToolName)
					term.Printf("Reason: %s\n", event.Interrupt.Reason)

					// Use UI abstraction for confirmation
					approved, err := term.Confirm("Approve?")
					if err != nil {
						if err == io.EOF {
							break event_loop
						}
						term.Printf("Error reading input: %v\n", err)
						approved = false // Default to reject on error
					}

					// Send confirmation with timeout protection (P3-1 optional)
					// This prevents hanging if the agent's channel is blocked
					select {
					case event.Interrupt.ResumeChannel <- agent.ConfirmationResponse{Approved: approved}:
						// Successfully sent confirmation
					case <-ctx.Done():
						term.Println("\nContext canceled while sending confirmation")
						break event_loop
					case <-time.After(5 * time.Second):
						term.Println("\nTimeout sending confirmation to agent")
						break event_loop
					}

					term.Print("Koopa> ")

				case agent.EventTypeError:
					term.Printf("\nError: %v\n", event.Error)
					break event_loop // Break inner loop on error
				case agent.EventTypeComplete:
					term.Println()
					break event_loop // Exit inner loop on completion
				}

			case <-ctx.Done():
				// Context cancelled, exit gracefully
				term.Println("\nOperation cancelled.")
				break event_loop

			case <-time.After(5 * time.Minute):
				// Timeout after 5 minutes to prevent indefinite hanging
				cancel() // Cancel context to stop agent goroutines (P1-1 fix)
				term.Println("\nAgent response timed out after 5 minutes.")
				break event_loop
			}
		}
	}

	return nil
}

// printWelcome displays the welcome message with KOOPA banner
func printWelcome(version string, term ui.IO) {
	// Use the banner package if available, but for now just print text
	// or adapt ui.PrintTo to use ui.IO if possible.
	// Since ui.PrintTo takes io.Writer, and ui.IO doesn't expose it directly,
	// we can either expose it or just print text here.
	// For this refactor, we'll keep it simple or use a temporary adapter if needed.
	// Ideally, ui package should handle banner printing.

	// Let's stick to text to avoid circular deps or complex adapters for now.
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
func handleSlashCommand(ctx context.Context, cmd string, ag *agent.Agent, application *app.App, version string, term ui.IO) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "/help":
		printInteractiveHelp(term)
		return false

	case "/version":
		// Show full version information (matching cobra version command)
		term.Printf("Koopa v%s\n", version)
		term.Printf("Build: %s\n", BuildTime)
		term.Printf("Commit: %s\n", GitCommit)
		term.Println()
		return false

	case "/clear":
		ag.ClearHistory()
		term.Println("Conversation history cleared")
		term.Println()
		return false

	case "/exit", "/quit":
		term.Println("Goodbye!")
		return true

	case "/rag":
		handleRAGCommand(ctx, parts[1:], application, term)
		return false

	case "/session":
		handleSessionCommand(ctx, parts[1:], ag, application, term)
		return false

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
	term.Println("╔══════════════════════════════════════════════════════════╗")
	term.Println("║  Available Commands                                      ║")
	term.Println("╚══════════════════════════════════════════════════════════╝")
	term.Println()
	term.Println("System:")
	term.Println("  /help              Show this help")
	term.Println("  /version           Show version information")
	term.Println("  /clear             Clear conversation history")
	term.Println("  /exit, /quit       Exit Koopa")
	term.Println()
	term.Println("RAG (Knowledge Management):")
	term.Println("  /rag add <file>        Add file to knowledge base")
	term.Println("  /rag add <directory>   Add directory to knowledge base")
	term.Println("  /rag list              List all indexed documents")
	term.Println("  /rag remove <id>       Remove document from knowledge base")
	term.Println("  /rag status            Show RAG status and statistics")
	term.Println("  /rag reindex-system    Reindex built-in system knowledge")
	term.Println()
	term.Println("Session Management:")
	term.Println("  /session               Show current session")
	term.Println("  /session list [N]      List sessions (default: 10)")
	term.Println("  /session new <title>   Create new session")
	term.Println("  /session switch <id>   Switch to session")
	term.Println("  /session delete <id>   Delete session")
	term.Println()
	term.Println("Shortcuts:")
	term.Println("  Ctrl+C             Cancel current input")
	term.Println("  Ctrl+D             Exit (same as /exit)")
	term.Println()
	term.Println("Learn more: https://github.com/koopa0/koopa-cli")
	term.Println()
}

// handleRAGCommand processes /rag subcommands
func handleRAGCommand(ctx context.Context, args []string, application *app.App, term ui.IO) {
	if len(args) == 0 {
		term.Println("Usage: /rag <subcommand>")
		term.Println()
		term.Println("Available subcommands:")
		term.Println("  add <file|directory>   Add file or directory to knowledge base")
		term.Println("  list                   List all indexed documents")
		term.Println("  remove <id>            Remove document from knowledge base")
		term.Println("  status                 Show RAG status and statistics")
		term.Println("  reindex-system         Reindex built-in system knowledge")
		term.Println()
		return
	}

	switch args[0] {
	case "add":
		handleRAGAdd(ctx, args[1:], application, term)
	case "list":
		handleRAGList(ctx, application, term)
	case "remove":
		handleRAGRemove(ctx, args[1:], application, term)
	case "status":
		handleRAGStatus(ctx, application, term)
	case "reindex-system":
		handleRAGReindexSystem(ctx, application, term)
	default:
		term.Printf("Unknown /rag subcommand: %s\n", args[0])
		term.Println("Type /rag to see available subcommands")
		term.Println()
	}
}

// handleRAGAdd adds files or directories to the knowledge base
func handleRAGAdd(ctx context.Context, args []string, application *app.App, term ui.IO) {
	if len(args) == 0 {
		term.Println("Error: Please specify a file or directory to add")
		term.Println("Usage: /rag add <file|directory>")
		term.Println()
		return
	}

	path := args[0]

	// Validate path using PathValidator (deep defense)
	safePath, err := application.PathValidator.Validate(path)
	if err != nil {
		term.Printf("Error: Invalid path: %v\n", err)
		term.Println()
		return
	}

	// Check if path exists
	info, err := os.Stat(safePath) // Using os.Stat as app.OSStat is not provided
	if err != nil {
		term.Printf("Error: Path not found: %s\n", safePath)
		term.Println()
		return
	}

	indexer := rag.NewIndexer(application.Knowledge, nil)

	if info.IsDir() {
		// Index directory
		term.Printf("Indexing directory: %s\n", safePath)
		term.Println()

		result, err := indexer.AddDirectory(ctx, safePath)
		if err != nil {
			term.Printf("Error: Failed to index directory: %v\n", err)
			term.Println()
			return
		}

		// Display results
		term.Println("╔══════════════════════════════════════════════════════════╗")
		term.Println("║  Indexing Results                                        ║")
		term.Println("╚══════════════════════════════════════════════════════════╝")
		term.Println()
		term.Printf("  Files added:    %d\n", result.FilesAdded)
		term.Printf("  Files skipped:  %d\n", result.FilesSkipped)
		term.Printf("  Files failed:   %d\n", result.FilesFailed)
		term.Printf("  Total size:     %d bytes\n", result.TotalSize)
		term.Printf("  Duration:       %s\n", result.Duration)
		term.Println()
	} else {
		// Index single file
		term.Printf("Indexing file: %s\n", safePath)

		err := indexer.AddFile(ctx, safePath)
		if err != nil {
			term.Printf("Error: Failed to index file: %v\n", err)
			term.Println()
			return
		}

		term.Println("✓ File indexed successfully")
		term.Println()
	}
}

// handleRAGList lists all indexed documents
func handleRAGList(ctx context.Context, application *app.App, term ui.IO) {
	indexer := rag.NewIndexer(application.Knowledge, nil)

	docs, err := indexer.ListDocuments(ctx)
	if err != nil {
		term.Printf("Error: Failed to list documents: %v\n", err)
		term.Println()
		return
	}

	if len(docs) == 0 {
		term.Println("No documents indexed yet")
		term.Println()
		term.Println("Use '/rag add <file>' to add documents")
		term.Println()
		return
	}

	term.Println("╔══════════════════════════════════════════════════════════╗")
	term.Println("║  Indexed Documents                                       ║")
	term.Println("╚══════════════════════════════════════════════════════════╝")
	term.Println()

	for i, doc := range docs {
		fileName := doc.Metadata["file_name"]
		filePath := doc.Metadata["file_path"]
		fileSize := doc.Metadata["file_size"]
		indexedAt := doc.Metadata["indexed_at"]

		term.Printf("%d. %s\n", i+1, fileName)
		term.Printf("   Path: %s\n", filePath)
		term.Printf("   Size: %s bytes\n", fileSize)
		term.Printf("   Indexed: %s\n", indexedAt)
		term.Printf("   ID: %s\n", doc.ID)
		term.Println()
	}

	term.Printf("Total: %d documents\n", len(docs))
	term.Println()
}

// handleRAGRemove removes a document from the knowledge base
func handleRAGRemove(ctx context.Context, args []string, application *app.App, term ui.IO) {
	if len(args) == 0 {
		term.Println("Error: Please specify a document ID to remove")
		term.Println("Usage: /rag remove <doc_id>")
		term.Println()
		return
	}

	docID := args[0]
	indexer := rag.NewIndexer(application.Knowledge, nil)

	err := indexer.RemoveDocument(ctx, docID)
	if err != nil {
		term.Printf("Error: Failed to remove document: %v\n", err)
		term.Println()
		return
	}

	term.Printf("✓ Document removed: %s\n", docID)
	term.Println()
}

// handleRAGStatus shows RAG status and statistics
func handleRAGStatus(ctx context.Context, application *app.App, term ui.IO) {
	term.Println("╔══════════════════════════════════════════════════════════╗")
	term.Println("║  RAG Status                                              ║")
	term.Println("╚══════════════════════════════════════════════════════════╝")
	term.Println()

	// Check database connection
	if application.DBPool != nil {
		term.Println("  Database:       Connected ✓")
	} else {
		term.Println("  Database:       Not connected")
	}

	// Check embedder
	if application.Embedder != nil {
		term.Println("  Embedder:       Configured ✓")
	} else {
		term.Println("  Embedder:       Not configured")
	}

	// Get indexed document stats
	indexer := rag.NewIndexer(application.Knowledge, nil)
	stats, err := indexer.GetStats(ctx)
	if err == nil {
		totalDocs, ok := stats["total_documents"].(int)
		if !ok {
			term.Println("  Documents:      Error getting stats")
		} else {
			term.Printf("  Documents:      %d indexed\n", totalDocs)

			if totalDocs > 0 {
				if totalSize, ok := stats["total_size"].(int64); ok {
					term.Printf("  Total Size:     %d bytes\n", totalSize)
				}

				if fileTypes, ok := stats["file_types"].(map[string]int); ok && len(fileTypes) > 0 {
					term.Println("  File Types:")
					for ext, count := range fileTypes {
						term.Printf("    %s: %d\n", ext, count)
					}
				}
			}
		}
	} else {
		term.Println("  Documents:      Error getting stats")
	}

	term.Println()
	term.Println("Use '/rag add <file>' to add documents to knowledge base")
	term.Println()
}

// handleRAGReindexSystem reindexes built-in system knowledge
func handleRAGReindexSystem(ctx context.Context, application *app.App, term ui.IO) {
	term.Println("╔══════════════════════════════════════════════════════════╗")
	term.Println("║  System Knowledge Reindexing                             ║")
	term.Println("╚══════════════════════════════════════════════════════════╝")
	term.Println()

	// Check if SystemIndexer is available
	if application.SystemIndexer == nil {
		term.Println("✗ Error: System indexer not available")
		term.Println()
		return
	}

	// Clear existing system knowledge
	term.Println("→ Clearing existing system knowledge...")
	if err := application.SystemIndexer.ClearAll(ctx); err != nil {
		term.Printf("✗ Failed to clear system knowledge: %v\n", err)
		term.Println()
		return
	}
	term.Println("✓ Existing system knowledge cleared")
	term.Println()

	// Reindex system knowledge
	term.Println("→ Reindexing system knowledge...")
	count, err := application.SystemIndexer.IndexAll(ctx)
	if err != nil {
		term.Printf("✗ Failed to index system knowledge: %v\n", err)
		term.Println()
		return
	}

	term.Println()
	term.Printf("✓ Successfully indexed %d system knowledge documents\n", count)
	term.Println()
	term.Println("System knowledge includes:")
	term.Println("  • Golang best practices (errors, concurrency, naming)")
	term.Println("  • Agent capabilities and tools")
	term.Println("  • Architecture principles")
	term.Println()
}

// ============================================================================
// Session Management Commands
// ============================================================================

// handleSessionCommand processes /session subcommands
func handleSessionCommand(ctx context.Context, args []string, ag *agent.Agent, application *app.App, term ui.IO) {
	if len(args) == 0 {
		handleSessionShow(ctx, ag, term)
		return
	}

	switch args[0] {
	case "list":
		handleSessionList(ctx, args[1:], application, term)
	case "new":
		handleSessionNew(ctx, args[1:], ag, term)
	case "switch":
		handleSessionSwitch(ctx, args[1:], ag, term)
	case "delete":
		handleSessionDelete(ctx, args[1:], ag, application, term)
	default:
		term.Printf("Unknown /session subcommand: %s\n", args[0])
		term.Println("Type /session to see usage")
		term.Println()
	}
}

// handleSessionShow displays the current active session
func handleSessionShow(ctx context.Context, ag *agent.Agent, term ui.IO) {
	currentSession, err := ag.GetCurrentSession(ctx)
	if err != nil || currentSession == nil {
		term.Println("No active session")
		term.Println()
		term.Println("Create a new session:  /session new <title>")
		term.Println("Switch to a session:   /session switch <id>")
		term.Println("List all sessions:     /session list")
		term.Println()
		return
	}

	term.Println()
	term.Println("╔══════════════════════════════════════════════════════════╗")
	term.Println("║  Current Session                                         ║")
	term.Println("╚══════════════════════════════════════════════════════════╝")
	term.Println()
	term.Printf("  Session ID:      %s\n", currentSession.ID)
	term.Printf("  Title:           %s\n", currentSession.Title)
	if currentSession.ModelName != "" {
		term.Printf("  Model:           %s\n", currentSession.ModelName)
	}
	term.Printf("  Messages:        %d\n", currentSession.MessageCount)
	term.Printf("  Created:         %s\n", currentSession.CreatedAt.Format("2006-01-02 15:04:05"))
	term.Printf("  Last Updated:    %s\n", currentSession.UpdatedAt.Format("2006-01-02 15:04:05"))
	term.Println()
	term.Println("Use '/session list' to see all sessions")
	term.Println("Use '/session switch <id>' to switch sessions")
	term.Println()
}

// handleSessionList lists all sessions with pagination
func handleSessionList(ctx context.Context, args []string, application *app.App, term ui.IO) {
	// Parse limit (default 10)
	var limit int32 = 10
	if len(args) > 0 {
		parsedLimit, err := strconv.Atoi(args[0])
		if err != nil {
			term.Printf("Error: Invalid limit '%s' - must be a number\n", args[0])
			term.Println("Usage: /session list [limit]")
			term.Println()
			return
		}
		if parsedLimit <= 0 || parsedLimit > 1000 {
			term.Println("Error: Limit must be between 1 and 1000")
			term.Println("Usage: /session list [limit]")
			term.Println()
			return
		}
		limit = int32(parsedLimit) // #nosec G109,G115 -- validated range 1-1000, safe conversion
	}

	sessions, err := application.SessionStore.ListSessions(ctx, limit, 0)
	if err != nil {
		term.Printf("Error: Failed to list sessions: %v\n", err)
		term.Println()
		return
	}

	if len(sessions) == 0 {
		term.Println("No sessions found")
		term.Println()
		term.Println("Create your first session with: /session new <title>")
		term.Println()
		return
	}

	// Get current session ID for highlighting
	var currentID uuid.UUID
	currentSessionIDPtr, err := session.LoadCurrentSessionID()
	if err == nil && currentSessionIDPtr != nil {
		currentID = *currentSessionIDPtr
	}

	// Limit displayed sessions to match header count
	displaySessions := sessions
	if len(sessions) > int(limit) {
		displaySessions = sessions[:limit]
	}

	term.Println()
	term.Printf("╔══════════════════════════════════════════════════════════╗\n")
	term.Printf("║  Sessions (%d most recent)                               ║\n", len(displaySessions))
	term.Printf("╚══════════════════════════════════════════════════════════╝\n")
	term.Println()

	for i, sess := range displaySessions {
		isActive := sess.ID == currentID
		activeMarker := " "
		activeLabel := ""
		if isActive {
			activeMarker = "▶"
			activeLabel = "  [ACTIVE]"
		}

		term.Printf(" %s %d. %s%s\n", activeMarker, i+1, sess.Title, activeLabel)
		term.Printf("    ID: %s\n", sess.ID)
		term.Printf("    Messages: %d  |  Updated: %s\n",
			sess.MessageCount,
			sess.UpdatedAt.Format("2006-01-02 15:04:05"))
		term.Println()
	}

	term.Printf("Total: %d sessions\n", len(sessions))
	term.Println()
	term.Println("Commands:")
	term.Println("  /session switch <id>    Switch to a session")
	term.Println("  /session new <title>    Create new session")
	term.Println("  /session delete <id>    Delete a session")
	term.Println()
}

// handleSessionNew creates a new session
func handleSessionNew(ctx context.Context, args []string, ag *agent.Agent, term ui.IO) {
	if len(args) == 0 {
		term.Println("Error: Please provide a session title")
		term.Println("Usage: /session new <title>")
		term.Println()
		return
	}

	title := strings.Join(args, " ")
	title = strings.TrimSpace(title)

	if title == "" {
		term.Println("Error: Session title cannot be empty")
		term.Println("Usage: /session new <title>")
		term.Println()
		return
	}

	newSession, err := ag.NewSession(ctx, title)
	if err != nil {
		term.Printf("Error: Failed to create session: %v\n", err)
		term.Println()
		return
	}

	term.Println()
	term.Printf("✓ Created new session: %s\n", newSession.Title)
	term.Printf("  Session ID: %s\n", newSession.ID)
	term.Println()
	term.Println("Conversation history cleared. You can now start a fresh conversation.")
	term.Println()
}

// handleSessionSwitch switches to a different session
func handleSessionSwitch(ctx context.Context, args []string, ag *agent.Agent, term ui.IO) {
	if len(args) == 0 {
		term.Println("Error: Please provide a session ID")
		term.Println("Usage: /session switch <id>")
		term.Println()
		return
	}

	idStr := args[0]

	// Parse UUID
	sessionID, err := parseSessionID(idStr)
	if err != nil {
		term.Printf("Error: Invalid session ID format: %s\n", idStr)
		term.Println("Usage: /session switch <id>")
		term.Println()
		return
	}

	// Attempt to switch
	err = ag.SwitchSession(ctx, sessionID)
	if err != nil {
		term.Printf("Error: Failed to switch session: %v\n", err)
		term.Println("Use '/session list' to see available sessions")
		term.Println()
		return
	}

	// Get session details for confirmation
	currentSession, err := ag.GetCurrentSession(ctx)
	if err != nil || currentSession == nil {
		term.Println("✓ Switched to session")
		term.Println()
		return
	}

	term.Println()
	term.Printf("✓ Switched to session: %s\n", currentSession.Title)
	term.Printf("  Session ID: %s\n", currentSession.ID)
	term.Printf("  Messages: %d\n", currentSession.MessageCount)
	term.Println()
	term.Printf("Conversation history loaded (%d messages)\n", currentSession.MessageCount)
	term.Println()
}

// handleSessionDelete deletes a session
func handleSessionDelete(ctx context.Context, args []string, ag *agent.Agent, application *app.App, term ui.IO) {
	if len(args) == 0 {
		term.Println("Error: Please provide a session ID")
		term.Println("Usage: /session delete <id>")
		term.Println()
		return
	}

	idStr := args[0]

	sessionID, err := parseSessionID(idStr)
	if err != nil {
		term.Printf("Error: Invalid session ID format: %s\n", idStr)
		term.Println("Usage: /session delete <id>")
		term.Println()
		return
	}

	// Check if deleting current session
	currentSession, _ := ag.GetCurrentSession(ctx)
	isDeletingCurrent := currentSession != nil && currentSession.ID == sessionID

	// Get session details before deletion
	sessionToDelete, err := application.SessionStore.GetSession(ctx, sessionID)
	if err != nil {
		term.Printf("Error: Session not found: %s\n", sessionID)
		term.Println("Use '/session list' to see available sessions")
		term.Println()
		return
	}

	// Delete session
	err = application.SessionStore.DeleteSession(ctx, sessionID)
	if err != nil {
		term.Printf("Error: Failed to delete session: %v\n", err)
		term.Println()
		return
	}

	term.Println()
	term.Printf("✓ Deleted session: %s\n", sessionToDelete.Title)
	term.Printf("  Session ID: %s\n", sessionID)
	term.Println()
	term.Println("Session and all its messages have been permanently deleted.")

	if isDeletingCurrent {
		// Clear current session reference
		_ = session.ClearCurrentSessionID()
		ag.ClearHistory()
		term.Println()
		term.Println("Conversation history cleared. Create a new session with '/session new <title>'")
	}

	term.Println()
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
