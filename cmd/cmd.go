package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/app"
	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/koopa0/koopa-cli/internal/rag"
)

// Run starts the interactive chat mode (default behavior of Koopa v2.0)
func Run(ctx context.Context, cfg *config.Config, version string) error {
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
		fmt.Print("You> ")

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

		// Send message to AI (streaming)
		fmt.Print("Koopa> ")
		_ = os.Stdout.Sync()

		if _, err := ag.ChatStream(ctx, input, func(chunk string) {
			fmt.Print(chunk)
			_ = os.Stdout.Sync()
		}); err != nil {
			fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
			continue
		}
		fmt.Println()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("error reading input: %w", err)
	}

	return nil
}

// printWelcome displays the welcome message
func printWelcome(version string) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Koopa v%-49s║\n", version)
	fmt.Println("║  AI Personal Assistant powered by Gemini                 ║")
	fmt.Println("║                                                          ║")
	fmt.Println("║  Type /help for commands, Ctrl+D to exit                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
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
