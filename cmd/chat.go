package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa/internal/agent"
	// "github.com/koopa0/koopa/internal/agent/mcp" // TEMPORARILY DISABLED FOR TESTING
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/koopa0/koopa/internal/knowledge"
	"github.com/koopa0/koopa/internal/memory"
	"github.com/koopa0/koopa/internal/notion"
	"github.com/koopa0/koopa/internal/retriever"
	"github.com/koopa0/koopa/internal/security"
	"github.com/spf13/cobra"
)

// NewChatCmd creates the chat command (factory pattern)
func NewChatCmd(db *sql.DB, cfg *config.Config, appVersion string) *cobra.Command {
	return &cobra.Command{
		Use:   "chat",
		Short: i18n.T("chat.description"),
		Annotations: map[string]string{
			"requiresAPIKey": "true", // Declarative: this command requires API Key
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChat(cmd.Context(), db, cfg, appVersion)
		},
	}
}

func runChat(ctx context.Context, db *sql.DB, cfg *config.Config, appVersion string) error {
	// API Key already checked in PersistentPreRunE

	// Step 1: Initialize Genkit (moved to cmd layer to resolve circular dependency)
	g := genkit.Init(ctx,
		genkit.WithPlugins(&googlegenai.GoogleAI{}),
		genkit.WithPromptDir("./prompts"),
	)

	// Step 2: Create embedder (uses configured model from config)
	embedder := googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)

	// Step 3: Initialize knowledge store for semantic search
	knowledgeStore, err := knowledge.New(cfg.VectorPath, "koopa-knowledge", embedder, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize knowledge store: %w", err)
	}
	defer knowledgeStore.Close()

	// Step 4: Create memory instance (needed to create session)
	mem := memory.New(db, knowledgeStore)

	// Step 5: Create new session (to get session ID for retriever filtering)
	session, err := mem.CreateSession(ctx, "Chat Session")
	if err != nil {
		return fmt.Errorf(i18n.T("error.session"), err)
	}

	// Step 6: Create retriever with session filtering
	// Convert session.ID (int64) to string for metadata filtering
	sessionIDStr := strconv.FormatInt(session.ID, 10)
	ret := retriever.NewWithSession(knowledgeStore, sessionIDStr)
	retrieverRef := ret.DefineConversation(g, "conversation")

	// Step 7: Create Agent with RAG support
	ag, err := agent.New(ctx, cfg, g, retrieverRef)
	if err != nil {
		return fmt.Errorf(i18n.T("error.agent"), err)
	}

	// Step 8: Notion sync (optional, first-time auto-sync)
	// NOTE: Notion sync is performed BEFORE MCP connection to avoid blocking
	var notionClient *notion.Client
	if notionToken := os.Getenv("NOTION_API_KEY"); notionToken != "" {
		// Create Notion client (uses security validator from agent)
		httpValidator := security.NewHTTPValidator()
		notionClient, err = notion.New(notionToken, httpValidator)
		if err != nil {
			slog.Warn("failed to create Notion client",
				"error", err)
		} else {
			// Check if first-time sync is needed
			shouldSync, err := notion.ShouldSyncOnInit(ctx, knowledgeStore)
			if err != nil {
				slog.Warn("failed to check Notion sync status",
					"error", err)
			} else if shouldSync {
				fmt.Println("\nℹ️  Performing first-time Notion sync...")
				fmt.Println("   (Syncing first 10 pages for testing)")

				syncResult, err := notion.SyncToKnowledgeStore(ctx, notionClient, knowledgeStore, 10)
				if err != nil {
					slog.Warn("Notion sync failed",
						"error", err)
					fmt.Println("⚠️  Notion sync failed. You can retry with /sync command.")
				} else {
					fmt.Printf("✅ Notion sync completed: %d pages synced, %d skipped, %d failed\n",
						syncResult.PagesSynced, syncResult.PagesSkipped, syncResult.PagesFailed)
				}
			} else {
				// Get sync stats to display
				stats, err := notion.GetSyncStats(ctx, knowledgeStore)
				if err == nil {
					if totalPages, ok := stats["total_pages"]; ok && totalPages != "0" {
						fmt.Printf("\nℹ️  Notion: %s pages available for RAG (use /sync to update)\n", totalPages)
					}
				}
			}
		}
	}

	// Step 9: Connect to MCP servers (optional, graceful degradation)
	// NOTE: MCP connection is performed AFTER Notion sync to avoid blocking
	// TEMPORARILY DISABLED FOR TESTING - MCP connection can block startup
	/*
	mcpConfigs := config.LoadMCPConfigs()
	if len(mcpConfigs) > 0 {
		// Convert config.MCPConfig to mcp.Config (they have identical structure)
		agentMCPConfigs := make([]mcp.Config, len(mcpConfigs))
		for i, cfg := range mcpConfigs {
			agentMCPConfigs[i] = mcp.Config{
				Name:          cfg.Name,
				ClientOptions: cfg.ClientOptions,
			}
		}

		if err := ag.ConnectMCP(ctx, agentMCPConfigs); err != nil {
			slog.Warn("failed to connect MCP servers, continuing without MCP",
				"error", err,
				"server_count", len(mcpConfigs))
		} else {
			slog.Info("MCP servers connected successfully",
				"server_count", len(mcpConfigs))
		}
	}
	*/

	// Display welcome message (use version passed as parameter)
	fmt.Println(i18n.Sprintf("welcome", appVersion))
	fmt.Println(i18n.T("welcome.help"))
	fmt.Printf("Session ID: %d\n", session.ID)
	fmt.Println()

	// Start conversation loop
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(i18n.T("chat.prompt"))

		// Read user input
		if !scanner.Scan() {
			// EOF (Ctrl+D)
			fmt.Println("\n" + i18n.T("goodbye"))
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		// Handle special commands
		if strings.HasPrefix(input, "/") {
			if handleCommand(ctx, input, ag, notionClient, knowledgeStore) {
				break // Exit command
			}
			continue
		}

		// Save user message to database
		if _, err = mem.AddMessage(ctx, session.ID, "user", input); err != nil {
			fmt.Fprint(os.Stderr, i18n.Sprintf("error.message", err))
		}

		// Send message to AI (using streaming)
		fmt.Print(i18n.T("chat.assistant"))
		_ = os.Stdout.Sync() // Ensure prompt is displayed immediately

		response, err := ag.ChatStream(ctx, input, func(chunk string) {
			// Print character by character, simulating typing effect
			printCharByChar(chunk)
		})
		if err != nil {
			fmt.Fprint(os.Stderr, i18n.Sprintf("chat.streaming.error", err)+"\n")
			continue
		}
		fmt.Println()

		// Save AI response to database
		if _, err = mem.AddMessage(ctx, session.ID, "model", response); err != nil {
			fmt.Fprint(os.Stderr, i18n.Sprintf("error.message", err))
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf(i18n.T("error.input"), err)
	}

	// Session is automatically saved
	fmt.Printf("Session saved (ID: %d)\n", session.ID)

	return nil
}

// handleCommand handles special commands, returns true if should exit
func handleCommand(ctx context.Context, cmd string, ag *agent.Agent, notionClient *notion.Client, knowledgeStore knowledge.VectorStore) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "/help":
		fmt.Println(i18n.T("help.title"))
		fmt.Println("  " + i18n.T("help.help"))
		fmt.Println("  " + i18n.T("help.tools"))
		fmt.Println("  " + i18n.T("help.clear"))
		fmt.Println("  /sync           - Sync Notion content to knowledge store (requires NOTION_API_KEY)")
		fmt.Println("  " + i18n.T("help.exit"))
		fmt.Println("  " + i18n.T("help.lang"))
		fmt.Println("  " + i18n.T("help.ctrl_d"))
		fmt.Println(i18n.Sprintf("help.current.lang", i18n.GetLanguage()))
		fmt.Println(i18n.Sprintf("help.available.lang", strings.Join(i18n.GetSupportedLanguages(), ", ")))
		fmt.Println()

	case "/tools":
		// Tools are always enabled, display available tools
		fmt.Println(i18n.T("chat.tools.enabled"))
		fmt.Println(i18n.T("chat.tools.available"))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.currentTime.name"), i18n.T("tool.currentTime.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.readFile.name"), i18n.T("tool.readFile.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.writeFile.name"), i18n.T("tool.writeFile.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.listFiles.name"), i18n.T("tool.listFiles.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.deleteFile.name"), i18n.T("tool.deleteFile.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.executeCommand.name"), i18n.T("tool.executeCommand.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.httpGet.name"), i18n.T("tool.httpGet.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.getEnv.name"), i18n.T("tool.getEnv.desc")))
		fmt.Println(i18n.Sprintf("chat.tool.item", i18n.T("tool.getFileInfo.name"), i18n.T("tool.getFileInfo.desc")))
		fmt.Println()

	case "/clear":
		ag.ClearHistory()
		fmt.Println(i18n.T("chat.cleared"))
		fmt.Println()

	case "/lang":
		if len(parts) < 2 {
			fmt.Println(i18n.Sprintf("lang.current", i18n.GetLanguage()))
			fmt.Println(i18n.Sprintf("lang.available", strings.Join(i18n.GetSupportedLanguages(), ", ")))
		} else {
			lang := parts[1]
			if i18n.IsLanguageSupported(lang) {
				i18n.SetLanguage(lang)
				fmt.Println(i18n.Sprintf("lang.changed", lang))
			} else {
				fmt.Println(i18n.Sprintf("lang.unsupported", lang))
				fmt.Println(i18n.Sprintf("lang.available", strings.Join(i18n.GetSupportedLanguages(), ", ")))
			}
		}
		fmt.Println()

	case "/sync":
		if notionClient == nil {
			fmt.Println("⚠️  Notion sync is not available.")
			fmt.Println("   Set NOTION_API_KEY environment variable to enable Notion integration.")
			fmt.Println()
			return false
		}

		fmt.Println("\n🔄 Syncing Notion content (first 10 pages for testing)...")
		syncResult, err := notion.SyncToKnowledgeStore(ctx, notionClient, knowledgeStore, 10)
		if err != nil {
			fmt.Printf("❌ Sync failed: %v\n\n", err)
			return false
		}

		fmt.Printf("✅ Sync completed: %d pages synced, %d skipped, %d failed (took %s)\n\n",
			syncResult.PagesSynced, syncResult.PagesSkipped, syncResult.PagesFailed, syncResult.TotalDuration)

	case "/exit", "/quit":
		fmt.Println(i18n.T("goodbye"))
		return true

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		fmt.Println("Type /help to see available commands")
		fmt.Println()
	}

	return false
}

// printCharByChar prints text character by character, simulating typing effect
func printCharByChar(text string) {
	// Iterate through each UTF-8 character (not bytes)
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		fmt.Print(string(r))
		_ = os.Stdout.Sync() // Flush immediately

		// Add small delay to create typing effect
		// Non-ASCII characters (e.g., Chinese) slightly slower, ASCII faster
		if r > 127 { // Non-ASCII character
			time.Sleep(30 * time.Millisecond)
		} else if r == ' ' || r == '\n' {
			// No delay for spaces and newlines
			time.Sleep(5 * time.Millisecond)
		} else {
			time.Sleep(20 * time.Millisecond)
		}

		text = text[size:]
	}
}
