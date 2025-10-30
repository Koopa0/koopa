package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/koopa0/koopa/internal/agent"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/koopa0/koopa/internal/memory"
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

	// Create Agent
	ag, err := agent.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf(i18n.T("error.agent"), err)
	}

	// Create memory instance
	mem := memory.New(db)

	// Create new session
	session, err := mem.CreateSession(ctx, "Chat Session")
	if err != nil {
		return fmt.Errorf(i18n.T("error.session"), err)
	}

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
			if handleCommand(input, ag) {
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
func handleCommand(cmd string, ag *agent.Agent) bool {
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
