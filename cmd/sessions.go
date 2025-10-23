package cmd

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/koopa0/koopa/internal/database"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/koopa0/koopa/internal/memory"
	"github.com/spf13/cobra"
)

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: i18n.T("sessions.description"),
}

var sessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: i18n.T("sessions.list.description"),
	RunE:  runSessionsList,
}

var sessionsShowCmd = &cobra.Command{
	Use:   "show <session-id>",
	Short: "Show specific session messages",
	Args:  cobra.ExactArgs(1),
	RunE:  runSessionsShow,
}

var sessionsDeleteCmd = &cobra.Command{
	Use:   "delete <session-id>",
	Short: i18n.T("sessions.delete.description"),
	Args:  cobra.ExactArgs(1),
	RunE:  runSessionsDelete,
}

func init() {
	rootCmd.AddCommand(sessionsCmd)
	sessionsCmd.AddCommand(sessionsListCmd)
	sessionsCmd.AddCommand(sessionsShowCmd)
	sessionsCmd.AddCommand(sessionsDeleteCmd)
}

func runSessionsList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Open database
	dbPath := ".koopa/koopa.db"
	sqlDB, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf(i18n.T("error.database"), err)
	}
	defer sqlDB.Close()

	// Create memory instance
	mem := memory.New(sqlDB)

	// List all sessions
	sessions, err := mem.ListSessions(ctx, 100) // Max 100
	if err != nil {
		return fmt.Errorf("Failed to list sessions: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println(i18n.T("session.list.empty"))
		return nil
	}

	// Use tabwriter for formatted output
	fmt.Println(i18n.T("session.list.title"))
	for _, session := range sessions {
		fmt.Println(i18n.Sprintf("session.list.item",
			session.ID,
			session.Title,
			formatTime(session.CreatedAt),
			formatTime(session.UpdatedAt),
		))
	}

	return nil
}

func runSessionsShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse session ID
	sessionID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("Invalid session ID: %s", args[0])
	}

	// Open database
	dbPath := ".koopa/koopa.db"
	sqlDB, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf(i18n.T("error.database"), err)
	}
	defer sqlDB.Close()

	// Create memory instance
	mem := memory.New(sqlDB)

	// Get session information
	session, err := mem.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("Failed to get session: %w", err)
	}

	// Get all messages for session
	messages, err := mem.GetMessages(ctx, sessionID, 0) // 0 = all messages
	if err != nil {
		return fmt.Errorf("Failed to get messages: %w", err)
	}

	// Display session information
	fmt.Printf("Session ID: %d\n", session.ID)
	fmt.Printf("Title: %s\n", session.Title)
	fmt.Printf("Created: %s\n", formatTime(session.CreatedAt))
	fmt.Printf("Updated: %s\n", formatTime(session.UpdatedAt))
	fmt.Printf("Messages: %d\n", len(messages))
	fmt.Println()
	fmt.Println("───────────────────────────────────────")
	fmt.Println()

	// Display messages
	for _, msg := range messages {
		role := "You"
		if msg.Role == "model" {
			role = "Koopa"
		}
		fmt.Printf("%s> %s\n", role, msg.Content)
		fmt.Println()
	}

	return nil
}

func runSessionsDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse session ID
	sessionID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("Invalid session ID: %s", args[0])
	}

	// Open database
	dbPath := ".koopa/koopa.db"
	sqlDB, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf(i18n.T("error.database"), err)
	}
	defer sqlDB.Close()

	// Create memory instance
	mem := memory.New(sqlDB)

	// Delete session
	if err := mem.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf(i18n.Sprintf("session.delete.fail", err))
	}

	fmt.Println(i18n.Sprintf("session.delete.ok", sessionID))
	return nil
}

// formatTime formats time in a human-readable format
func formatTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	case diff < 7*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	default:
		return t.Format("2006-01-02 15:04")
	}
}
