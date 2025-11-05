package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/koopa0/koopa/internal/i18n"
	"github.com/koopa0/koopa/internal/memory"
	"github.com/spf13/cobra"
)

// NewSessionsCmd creates the sessions command (factory pattern)
func NewSessionsCmd(db *sql.DB) *cobra.Command {
	sessionsCmd := &cobra.Command{
		Use:   "sessions",
		Short: i18n.T("sessions.description"),
	}

	// Add subcommands
	sessionsCmd.AddCommand(newSessionsListCmd(db))
	sessionsCmd.AddCommand(newSessionsShowCmd(db))
	sessionsCmd.AddCommand(newSessionsDeleteCmd(db))

	return sessionsCmd
}

func newSessionsListCmd(db *sql.DB) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: i18n.T("sessions.list.description"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionsList(cmd.Context(), db)
		},
	}
}

func newSessionsShowCmd(db *sql.DB) *cobra.Command {
	return &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show specific session messages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionsShow(cmd.Context(), db, args)
		},
	}
}

func newSessionsDeleteCmd(db *sql.DB) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <session-id>",
		Short: i18n.T("sessions.delete.description"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionsDelete(cmd.Context(), db, args)
		},
	}
}

func runSessionsList(ctx context.Context, db *sql.DB) error {
	// Create memory instance
	mem := memory.New(db, nil)

	// List all sessions
	sessions, err := mem.ListSessions(ctx, 100) // Max 100
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
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

func runSessionsShow(ctx context.Context, db *sql.DB, args []string) error {
	// Parse session ID
	sessionID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid session ID: %s", args[0])
	}

	// Create memory instance
	mem := memory.New(db, nil)

	// Get session information
	session, err := mem.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Get all messages for session
	messages, err := mem.GetMessages(ctx, sessionID, 0) // 0 = all messages
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
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

func runSessionsDelete(ctx context.Context, db *sql.DB, args []string) error {
	// Parse session ID
	sessionID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid session ID: %s", args[0])
	}

	// Create memory instance
	mem := memory.New(db, nil)

	// Delete session
	if err := mem.DeleteSession(ctx, sessionID); err != nil {
		return errors.New(i18n.Sprintf("session.delete.fail", err))
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
