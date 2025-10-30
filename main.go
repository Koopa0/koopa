package main

import (
	"fmt"
	"os"

	"github.com/koopa0/koopa/cmd"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/database"
)

func main() {
	// Initialize database
	dbPath := ".koopa/koopa.db"
	db, err := database.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := database.Migrate(db); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to migrate database: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Create root command with API Key validation (factory pattern)
	rootCmd := cmd.NewRootCmd(cfg)

	// Register subcommands with dependency injection (no global variables)
	rootCmd.AddCommand(cmd.NewChatCmd(db, cfg, cmd.AppVersion))
	rootCmd.AddCommand(cmd.NewAskCmd(cfg))
	rootCmd.AddCommand(cmd.NewSessionsCmd(db))
	rootCmd.AddCommand(cmd.NewVersionCmd(cfg))

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
