// Package cmd implements command-line interface using Cobra.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/koopa0/koopa-cli/internal/config"
	"github.com/spf13/cobra"
)

// NewRootCmd creates the root command (factory pattern, no global state)
func NewRootCmd(cfg *config.Config) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "koopa",
		Short: "Your terminal AI personal assistant",
		Long:  "Koopa - Your terminal AI personal assistant powered by Genkit",
		// No default RunE - subcommands must be specified explicitly
	}

	// PersistentPreRunE: runs before any command
	// Handles API Key validation (declarative via annotations)
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Check if this command requires API Key (declarative via annotations)
		if cmd.Annotations["requiresAPIKey"] == "true" {
			// Check for GEMINI_API_KEY (trim whitespace to reject whitespace-only keys)
			apiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
			if apiKey == "" {
				fmt.Fprintln(os.Stderr, "Error: GEMINI_API_KEY environment variable not set or contains only whitespace")
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintln(os.Stderr, "Please run:")
				fmt.Fprintln(os.Stderr, "  export GEMINI_API_KEY=your-api-key")
				return fmt.Errorf("GEMINI_API_KEY not set")
			}
		}

		return nil
	}

	return rootCmd
}
