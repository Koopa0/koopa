package cmd

import (
	"fmt"
	"os"

	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/spf13/cobra"
)

// NewRootCmd creates the root command (factory pattern, no global state)
func NewRootCmd(cfg *config.Config) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "koopa",
		Short: i18n.T("app.description"),
		Long:  i18n.T("root.description"),
		// No default RunE - subcommands must be specified explicitly
	}

	// Add global --lang flag
	rootCmd.PersistentFlags().StringP("lang", "l", "", i18n.T("root.lang.flag"))

	// PersistentPreRunE: runs before any command
	// Handles language flag and API Key validation (declarative via annotations)
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Handle language flag
		if lang, _ := cmd.Flags().GetString("lang"); lang != "" {
			i18n.SetLanguage(lang)
		}

		// Check if this command requires API Key (declarative via annotations)
		if cmd.Annotations["requiresAPIKey"] == "true" {
			if cfg.GeminiAPIKey == "" {
				fmt.Fprintln(os.Stderr, "Error: KOOPA_GEMINI_API_KEY environment variable not set")
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprintln(os.Stderr, "Please run:")
				fmt.Fprintln(os.Stderr, "  export KOOPA_GEMINI_API_KEY=your-api-key")
				return fmt.Errorf("KOOPA_GEMINI_API_KEY not set")
			}
		}

		return nil
	}

	return rootCmd
}
