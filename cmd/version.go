package cmd

import (
	"fmt"

	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: i18n.T("version.description"),
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Println("Koopa v0.1.0-alpha (Development)")
	fmt.Println()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf(i18n.T("error.config"), err)
	}

	// Display configuration information
	fmt.Println("Configuration:")
	fmt.Println(i18n.Sprintf("config.model", cfg.ModelName))
	fmt.Println(i18n.Sprintf("config.temperature", cfg.Temperature))
	fmt.Println(i18n.Sprintf("config.max.tokens", cfg.MaxTokens))
	fmt.Printf("  Database: %s\n", cfg.DatabasePath)

	// Check API Key (don't display full content)
	if cfg.GeminiAPIKey != "" {
		fmt.Printf("  Gemini API Key: %s...%s (configured)\n",
			cfg.GeminiAPIKey[:4],
			cfg.GeminiAPIKey[len(cfg.GeminiAPIKey)-4:])
	} else {
		fmt.Println("  Gemini API Key: Not set")
		fmt.Println()
		fmt.Println("Hint: Please set KOOPA_GEMINI_API_KEY environment variable")
		fmt.Println("  export KOOPA_GEMINI_API_KEY=your-api-key")
	}

	return nil
}
