package cmd

import (
	"fmt"

	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/spf13/cobra"
)

// Version information (injected at build time via ldflags)
var (
	AppVersion = "development"
	BuildTime  = "unknown"
	GitCommit  = "unknown"
)

// NewVersionCmd creates the version command (factory pattern)
func NewVersionCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: i18n.T("version.description"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion(cfg)
		},
	}
}

func runVersion(cfg *config.Config) error {
	// Display version information (from ldflags)
	fmt.Printf("Koopa %s\n", AppVersion)
	fmt.Printf("Build Time: %s\n", BuildTime)
	fmt.Printf("Git Commit: %s\n", GitCommit)
	fmt.Println()

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
