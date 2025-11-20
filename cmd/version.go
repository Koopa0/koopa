package cmd

import (
	"fmt"
	"os"

	"github.com/koopa0/koopa-cli/internal/config"
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
		Short: "Show version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Pass global version variables as parameters to avoid test data races
			return runVersion(cfg, AppVersion, BuildTime, GitCommit)
		},
	}
}

// runVersion displays version and configuration information
// Parameters are passed explicitly to avoid global state mutation in tests
func runVersion(cfg *config.Config, appVersion, buildTime, gitCommit string) error {
	// Display version information (from ldflags)
	fmt.Printf("Koopa %s\n", appVersion)
	fmt.Printf("Build Time: %s\n", buildTime)
	fmt.Printf("Git Commit: %s\n", gitCommit)
	fmt.Println()

	// Display configuration information
	fmt.Println("Configuration:")
	fmt.Printf("  Model: %s\n", cfg.ModelName)
	fmt.Printf("  Temperature: %.2f\n", cfg.Temperature)
	fmt.Printf("  Max tokens: %d\n", cfg.MaxTokens)
	fmt.Printf("  Database: %s\n", cfg.DatabasePath)

	// Check API Key from environment (don't display full content)
	geminiKey := os.Getenv("GEMINI_API_KEY")

	if geminiKey != "" {
		// Mask API key safely, handling short keys without panic
		var masked string
		if len(geminiKey) >= 8 {
			// Standard masking: show first 4 and last 4 chars
			masked = fmt.Sprintf("%s...%s", geminiKey[:4], geminiKey[len(geminiKey)-4:])
		} else if len(geminiKey) > 0 {
			// For very short keys, just show asterisks
			masked = "****"
		}
		fmt.Printf("  GEMINI_API_KEY: %s (configured)\n", masked)
	} else {
		fmt.Println("  GEMINI_API_KEY: Not set")
		fmt.Println()
		fmt.Println("Hint: Please set GEMINI_API_KEY environment variable")
		fmt.Println("  export GEMINI_API_KEY=your-api-key")
	}

	return nil
}
