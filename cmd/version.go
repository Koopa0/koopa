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
	fmt.Printf("  Model: %s\n", cfg.ModelName)
	fmt.Printf("  Temperature: %.2f\n", cfg.Temperature)
	fmt.Printf("  Max tokens: %d\n", cfg.MaxTokens)
	fmt.Printf("  Database: %s\n", cfg.DatabasePath)

	// Check API Key from environment (don't display full content)
	geminiKey := os.Getenv("GEMINI_API_KEY")

	if geminiKey != "" {
		fmt.Printf("  GEMINI_API_KEY: %s...%s (configured)\n",
			geminiKey[:4],
			geminiKey[len(geminiKey)-4:])
	} else {
		fmt.Println("  GEMINI_API_KEY: Not set")
		fmt.Println()
		fmt.Println("Hint: Please set GEMINI_API_KEY environment variable")
		fmt.Println("  export GEMINI_API_KEY=your-api-key")
	}

	return nil
}
