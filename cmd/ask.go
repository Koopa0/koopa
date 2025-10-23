package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/koopa0/koopa/internal/agent"
	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/i18n"
	"github.com/spf13/cobra"
)

var useTools bool

var askCmd = &cobra.Command{
	Use:   "ask [question]",
	Short: i18n.T("ask.description"),
	Args:  cobra.MinimumNArgs(1),
	RunE:  runAsk,
}

func init() {
	askCmd.Flags().BoolVar(&useTools, "tools", false, i18n.T("ask.tools.flag"))
	rootCmd.AddCommand(askCmd)
}

func runAsk(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf(i18n.T("error.config"), err)
	}

	// Check API Key
	if cfg.GeminiAPIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: KOOPA_GEMINI_API_KEY environment variable not set")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Please run:")
		fmt.Fprintln(os.Stderr, "  export KOOPA_GEMINI_API_KEY=your-api-key")
		return fmt.Errorf("KOOPA_GEMINI_API_KEY not set")
	}

	// Create Agent
	ag, err := agent.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf(i18n.T("error.agent"), err)
	}

	// Merge all arguments as question
	question := strings.Join(args, " ")
	if question == "" {
		return fmt.Errorf(i18n.T("error.question.empty"))
	}

	// Ask AI
	var answer string
	if useTools {
		answer, err = ag.AskWithTools(ctx, question)
	} else {
		answer, err = ag.Ask(ctx, question)
	}
	if err != nil {
		return fmt.Errorf(i18n.T("error.generate"), err)
	}

	// Display response
	fmt.Println(answer)

	return nil
}
