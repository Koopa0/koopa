package tools

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// registerSystemTools registers system-related tools
// Validators are passed as parameters and captured by closures (Go best practice)
func registerSystemTools(g *genkit.Genkit, cmdValidator *security.CommandValidator, envValidator *security.EnvValidator) {
	// 1. Get current time
	genkit.DefineTool(
		g, "currentTime", "Get current time",
		func(ctx *ai.ToolContext, input struct{}) (string, error) {
			now := time.Now()
			return now.Format("2006-01-02 15:04:05 (Monday)"), nil
		},
	)

	// 2. Execute system command
	genkit.DefineTool(
		g, "executeCommand", "Execute system command (use with caution, dangerous commands are automatically checked)",
		func(ctx *ai.ToolContext, input struct {
			Command string   `json:"command" jsonschema_description:"Command to execute"`
			Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments (optional)"`
		}) (string, error) {
			// Command security validation (prevent command injection attacks CWE-78)
			if err := cmdValidator.ValidateCommand(input.Command, input.Args); err != nil {
				return "", fmt.Errorf("⚠️  Security warning: Dangerous command rejected\nCommand: %s %s\nReason: %w\nIf you need to execute this, please run it manually in the terminal",
					input.Command, strings.Join(input.Args, " "), err)
			}

			cmd := exec.Command(input.Command, input.Args...) // #nosec G204 -- validated by cmdValidator above
			output, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("command execution failed: %w\nOutput: %s", err, string(output))
			}
			return string(output), nil
		},
	)

	// 3. Read environment variable (restricted access)
	genkit.DefineTool(
		g, "getEnv", "Read environment variable (sensitive variables are protected)",
		func(ctx *ai.ToolContext, input struct {
			Name string `json:"name" jsonschema_description:"Environment variable name"`
		}) (string, error) {
			// Environment variable security validation (prevent sensitive information leakage)
			if err := envValidator.ValidateEnvAccess(input.Name); err != nil {
				return "", fmt.Errorf("⚠️  Security warning: %w\nNote: This environment variable may contain sensitive information and is protected.\nIf you need to access it, please check it directly in the terminal", err)
			}

			value := os.Getenv(input.Name)
			if value == "" {
				return fmt.Sprintf("Environment variable %s is not set or is empty", input.Name), nil
			}
			return value, nil
		},
	)
}
