package tools

// system.go defines system-related tools with security validation.
//
// Provides 3 system tools:
//   - currentTime: Returns formatted timestamp (2006-01-02 15:04:05 Monday)
//   - executeCommand: Executes commands with validation (blocks rm -rf, sudo, shutdown, etc.)
//   - getEnv: Reads environment variables with protection (blocks *KEY*, *SECRET*, *TOKEN*, etc.)
//
// All operations use security validators to prevent command injection (CWE-78) and information leakage.

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
func registerSystemTools(g *genkit.Genkit, cmdValidator *security.Command, envValidator *security.Env) {
	// 1. Get current time
	genkit.DefineTool(
		g,
		"currentTime",
		"Get the current system date and time. "+
			"Returns the current timestamp in human-readable format with date, time, and day of week. "+
			"Use this when you need to know the current time, date calculations, or timestamp information. "+
			"Useful for: time-based operations, logging timestamps, scheduling tasks, date-aware responses.",
		func(ctx *ai.ToolContext, input struct{}) (string, error) {
			now := time.Now()
			return now.Format("2006-01-02 15:04:05 (Monday)"), nil
		},
	)

	// 2. Execute system command
	genkit.DefineTool(
		g,
		"executeCommand",
		"Execute a system shell command with security validation. "+
			"WARNING: Dangerous commands (rm -rf, dd, format, etc.) are automatically blocked for safety. "+
			"Use this to run system utilities, git commands, build tools, or other safe operations. "+
			"Security features: command validation, argument sanitization, prevents command injection (CWE-78). "+
			"Returns the combined stdout and stderr output. "+
			"Use for: running git commands, executing build scripts, checking system status, running test suites.",
		func(ctx *ai.ToolContext, input struct {
			Command string   `json:"command" jsonschema_description:"Command to execute (e.g., 'ls', 'git', 'go'). Dangerous commands are automatically blocked."`
			Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments as separate array elements. Examples: ['status'], ['-la', '/home'], ['build', './...']"`
		},
		) (string, error) {
			// Command security validation (prevent command injection attacks CWE-78)
			if err := cmdValidator.ValidateCommand(input.Command, input.Args); err != nil {
				return "", fmt.Errorf("security warning: dangerous command rejected (%s %s): %w",
					input.Command, strings.Join(input.Args, " "), err)
			}

			cmd := exec.Command(input.Command, input.Args...) // #nosec G204 -- validated by cmdValidator above
			output, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("command execution failed: %w (output: %s)", err, string(output))
			}
			return string(output), nil
		},
	)

	// 3. Read environment variable (restricted access)
	genkit.DefineTool(
		g,
		"getEnv",
		"Read an environment variable value with security protection. "+
			"Sensitive variables (API keys, passwords, tokens) are automatically blocked to prevent information leakage. "+
			"Use this to check system configuration, paths, or non-sensitive environment settings. "+
			"Returns the variable value or an empty message if not set. "+
			"Blocked patterns: *KEY*, *SECRET*, *TOKEN*, *PASSWORD*, *CREDENTIAL*. "+
			"Use for: checking PATH, HOME, SHELL, or other non-sensitive configuration variables.",
		func(ctx *ai.ToolContext, input struct {
			Name string `json:"name" jsonschema_description:"Environment variable name to read (e.g., 'PATH', 'HOME', 'SHELL'). Sensitive variables like API_KEY are automatically blocked."`
		},
		) (string, error) {
			// Environment variable security validation (prevent sensitive information leakage)
			if err := envValidator.ValidateEnvAccess(input.Name); err != nil {
				return "", fmt.Errorf("security warning: %w (protected environment variable)", err)
			}

			value := os.Getenv(input.Name)
			if value == "" {
				return fmt.Sprintf("environment variable %s is not set or is empty", input.Name), nil
			}
			return value, nil
		},
	)
}
