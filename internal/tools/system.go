package tools

// system.go defines system-related tools with security validation.
//
// Provides 3 system tools:
//   - currentTime: Returns formatted timestamp (2006-01-02 15:04:05 Monday)
//   - executeCommand: Executes commands with validation (blocks rm -rf, sudo, shutdown, etc.)
//   - getEnv: Reads environment variables with protection (blocks *KEY*, *SECRET*, *TOKEN*, etc.)
//
// All operations use security validators to prevent command injection (CWE-78) and information leakage.
//
// Architecture: Genkit closures act as thin adapters that convert JSON input
// to Handler method calls. Business logic lives in testable Handler methods.

import (
	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// registerSystemTools registers system-related tools
// handler contains all business logic for system operations
func registerSystemTools(g *genkit.Genkit, handler *Handler) {
	// 1. Get current time
	genkit.DefineTool(
		g,
		"currentTime",
		"Get the current system date and time. "+
			"Returns the current timestamp in human-readable format with date, time, and day of week. "+
			"Use this when you need to know the current time, date calculations, or timestamp information. "+
			"Useful for: time-based operations, logging timestamps, scheduling tasks, date-aware responses.",
		func(ctx *ai.ToolContext, input struct{}) (string, error) {
			return handler.CurrentTime()
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
			return handler.ExecuteCommand(input.Command, input.Args)
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
			return handler.GetEnv(input.Name)
		},
	)
}
