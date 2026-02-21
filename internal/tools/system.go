package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa/internal/security"
)

// Tool name constants for system operations registered with Genkit.
const (
	// CurrentTimeName is the Genkit tool name for retrieving the current time.
	CurrentTimeName = "current_time"
	// ExecuteCommandName is the Genkit tool name for executing shell commands.
	ExecuteCommandName = "execute_command"
	// GetEnvName is the Genkit tool name for reading environment variables.
	GetEnvName = "get_env"
)

// ExecuteCommandInput defines input for execute_command tool.
type ExecuteCommandInput struct {
	Command string   `json:"command" jsonschema_description:"The command to execute (e.g., 'ls', 'git')"`
	Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments as separate array elements"`
}

// MaxEnvKeyLength is the maximum allowed environment variable name length (256 bytes).
const MaxEnvKeyLength = 256

// MaxCommandArgLength is the maximum total length of command + args in bytes.
// Prevents abuse via extremely long command strings.
const MaxCommandArgLength = 10000

// EnvInput defines input for get_env tool.
type EnvInput struct {
	Key string `json:"key" jsonschema_description:"The environment variable name"`
}

// CurrentTimeInput defines input for current_time tool (no input needed).
type CurrentTimeInput struct{}

// System holds dependencies for system operation handlers.
// Use NewSystem to create an instance, then either:
// - Call methods directly (for MCP)
// - Use RegisterSystem to register with Genkit
type System struct {
	cmdVal *security.Command
	envVal *security.Env
	logger *slog.Logger
}

// NewSystem creates a System instance.
func NewSystem(cmdVal *security.Command, envVal *security.Env, logger *slog.Logger) (*System, error) {
	if cmdVal == nil {
		return nil, fmt.Errorf("command validator is required")
	}
	if envVal == nil {
		return nil, fmt.Errorf("env validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &System{cmdVal: cmdVal, envVal: envVal, logger: logger}, nil
}

// RegisterSystem registers all system operation tools with Genkit.
// Tools are registered with event emission wrappers for streaming support.
func RegisterSystem(g *genkit.Genkit, st *System) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if st == nil {
		return nil, fmt.Errorf("System is required")
	}

	return []ai.Tool{
		genkit.DefineTool(g, CurrentTimeName,
			"Get the current system date and time. "+
				"Returns: formatted time string, Unix timestamp, and ISO 8601 format. "+
				"Use this to: check current time, calculate relative times, add timestamps to outputs. "+
				"Always returns the server's local time zone. "+
				"IMPORTANT: You MUST call this tool before answering ANY question about current dates, times, ages, durations, or 'how long ago' something happened.",
			WithEvents(CurrentTimeName, st.CurrentTime)),
		genkit.DefineTool(g, ExecuteCommandName,
			"Execute a shell command from the allowed list with security validation. "+
				"Allowed commands: ls, pwd, cd, tree, date, whoami, hostname, uname, df, du, free, top, ps, "+
				"git (with subcommand restrictions), go (version/env/vet/doc/fmt/list only), npm/yarn (read-only queries), which, whereis. "+
				"Commands run with a timeout to prevent hanging. "+
				"Returns: stdout, stderr, exit code, and execution time. "+
				"Use this for: checking git status, listing files, viewing system info. "+
				"Security: Commands not in the allowlist are blocked. Subcommands are restricted per command.",
			WithEvents(ExecuteCommandName, st.ExecuteCommand)),
		genkit.DefineTool(g, GetEnvName,
			"Read an environment variable value from the system. "+
				"Returns: the variable name and its value. "+
				"Use this to: check configuration, verify paths, read non-sensitive settings. "+
				"Security: Sensitive variables containing KEY, SECRET, TOKEN, or PASSWORD in their names are protected and will not be returned.",
			WithEvents(GetEnvName, st.Env)),
	}, nil
}

// CurrentTime returns the current system date and time in multiple formats.
func (s *System) CurrentTime(_ *ai.ToolContext, _ CurrentTimeInput) (Result, error) {
	s.logger.Debug("CurrentTime called")
	now := time.Now()
	s.logger.Debug("CurrentTime succeeded")
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"time":      now.Format("2006-01-02 15:04:05"),
			"timestamp": now.Unix(),
			"iso8601":   now.Format(time.RFC3339),
		},
	}, nil
}

// ExecuteCommand executes a system shell command with security validation.
// Dangerous commands like rm -rf, sudo, and shutdown are blocked.
// Business errors (blocked commands, execution failures) are returned in Result.Error.
// Only context cancellation returns a Go error.
func (s *System) ExecuteCommand(ctx *ai.ToolContext, input ExecuteCommandInput) (Result, error) {
	s.logger.Debug("ExecuteCommand called", "command", input.Command, "args", input.Args)

	// Validate total command + args length
	totalLen := len(input.Command)
	for _, a := range input.Args {
		totalLen += len(a)
	}
	if totalLen > MaxCommandArgLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("command + args length %d exceeds maximum %d bytes", totalLen, MaxCommandArgLength),
			},
		}, nil
	}

	// Command security validation (prevent command injection attacks CWE-78)
	if err := s.cmdVal.Validate(input.Command, input.Args); err != nil {
		s.logger.Warn("ExecuteCommand dangerous command rejected", "command", input.Command, "args", input.Args, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "command not permitted",
			},
		}, nil
	}

	// Use CommandContext for cancellation support
	execCtx := ctx.Context
	if execCtx == nil {
		execCtx = context.Background()
	}

	cmd := exec.CommandContext(execCtx, input.Command, input.Args...) // #nosec G204 -- validated by cmdVal above
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it was canceled by context - this is infrastructure error
		if execCtx.Err() != nil {
			return Result{}, fmt.Errorf("command execution canceled: %w", execCtx.Err())
		}

		// Command execution failure is a business error
		s.logger.Warn("executing command", "command", input.Command, "error", err, "output", string(output))
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: "command execution failed",
				Details: map[string]any{
					"command": input.Command,
					"args":    strings.Join(input.Args, " "),
					"hint":    "check server logs for details",
					"success": false,
				},
			},
		}, nil
	}

	s.logger.Debug("ExecuteCommand succeeded", "command", input.Command, "output_length", len(output))
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"command": input.Command,
			"args":    strings.Join(input.Args, " "),
			"output":  string(output),
			"success": true,
		},
	}, nil
}

// Env reads an environment variable value with security protection.
// Sensitive variables containing KEY, SECRET, or TOKEN in the name are blocked.
// Business errors (sensitive variable blocked) are returned in Result.Error.
func (s *System) Env(_ *ai.ToolContext, input EnvInput) (Result, error) {
	s.logger.Debug("Env called", "key", input.Key)

	if len(input.Key) > MaxEnvKeyLength {
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("env key length %d exceeds maximum %d bytes", len(input.Key), MaxEnvKeyLength),
			},
		}, nil
	}

	// Environment variable security validation (prevent sensitive information leakage)
	if err := s.envVal.Validate(input.Key); err != nil {
		s.logger.Warn("Env sensitive variable blocked", "key", input.Key, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: "access to sensitive variable blocked",
			},
		}, nil
	}

	value, isSet := os.LookupEnv(input.Key)

	s.logger.Debug("Env succeeded", "key", input.Key, "is_set", isSet)
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"key":   input.Key,
			"value": value,
			"isSet": isSet,
		},
	}, nil
}
