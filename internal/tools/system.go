package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"

	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/security"
)

const (
	ToolCurrentTime    = "current_time"
	ToolExecuteCommand = "execute_command"
	ToolGetEnv         = "get_env"
)

// ExecuteCommandInput defines input for execute_command tool.
type ExecuteCommandInput struct {
	Command string   `json:"command" jsonschema_description:"The command to execute (e.g., 'ls', 'git')"`
	Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments as separate array elements"`
}

// GetEnvInput defines input for get_env tool.
type GetEnvInput struct {
	Key string `json:"key" jsonschema_description:"The environment variable name"`
}

// CurrentTimeInput defines input for current_time tool (no input needed).
type CurrentTimeInput struct{}

// SystemTools holds dependencies for system operation handlers.
// Use NewSystemTools to create an instance, then either:
// - Call methods directly (for MCP)
// - Use RegisterSystemTools to register with Genkit
type SystemTools struct {
	cmdVal *security.Command
	envVal *security.Env
	logger log.Logger
}

// NewSystemTools creates a SystemTools instance.
func NewSystemTools(cmdVal *security.Command, envVal *security.Env, logger log.Logger) (*SystemTools, error) {
	if cmdVal == nil {
		return nil, fmt.Errorf("command validator is required")
	}
	if envVal == nil {
		return nil, fmt.Errorf("env validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &SystemTools{cmdVal: cmdVal, envVal: envVal, logger: logger}, nil
}

// RegisterSystemTools registers all system operation tools with Genkit.
// Tools are registered with event emission wrappers for streaming support.
func RegisterSystemTools(g *genkit.Genkit, st *SystemTools) ([]ai.Tool, error) {
	if g == nil {
		return nil, fmt.Errorf("genkit instance is required")
	}
	if st == nil {
		return nil, fmt.Errorf("SystemTools is required")
	}

	return []ai.Tool{
		genkit.DefineTool(g, ToolCurrentTime,
			"Get the current system date and time in formatted string",
			WithEvents(ToolCurrentTime, st.CurrentTime)),
		genkit.DefineTool(g, ToolExecuteCommand,
			"Execute a shell command with security validation. Dangerous commands (rm -rf, sudo, etc.) are blocked.",
			WithEvents(ToolExecuteCommand, st.ExecuteCommand)),
		genkit.DefineTool(g, ToolGetEnv,
			"Read an environment variable value. Sensitive variables (*KEY*, *SECRET*, *TOKEN*) are protected.",
			WithEvents(ToolGetEnv, st.GetEnv)),
	}, nil
}

// CurrentTime returns the current system date and time in multiple formats.
func (s *SystemTools) CurrentTime(_ *ai.ToolContext, _ CurrentTimeInput) (Result, error) {
	s.logger.Info("CurrentTime called")
	now := time.Now()
	s.logger.Info("CurrentTime succeeded")
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
func (s *SystemTools) ExecuteCommand(ctx *ai.ToolContext, input ExecuteCommandInput) (Result, error) {
	s.logger.Info("ExecuteCommand called", "command", input.Command, "args", input.Args)

	// Command security validation (prevent command injection attacks CWE-78)
	if err := s.cmdVal.ValidateCommand(input.Command, input.Args); err != nil {
		s.logger.Error("ExecuteCommand dangerous command rejected", "command", input.Command, "args", input.Args, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("dangerous command rejected: %v", err),
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
			s.logger.Error("ExecuteCommand canceled", "command", input.Command, "error", execCtx.Err())
			return Result{}, fmt.Errorf("command execution canceled: %w", execCtx.Err())
		}

		// Command execution failure is a business error
		s.logger.Error("ExecuteCommand failed", "command", input.Command, "error", err, "output", string(output))
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("command failed: %v", err),
				Details: map[string]any{
					"command": input.Command,
					"args":    strings.Join(input.Args, " "),
					"output":  string(output),
					"success": false,
				},
			},
		}, nil
	}

	s.logger.Info("ExecuteCommand succeeded", "command", input.Command, "output_length", len(output))
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

// GetEnv reads an environment variable value with security protection.
// Sensitive variables containing KEY, SECRET, or TOKEN in the name are blocked.
// Business errors (sensitive variable blocked) are returned in Result.Error.
func (s *SystemTools) GetEnv(_ *ai.ToolContext, input GetEnvInput) (Result, error) {
	s.logger.Info("GetEnv called", "key", input.Key)

	// Environment variable security validation (prevent sensitive information leakage)
	if err := s.envVal.ValidateEnvAccess(input.Key); err != nil {
		s.logger.Error("GetEnv sensitive variable blocked", "key", input.Key, "error", err)
		return Result{
			Status: StatusError,
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("access to sensitive variable blocked: %v", err),
			},
		}, nil
	}

	value, isSet := os.LookupEnv(input.Key)

	s.logger.Info("GetEnv succeeded", "key", input.Key, "is_set", isSet)
	return Result{
		Status: StatusSuccess,
		Data: map[string]any{
			"key":   input.Key,
			"value": value,
			"isSet": isSet,
		},
	}, nil
}
