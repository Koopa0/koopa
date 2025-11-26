package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/log"
	"github.com/koopa0/koopa-cli/internal/security"
)

// SystemToolsetName is the toolset identifier constant.
const SystemToolsetName = "system"

// ExecuteCommandInput defines input for executeCommand tool.
type ExecuteCommandInput struct {
	Command string   `json:"command" jsonschema_description:"The command to execute (e.g., 'ls', 'git')"`
	Args    []string `json:"args,omitempty" jsonschema_description:"Command arguments as separate array elements"`
}

// GetEnvInput defines input for getEnv tool.
type GetEnvInput struct {
	Key string `json:"key" jsonschema_description:"The environment variable name"`
}

// CurrentTimeInput defines input for currentTime tool (no input needed).
type CurrentTimeInput struct{}

// SystemToolset provides system-level operation tools with built-in security validations.
// It implements the Toolset interface and offers 3 tools:
//   - currentTime: Returns formatted timestamp
//   - executeCommand: Executes shell commands with security validation (blocks rm -rf, sudo, shutdown, etc.)
//   - getEnv: Reads environment variables with protection (blocks *KEY*, *SECRET*, *TOKEN*, etc.)
//
// All operations use security validators to prevent command injection (CWE-78) and information disclosure.
type SystemToolset struct {
	cmdVal *security.Command
	envVal *security.Env
	logger log.Logger
}

// NewSystemToolset creates a new SystemToolset with command and environment validators.
func NewSystemToolset(cmdVal *security.Command, envVal *security.Env, logger log.Logger) (*SystemToolset, error) {
	if cmdVal == nil {
		return nil, fmt.Errorf("command validator is required")
	}
	if envVal == nil {
		return nil, fmt.Errorf("env validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &SystemToolset{
		cmdVal: cmdVal,
		envVal: envVal,
		logger: logger,
	}, nil
}

// Name returns the toolset identifier.
func (st *SystemToolset) Name() string {
	return SystemToolsetName
}

// Tools returns all system operation tools provided by this toolset.
func (st *SystemToolset) Tools(ctx agent.ReadonlyContext) ([]Tool, error) {
	return []Tool{
		NewTool(
			"currentTime",
			"Get the current system date and time in formatted string",
			false,
			st.CurrentTime,
		),
		NewTool(
			"executeCommand",
			"Execute a shell command with security validation. Dangerous commands (rm -rf, sudo, etc.) are blocked.",
			true, // long running
			st.ExecuteCommand,
		),
		NewTool(
			"getEnv",
			"Read an environment variable value. Sensitive variables (*KEY*, *SECRET*, *TOKEN*) are protected.",
			false,
			st.GetEnv,
		),
	}, nil
}

// Output type definitions follow.

// CurrentTimeOutput is the output for currentTime tool
type CurrentTimeOutput struct {
	Time      string `json:"time" jsonschema_description:"Formatted time string (2006-01-02 15:04:05)"`
	Timestamp int64  `json:"timestamp" jsonschema_description:"Unix timestamp"`
	ISO8601   string `json:"iso8601" jsonschema_description:"ISO 8601 formatted time"`
}

// ExecuteCommandOutput is the output for executeCommand tool
type ExecuteCommandOutput struct {
	Command string `json:"command" jsonschema_description:"Executed command"`
	Args    string `json:"args" jsonschema_description:"Command arguments"`
	Output  string `json:"output" jsonschema_description:"Command output (stdout and stderr)"`
	Success bool   `json:"success" jsonschema_description:"Whether command executed successfully"`
}

// GetEnvOutput is the output for getEnv tool
type GetEnvOutput struct {
	Key   string `json:"key" jsonschema_description:"Environment variable name"`
	Value string `json:"value" jsonschema_description:"Environment variable value"`
	IsSet bool   `json:"isSet" jsonschema_description:"Whether the variable is set"`
}

// CurrentTime returns the current system date and time in multiple formats.
func (st *SystemToolset) CurrentTime(ctx *ai.ToolContext, input CurrentTimeInput) (CurrentTimeOutput, error) {
	st.logger.Info("CurrentTime called")

	now := time.Now()
	formatted := now.Format("2006-01-02 15:04:05")

	st.logger.Info("CurrentTime succeeded")
	return CurrentTimeOutput{
		Time:      formatted,
		Timestamp: now.Unix(),
		ISO8601:   now.Format(time.RFC3339),
	}, nil
}

// ExecuteCommand executes a system shell command with security validation.
// Dangerous commands like rm -rf, sudo, and shutdown are blocked.
func (st *SystemToolset) ExecuteCommand(ctx *ai.ToolContext, input ExecuteCommandInput) (ExecuteCommandOutput, error) {
	st.logger.Info("ExecuteCommand called", "command", input.Command, "args", input.Args)

	// Command security validation (prevent command injection attacks CWE-78)
	if err := st.cmdVal.ValidateCommand(input.Command, input.Args); err != nil {
		st.logger.Error("ExecuteCommand dangerous command rejected", "command", input.Command, "args", input.Args, "error", err)
		return ExecuteCommandOutput{}, fmt.Errorf("dangerous command rejected: %w", err)
	}

	// Use CommandContext for cancellation support
	execCtx := ctx.Context
	if execCtx == nil {
		execCtx = context.Background()
	}

	cmd := exec.CommandContext(execCtx, input.Command, input.Args...) // #nosec G204 -- validated by cmdVal above
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check if it was cancelled by context
		if execCtx.Err() != nil {
			st.logger.Error("ExecuteCommand cancelled", "command", input.Command, "error", execCtx.Err())
			return ExecuteCommandOutput{}, fmt.Errorf("command execution cancelled: %w", execCtx.Err())
		}

		st.logger.Error("ExecuteCommand failed", "command", input.Command, "error", err, "output", string(output))
		return ExecuteCommandOutput{
			Command: input.Command,
			Args:    strings.Join(input.Args, " "),
			Output:  string(output),
			Success: false,
		}, fmt.Errorf("command execution failed: %w (output: %s)", err, string(output))
	}

	// Success
	st.logger.Info("ExecuteCommand succeeded", "command", input.Command, "output_length", len(output))
	return ExecuteCommandOutput{
		Command: input.Command,
		Args:    strings.Join(input.Args, " "),
		Output:  string(output),
		Success: true,
	}, nil
}

// GetEnv reads an environment variable value with security protection.
// Sensitive variables containing KEY, SECRET, or TOKEN in the name are blocked.
func (st *SystemToolset) GetEnv(ctx *ai.ToolContext, input GetEnvInput) (GetEnvOutput, error) {
	st.logger.Info("GetEnv called", "key", input.Key)

	// Environment variable security validation (prevent sensitive information leakage)
	if err := st.envVal.ValidateEnvAccess(input.Key); err != nil {
		st.logger.Error("GetEnv sensitive variable blocked", "key", input.Key, "error", err)
		return GetEnvOutput{}, fmt.Errorf("sensitive environment variable blocked: %w", err)
	}

	value := os.Getenv(input.Key)
	isSet := value != ""

	st.logger.Info("GetEnv succeeded", "key", input.Key, "is_set", isSet)
	return GetEnvOutput{
		Key:   input.Key,
		Value: value,
		IsSet: isSet,
	}, nil
}
