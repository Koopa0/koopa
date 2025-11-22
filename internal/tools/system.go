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
// Architecture: Kit methods implement all business logic with security validation.
// Tools are registered to Genkit via Kit.Register() for use by the Agent.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
)

// ============================================================================
// Kit Methods (Phase 1 - New Architecture)
// ============================================================================

// CurrentTime returns the current system date and time.
//
// Error handling:
//   - Never returns error (always succeeds)
func (k *Kit) CurrentTime(ctx *ai.ToolContext, input CurrentTimeInput) (Result, error) {
	k.log("info", "CurrentTime called")

	now := time.Now()
	formatted := now.Format("2006-01-02 15:04:05 (Monday)")

	k.log("info", "CurrentTime succeeded")
	return Result{
		Status:  StatusSuccess,
		Message: "Successfully retrieved current time",
		Data: map[string]any{
			"time":      formatted,
			"timestamp": now.Unix(),
			"iso8601":   now.Format(time.RFC3339),
		},
	}, nil
}

// ExecuteCommand executes a system shell command with security validation.
//
// Error handling:
//   - Agent Error (dangerous command, execution failed, timeout): Return Result{Error: ...}, nil
//   - System Error (internal failure): Return Result{}, error (rare)
func (k *Kit) ExecuteCommand(ctx *ai.ToolContext, input ExecuteCommandInput) (Result, error) {
	k.log("info", "ExecuteCommand called", "command", input.Command, "args", input.Args)

	// Command security validation (prevent command injection attacks CWE-78)
	if err := k.cmdVal.ValidateCommand(input.Command, input.Args); err != nil {
		k.log("error", "ExecuteCommand dangerous command rejected", "command", input.Command, "args", input.Args, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Dangerous command rejected",
			Error: &Error{
				Code: ErrCodeSecurity,
				Message: fmt.Sprintf("security warning: dangerous command rejected (%s %s): %v",
					input.Command, strings.Join(input.Args, " "), err),
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
		// Check if it was cancelled by context
		if execCtx.Err() != nil {
			k.log("error", "ExecuteCommand cancelled", "command", input.Command, "error", execCtx.Err())
			return Result{
				Status:  StatusError,
				Message: "Command execution cancelled",
				Error: &Error{
					Code:    ErrCodeTimeout,
					Message: fmt.Sprintf("command execution cancelled: %v", execCtx.Err()),
				},
			}, nil
		}

		k.log("error", "ExecuteCommand failed", "command", input.Command, "error", err, "output", string(output))
		return Result{
			Status:  StatusError,
			Message: "Command execution failed",
			Error: &Error{
				Code:    ErrCodeExecution,
				Message: fmt.Sprintf("command execution failed: %v (output: %s)", err, string(output)),
			},
		}, nil
	}

	// Success
	k.log("info", "ExecuteCommand succeeded", "command", input.Command, "output_length", len(output))
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully executed: %s %s", input.Command, strings.Join(input.Args, " ")),
		Data: map[string]any{
			"command": input.Command,
			"args":    input.Args,
			"output":  string(output),
		},
	}, nil
}

// GetEnv reads an environment variable value with security protection.
//
// Error handling:
//   - Agent Error (sensitive variable blocked): Return Result{Error: ...}, nil
//   - Success (variable not set): Return Result{Status: success, Data: {value: ""}}
func (k *Kit) GetEnv(ctx *ai.ToolContext, input GetEnvInput) (Result, error) {
	k.log("info", "GetEnv called", "key", input.Key)

	// Environment variable security validation (prevent sensitive information leakage)
	if err := k.envVal.ValidateEnvAccess(input.Key); err != nil {
		k.log("error", "GetEnv sensitive variable blocked", "key", input.Key, "error", err)
		return Result{
			Status:  StatusError,
			Message: "Sensitive environment variable blocked",
			Error: &Error{
				Code:    ErrCodeSecurity,
				Message: fmt.Sprintf("security warning: %v (protected environment variable)", err),
			},
		}, nil
	}

	value := os.Getenv(input.Key)
	isSet := value != ""

	k.log("info", "GetEnv succeeded", "key", input.Key, "is_set", isSet)
	return Result{
		Status:  StatusSuccess,
		Message: fmt.Sprintf("Successfully retrieved environment variable: %s", input.Key),
		Data: map[string]any{
			"key":    input.Key,
			"value":  value,
			"is_set": isSet,
		},
	}, nil
}
