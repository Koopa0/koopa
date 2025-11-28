package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/security"
)

// TestSystemToolset_NewSystemToolset tests the constructor
func TestSystemToolset_NewSystemToolset(t *testing.T) {
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()

	t.Run("success with validators", func(t *testing.T) {
		st, err := NewSystemToolset(cmdVal, envVal, testLogger())
		if err != nil {
			t.Errorf("NewSystemToolset() unexpected error: %v", err)
		}
		if st == nil {
			t.Error("NewSystemToolset() returned nil")
		}
		if st.Name() != SystemToolsetName {
			t.Errorf("Name() = %s, want %s", st.Name(), SystemToolsetName)
		}
	})

	t.Run("error with nil command validator", func(t *testing.T) {
		_, err := NewSystemToolset(nil, envVal, testLogger())
		if err == nil {
			t.Error("NewSystemToolset() expected error with nil cmdVal")
		}
		if !strings.Contains(err.Error(), "command validator is required") {
			t.Errorf("NewSystemToolset() error = %v, want error containing 'command validator is required'", err)
		}
	})

	t.Run("error with nil env validator", func(t *testing.T) {
		_, err := NewSystemToolset(cmdVal, nil, testLogger())
		if err == nil {
			t.Error("NewSystemToolset() expected error with nil envVal")
		}
		if !strings.Contains(err.Error(), "env validator is required") {
			t.Errorf("NewSystemToolset() error = %v, want error containing 'env validator is required'", err)
		}
	})

	t.Run("error with nil logger", func(t *testing.T) {
		_, err := NewSystemToolset(cmdVal, envVal, nil)
		if err == nil {
			t.Error("NewSystemToolset() expected error with nil logger")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewSystemToolset() error = %v, want error containing 'logger is required'", err)
		}
	})
}

// TestSystemToolset_Tools tests tool list
func TestSystemToolset_Tools(t *testing.T) {
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	st, err := NewSystemToolset(cmdVal, envVal, testLogger())
	if err != nil {
		t.Fatalf("NewSystemToolset() unexpected error: %v", err)
	}

	emptyCtx := &emptyReadonlyContext{}
	tools, err := st.Tools(emptyCtx)
	if err != nil {
		t.Errorf("Tools() unexpected error: %v", err)
	}

	if len(tools) != 3 {
		t.Errorf("Tools() returned %d tools, want 3", len(tools))
	}

	expectedNames := []string{ToolCurrentTime, ToolExecuteCommand, ToolGetEnv}
	for i, tool := range tools {
		if tool.Name() != expectedNames[i] {
			t.Errorf("Tools()[%d].Name() = %s, want %s", i, tool.Name(), expectedNames[i])
		}
	}
}

// TestSystemToolset_CurrentTime tests the CurrentTime tool
func TestSystemToolset_CurrentTime(t *testing.T) {
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	st, err := NewSystemToolset(cmdVal, envVal, testLogger())
	if err != nil {
		t.Fatalf("NewSystemToolset() unexpected error: %v", err)
	}

	ctx := &ai.ToolContext{
		Context: context.Background(),
	}

	output, err := st.CurrentTime(ctx, CurrentTimeInput{})
	if err != nil {
		t.Errorf("CurrentTime() unexpected error: %v", err)
	}

	// Verify output format
	if output.Time == "" {
		t.Error("CurrentTime() Time is empty")
	}
	if output.Timestamp == 0 {
		t.Error("CurrentTime() Timestamp is 0")
	}
	if output.ISO8601 == "" {
		t.Error("CurrentTime() ISO8601 is empty")
	}

	// Verify time format (should be "2006-01-02 15:04:05")
	if !strings.Contains(output.Time, "-") || !strings.Contains(output.Time, ":") {
		t.Errorf("CurrentTime() Time = %s, expected format '2006-01-02 15:04:05'", output.Time)
	}
}

// TestSystemToolset_ExecuteCommand tests the ExecuteCommand tool
func TestSystemToolset_ExecuteCommand(t *testing.T) {
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	st, err := NewSystemToolset(cmdVal, envVal, testLogger())
	if err != nil {
		t.Fatalf("NewSystemToolset() unexpected error: %v", err)
	}

	ctx := &ai.ToolContext{
		Context: context.Background(),
	}

	t.Run("success with safe command", func(t *testing.T) {
		output, err := st.ExecuteCommand(ctx, ExecuteCommandInput{
			Command: "echo",
			Args:    []string{"hello", "world"},
		})
		if err != nil {
			t.Errorf("ExecuteCommand() unexpected error: %v", err)
		}
		if !output.Success {
			t.Error("ExecuteCommand() Success = false, want true")
		}
		if !strings.Contains(output.Output, "hello world") {
			t.Errorf("ExecuteCommand() Output = %s, want to contain 'hello world'", output.Output)
		}
		if output.Command != "echo" {
			t.Errorf("ExecuteCommand() Command = %s, want echo", output.Command)
		}
	})

	t.Run("error with dangerous command", func(t *testing.T) {
		_, err := st.ExecuteCommand(ctx, ExecuteCommandInput{
			Command: "rm",
			Args:    []string{"-rf", "/"},
		})
		if err == nil {
			t.Error("ExecuteCommand() expected error with dangerous command")
		}
		if !strings.Contains(err.Error(), "dangerous command rejected") {
			t.Errorf("ExecuteCommand() error = %v, want error containing 'dangerous command rejected'", err)
		}
	})

	t.Run("error with sudo command", func(t *testing.T) {
		_, err := st.ExecuteCommand(ctx, ExecuteCommandInput{
			Command: "sudo",
			Args:    []string{"ls"},
		})
		if err == nil {
			t.Error("ExecuteCommand() expected error with sudo command")
		}
	})

	t.Run("error with invalid command", func(t *testing.T) {
		output, err := st.ExecuteCommand(ctx, ExecuteCommandInput{
			Command: "nonexistent_command_12345",
			Args:    []string{},
		})
		if err == nil {
			t.Error("ExecuteCommand() expected error with nonexistent command")
		}
		if output.Success {
			t.Error("ExecuteCommand() Success = true with failed command, want false")
		}
	})
}

// TestSystemToolset_GetEnv tests the GetEnv tool
func TestSystemToolset_GetEnv(t *testing.T) {
	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	st, err := NewSystemToolset(cmdVal, envVal, testLogger())
	if err != nil {
		t.Fatalf("NewSystemToolset() unexpected error: %v", err)
	}

	ctx := &ai.ToolContext{
		Context: context.Background(),
	}

	t.Run("success with existing variable", func(t *testing.T) {
		// Set a test environment variable using t.Setenv for automatic cleanup
		testKey := "TEST_SYSTEM_TOOLSET_VAR"
		testValue := "test_value_123"
		t.Setenv(testKey, testValue)

		output, err := st.GetEnv(ctx, GetEnvInput{Key: testKey})
		if err != nil {
			t.Errorf("GetEnv() unexpected error: %v", err)
		}
		if output.Key != testKey {
			t.Errorf("GetEnv() Key = %s, want %s", output.Key, testKey)
		}
		if output.Value != testValue {
			t.Errorf("GetEnv() Value = %s, want %s", output.Value, testValue)
		}
		if !output.IsSet {
			t.Error("GetEnv() IsSet = false, want true")
		}
	})

	t.Run("success with nonexistent variable", func(t *testing.T) {
		output, err := st.GetEnv(ctx, GetEnvInput{Key: "NONEXISTENT_VAR_12345"})
		if err != nil {
			t.Errorf("GetEnv() unexpected error: %v", err)
		}
		if output.Value != "" {
			t.Errorf("GetEnv() Value = %s, want empty string", output.Value)
		}
		if output.IsSet {
			t.Error("GetEnv() IsSet = true, want false")
		}
	})

	t.Run("error with sensitive variable", func(t *testing.T) {
		sensitiveKeys := []string{"API_KEY", "SECRET_TOKEN", "PASSWORD", "AWS_SECRET"}
		for _, key := range sensitiveKeys {
			_, err := st.GetEnv(ctx, GetEnvInput{Key: key})
			if err == nil {
				t.Errorf("GetEnv() expected error with sensitive key %s", key)
			}
			if !strings.Contains(err.Error(), "sensitive environment variable blocked") {
				t.Errorf("GetEnv() error = %v, want error containing 'sensitive environment variable blocked'", err)
			}
		}
	})
}

// TestSystemToolset_ToolMetadata tests tool metadata structures
func TestSystemToolset_ToolMetadata(t *testing.T) {
	tests := []struct {
		toolName        string
		wantDescription string
		wantLongRunning bool
	}{
		{
			toolName:        ToolCurrentTime,
			wantDescription: "Get the current system date and time in formatted string",
			wantLongRunning: false,
		},
		{
			toolName:        ToolExecuteCommand,
			wantDescription: "Execute a shell command with security validation. Dangerous commands (rm -rf, sudo, etc.) are blocked.",
			wantLongRunning: true,
		},
		{
			toolName:        ToolGetEnv,
			wantDescription: "Read an environment variable value. Sensitive variables (*KEY*, *SECRET*, *TOKEN*) are protected.",
			wantLongRunning: false,
		},
	}

	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	st, err := NewSystemToolset(cmdVal, envVal, testLogger())
	if err != nil {
		t.Fatalf("NewSystemToolset() unexpected error: %v", err)
	}

	emptyCtx := &emptyReadonlyContext{}
	tools, _ := st.Tools(emptyCtx)

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			var found bool
			for _, tool := range tools {
				if tool.Name() == tt.toolName {
					found = true
					if tool.Description() != tt.wantDescription {
						t.Errorf("Tool %s: Description = %s, want %s",
							tt.toolName, tool.Description(), tt.wantDescription)
					}
					if tool.IsLongRunning() != tt.wantLongRunning {
						t.Errorf("Tool %s: IsLongRunning = %v, want %v",
							tt.toolName, tool.IsLongRunning(), tt.wantLongRunning)
					}
					break
				}
			}
			if !found {
				t.Errorf("Tool %s not found in definitions", tt.toolName)
			}
		})
	}
}

// emptyReadonlyContext is a helper for testing
type emptyReadonlyContext struct{}

func (*emptyReadonlyContext) InvocationID() string       { return "" }
func (*emptyReadonlyContext) Branch() string             { return "" }
func (*emptyReadonlyContext) SessionID() agent.SessionID { return "" }
func (*emptyReadonlyContext) AgentName() string          { return "" }
