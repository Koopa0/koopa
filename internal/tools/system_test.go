package tools

import (
	"testing"

	"github.com/koopa0/koopa/internal/security"
)

func TestSystemTools_Constructor(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, testLogger())
		if err != nil {
			t.Errorf("NewSystemTools() error = %v, want nil", err)
		}
		if st == nil {
			t.Error("NewSystemTools() returned nil, want non-nil")
		}
	})

	t.Run("nil command validator", func(t *testing.T) {
		envVal := security.NewEnv()

		st, err := NewSystemTools(nil, envVal, testLogger())
		if err == nil {
			t.Error("NewSystemTools() error = nil, want error")
		}
		if st != nil {
			t.Error("NewSystemTools() returned non-nil, want nil")
		}
	})

	t.Run("nil env validator", func(t *testing.T) {
		cmdVal := security.NewCommand()

		st, err := NewSystemTools(cmdVal, nil, testLogger())
		if err == nil {
			t.Error("NewSystemTools() error = nil, want error")
		}
		if st != nil {
			t.Error("NewSystemTools() returned non-nil, want nil")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, nil)
		if err == nil {
			t.Error("NewSystemTools() error = nil, want error")
		}
		if st != nil {
			t.Error("NewSystemTools() returned non-nil, want nil")
		}
	})
}

func TestSystemToolConstants(t *testing.T) {
	expectedNames := map[string]string{
		"ToolCurrentTime":    "current_time",
		"ToolExecuteCommand": "execute_command",
		"ToolGetEnv":         "get_env",
	}

	if ToolCurrentTime != expectedNames["ToolCurrentTime"] {
		t.Errorf("ToolCurrentTime = %q, want %q", ToolCurrentTime, expectedNames["ToolCurrentTime"])
	}
	if ToolExecuteCommand != expectedNames["ToolExecuteCommand"] {
		t.Errorf("ToolExecuteCommand = %q, want %q", ToolExecuteCommand, expectedNames["ToolExecuteCommand"])
	}
	if ToolGetEnv != expectedNames["ToolGetEnv"] {
		t.Errorf("ToolGetEnv = %q, want %q", ToolGetEnv, expectedNames["ToolGetEnv"])
	}
}

func TestExecuteCommandInput(t *testing.T) {
	input := ExecuteCommandInput{
		Command: "ls",
		Args:    []string{"-la", "/tmp"},
	}
	if input.Command != "ls" {
		t.Errorf("ExecuteCommandInput.Command = %q, want %q", input.Command, "ls")
	}
	if len(input.Args) != 2 {
		t.Errorf("ExecuteCommandInput.Args length = %d, want 2", len(input.Args))
	}
	if input.Args[0] != "-la" {
		t.Errorf("ExecuteCommandInput.Args[0] = %q, want %q", input.Args[0], "-la")
	}
}

func TestGetEnvInput(t *testing.T) {
	input := GetEnvInput{Key: "PATH"}
	if input.Key != "PATH" {
		t.Errorf("GetEnvInput.Key = %q, want %q", input.Key, "PATH")
	}
}

func TestCurrentTimeInput(t *testing.T) {
	// CurrentTimeInput is an empty struct
	input := CurrentTimeInput{}
	_ = input // Just verify it can be created
}
