package tools

import (
	"testing"

	"github.com/koopa0/koopa/internal/security"
)

func TestSystem_Constructor(t *testing.T) {
	t.Run("valid inputs", func(t *testing.T) {
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystem(cmdVal, envVal, testLogger())
		if err != nil {
			t.Errorf("NewSystem() error = %v, want nil", err)
		}
		if st == nil {
			t.Error("NewSystem() returned nil, want non-nil")
		}
	})

	t.Run("nil command validator", func(t *testing.T) {
		envVal := security.NewEnv()

		st, err := NewSystem(nil, envVal, testLogger())
		if err == nil {
			t.Error("NewSystem() error = nil, want error")
		}
		if st != nil {
			t.Error("NewSystem() returned non-nil, want nil")
		}
	})

	t.Run("nil env validator", func(t *testing.T) {
		cmdVal := security.NewCommand()

		st, err := NewSystem(cmdVal, nil, testLogger())
		if err == nil {
			t.Error("NewSystem() error = nil, want error")
		}
		if st != nil {
			t.Error("NewSystem() returned non-nil, want nil")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystem(cmdVal, envVal, nil)
		if err == nil {
			t.Error("NewSystem() error = nil, want error")
		}
		if st != nil {
			t.Error("NewSystem() returned non-nil, want nil")
		}
	})
}

func TestSystemToolConstants(t *testing.T) {
	expectedNames := map[string]string{
		"CurrentTimeName":    "current_time",
		"ExecuteCommandName": "execute_command",
		"GetEnvName":         "get_env",
	}

	if CurrentTimeName != expectedNames["CurrentTimeName"] {
		t.Errorf("CurrentTimeName = %q, want %q", CurrentTimeName, expectedNames["CurrentTimeName"])
	}
	if ExecuteCommandName != expectedNames["ExecuteCommandName"] {
		t.Errorf("ExecuteCommandName = %q, want %q", ExecuteCommandName, expectedNames["ExecuteCommandName"])
	}
	if GetEnvName != expectedNames["GetEnvName"] {
		t.Errorf("GetEnvName = %q, want %q", GetEnvName, expectedNames["GetEnvName"])
	}
}
