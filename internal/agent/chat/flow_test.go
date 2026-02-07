package chat

import (
	"errors"
	"testing"

	"github.com/koopa0/koopa/internal/agent"
)

// TestFlowName tests the FlowName constant
func TestFlowName(t *testing.T) {
	t.Parallel()
	if FlowName != "koopa/chat" {
		t.Errorf("FlowName = %q, want %q", FlowName, "koopa/chat")
	}
	if FlowName == "" {
		t.Error("FlowName is empty, want non-empty")
	}
}

// TestStreamChunk_Structure tests the StreamChunk type
func TestStreamChunk_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty text", func(t *testing.T) {
		t.Parallel()
		var chunk StreamChunk
		if chunk.Text != "" {
			t.Errorf("chunk.Text = %q, want %q", chunk.Text, "")
		}
	})

	t.Run("can set text", func(t *testing.T) {
		t.Parallel()
		chunk := StreamChunk{Text: "Hello, World!"}
		if chunk.Text != "Hello, World!" {
			t.Errorf("chunk.Text = %q, want %q", chunk.Text, "Hello, World!")
		}
	})

	t.Run("can hold unicode text", func(t *testing.T) {
		t.Parallel()
		chunk := StreamChunk{Text: "你好世界 🌍"}
		if chunk.Text != "你好世界 🌍" {
			t.Errorf("chunk.Text = %q, want %q", chunk.Text, "你好世界 🌍")
		}
	})
}

// TestInput_Structure tests the Input type
func TestInput_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty fields", func(t *testing.T) {
		t.Parallel()
		var input Input
		if input.Query != "" {
			t.Errorf("input.Query = %q, want %q", input.Query, "")
		}
		if input.SessionID != "" {
			t.Errorf("input.SessionID = %q, want %q", input.SessionID, "")
		}
	})

	t.Run("can set all fields", func(t *testing.T) {
		t.Parallel()
		input := Input{
			Query:     "What is the weather?",
			SessionID: "test-session-123",
		}
		if input.Query != "What is the weather?" {
			t.Errorf("input.Query = %q, want %q", input.Query, "What is the weather?")
		}
		if input.SessionID != "test-session-123" {
			t.Errorf("input.SessionID = %q, want %q", input.SessionID, "test-session-123")
		}
	})
}

// TestOutput_Structure tests the Output type
func TestOutput_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty fields", func(t *testing.T) {
		t.Parallel()
		var output Output
		if output.Response != "" {
			t.Errorf("output.Response = %q, want %q", output.Response, "")
		}
		if output.SessionID != "" {
			t.Errorf("output.SessionID = %q, want %q", output.SessionID, "")
		}
	})

	t.Run("can set response and session", func(t *testing.T) {
		t.Parallel()
		output := Output{
			Response:  "The weather is sunny.",
			SessionID: "test-session-123",
		}
		if output.Response != "The weather is sunny." {
			t.Errorf("output.Response = %q, want %q", output.Response, "The weather is sunny.")
		}
		if output.SessionID != "test-session-123" {
			t.Errorf("output.SessionID = %q, want %q", output.SessionID, "test-session-123")
		}
	})
}

// TestSentinelErrors_CanBeChecked tests that sentinel errors work correctly with errors.Is
func TestSentinelErrors_CanBeChecked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"ErrInvalidSession", agent.ErrInvalidSession, agent.ErrInvalidSession},
		{"ErrExecutionFailed", agent.ErrExecutionFailed, agent.ErrExecutionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.sentinel)
			}
		})
	}
}

// TestWrappedErrors_PreserveSentinel tests that wrapped errors preserve sentinel checking
func TestWrappedErrors_PreserveSentinel(t *testing.T) {
	t.Parallel()

	t.Run("wrapped invalid session error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("original error")
		wrapped := errors.Join(agent.ErrInvalidSession, err)
		if !errors.Is(wrapped, agent.ErrInvalidSession) {
			t.Errorf("errors.Is(wrapped, ErrInvalidSession) = false, want true")
		}
	})

	t.Run("wrapped execution failed error", func(t *testing.T) {
		t.Parallel()
		err := errors.New("LLM timeout")
		wrapped := errors.Join(agent.ErrExecutionFailed, err)
		if !errors.Is(wrapped, agent.ErrExecutionFailed) {
			t.Errorf("errors.Is(wrapped, ErrExecutionFailed) = false, want true")
		}
	})
}
