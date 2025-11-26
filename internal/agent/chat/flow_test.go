package chat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFlowName tests the FlowName constant
func TestFlowName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "koopa/chat", FlowName)
	assert.NotEmpty(t, FlowName)
}

// TestStreamChunk_Structure tests the StreamChunk type
func TestStreamChunk_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty text", func(t *testing.T) {
		t.Parallel()
		var chunk StreamChunk
		assert.Equal(t, "", chunk.Text)
	})

	t.Run("can set text", func(t *testing.T) {
		t.Parallel()
		chunk := StreamChunk{Text: "Hello, World!"}
		assert.Equal(t, "Hello, World!", chunk.Text)
	})

	t.Run("can hold unicode text", func(t *testing.T) {
		t.Parallel()
		chunk := StreamChunk{Text: "你好世界 🌍"}
		assert.Equal(t, "你好世界 🌍", chunk.Text)
	})
}

// TestInput_Structure tests the Input type
func TestInput_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty fields", func(t *testing.T) {
		t.Parallel()
		var input Input
		assert.Equal(t, "", input.Query)
		assert.Equal(t, "", input.SessionID)
	})

	t.Run("can set all fields", func(t *testing.T) {
		t.Parallel()
		input := Input{
			Query:     "What is the weather?",
			SessionID: "test-session-123",
		}
		assert.Equal(t, "What is the weather?", input.Query)
		assert.Equal(t, "test-session-123", input.SessionID)
	})
}

// TestOutput_Structure tests the Output type
func TestOutput_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty fields and nil error", func(t *testing.T) {
		t.Parallel()
		var output Output
		assert.Equal(t, "", output.Response)
		assert.Equal(t, "", output.SessionID)
		assert.Nil(t, output.Error)
	})

	t.Run("can set response and session", func(t *testing.T) {
		t.Parallel()
		output := Output{
			Response:  "The weather is sunny.",
			SessionID: "test-session-123",
		}
		assert.Equal(t, "The weather is sunny.", output.Response)
		assert.Equal(t, "test-session-123", output.SessionID)
		assert.Nil(t, output.Error)
	})

	t.Run("can set structured error", func(t *testing.T) {
		t.Parallel()
		output := Output{
			SessionID: "test-session-123",
			Error: &FlowError{
				Code:    "INVALID_SESSION_ID",
				Message: "session ID is not valid",
			},
		}
		assert.Equal(t, "", output.Response)
		assert.NotNil(t, output.Error)
		assert.Equal(t, "INVALID_SESSION_ID", output.Error.Code)
		assert.Equal(t, "session ID is not valid", output.Error.Message)
	})
}

// TestFlowError_Structure tests the FlowError type
func TestFlowError_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has empty fields", func(t *testing.T) {
		t.Parallel()
		var flowErr FlowError
		assert.Equal(t, "", flowErr.Code)
		assert.Equal(t, "", flowErr.Message)
	})

	t.Run("can set error details", func(t *testing.T) {
		t.Parallel()
		flowErr := FlowError{
			Code:    "EXECUTION_FAILED",
			Message: "failed to execute chat agent",
		}
		assert.Equal(t, "EXECUTION_FAILED", flowErr.Code)
		assert.Equal(t, "failed to execute chat agent", flowErr.Message)
	})
}

// TestGetFlow_ReturnsNonNilOnSubsequentCalls tests that GetFlow returns cached flow
// Note: Due to sync.Once, this test verifies the singleton behavior by ensuring
// the returned flow is consistent (not nil after first initialization in other tests)
func TestGetFlow_ReturnsNonNilOnSubsequentCalls(t *testing.T) {
	// Note: We cannot easily test GetFlow in isolation because:
	// 1. sync.Once cannot be reset between tests
	// 2. GetFlow requires valid genkit.Genkit and Chat instances
	// 3. The Flow may or may not be initialized depending on test execution order
	//
	// This is a known limitation documented in the GetFlow function.
	// Integration tests in integration_test.go cover the full flow behavior.
	t.Skip("GetFlow singleton behavior is tested via integration tests")
}
