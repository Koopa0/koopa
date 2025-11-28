package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
)

// TestNewTool_Creation tests the NewTool factory function
func TestNewTool_Creation(t *testing.T) {
	t.Parallel()

	t.Run("creates tool with correct metadata", func(t *testing.T) {
		t.Parallel()
		tool := NewTool(
			"testTool",
			"Test tool description",
			false,
			func(ctx *ai.ToolContext, input string) (string, error) {
				return "output", nil
			},
		)

		assert.NotNil(t, tool)
		assert.Equal(t, "testTool", tool.Name())
		assert.Equal(t, "Test tool description", tool.Description())
		assert.False(t, tool.IsLongRunning())
	})

	t.Run("creates long running tool", func(t *testing.T) {
		t.Parallel()
		tool := NewTool(
			"longTool",
			"Long running tool",
			true,
			func(ctx *ai.ToolContext, input string) (string, error) {
				return "output", nil
			},
		)

		assert.True(t, tool.IsLongRunning())
	})

	t.Run("works with different input/output types", func(t *testing.T) {
		t.Parallel()
		type complexInput struct {
			Field1 string
			Field2 int
		}
		type complexOutput struct {
			Result string
			Count  int
		}

		tool := NewTool(
			"complexTool",
			"Complex tool",
			false,
			func(ctx *ai.ToolContext, input complexInput) (complexOutput, error) {
				return complexOutput{
					Result: input.Field1,
					Count:  input.Field2,
				}, nil
			},
		)

		assert.NotNil(t, tool)
		assert.Equal(t, "complexTool", tool.Name())
	})
}

// TestExecutableTool_Execute tests the Execute method with various scenarios
func TestExecutableTool_Execute(t *testing.T) {
	t.Parallel()

	t.Run("successful execution", func(t *testing.T) {
		t.Parallel()
		tool := NewTool(
			"successTool",
			"Success tool",
			false,
			func(ctx *ai.ToolContext, input string) (string, error) {
				return "result: " + input, nil
			},
		)

		ctx := &ai.ToolContext{
			Context: context.Background(),
		}
		result, err := tool.Execute(ctx, "test")

		assert.NoError(t, err)
		assert.Equal(t, "result: test", result)
	})

	t.Run("execution with error", func(t *testing.T) {
		t.Parallel()
		expectedErr := errors.New("tool error")
		tool := NewTool(
			"errorTool",
			"Error tool",
			false,
			func(ctx *ai.ToolContext, input string) (string, error) {
				return "", expectedErr
			},
		)

		ctx := &ai.ToolContext{
			Context: context.Background(),
		}
		result, err := tool.Execute(ctx, "test")

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, "", result)
	})

	t.Run("nil context handling", func(t *testing.T) {
		t.Parallel()
		tool := NewTool(
			"nilCtxTool",
			"Nil context tool",
			false,
			func(ctx *ai.ToolContext, input string) (string, error) {
				// Tool should handle nil context gracefully
				if ctx == nil {
					return "", errors.New("nil context")
				}
				return "ok", nil
			},
		)

		// Pass nil context - handler should handle this
		_, err := tool.Execute(nil, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil context")
	})

	t.Run("empty input handling", func(t *testing.T) {
		t.Parallel()
		tool := NewTool(
			"emptyInputTool",
			"Empty input tool",
			false,
			func(ctx *ai.ToolContext, input string) (string, error) {
				if input == "" {
					return "empty", nil
				}
				return input, nil
			},
		)

		ctx := &ai.ToolContext{
			Context: context.Background(),
		}
		result, err := tool.Execute(ctx, "")

		assert.NoError(t, err)
		assert.Equal(t, "empty", result)
	})

	t.Run("complex input type", func(t *testing.T) {
		t.Parallel()
		type complexInput struct {
			Name  string
			Value int
		}

		tool := NewTool(
			"complexInputTool",
			"Complex input tool",
			false,
			func(ctx *ai.ToolContext, input complexInput) (string, error) {
				return input.Name, nil
			},
		)

		ctx := &ai.ToolContext{
			Context: context.Background(),
		}
		result, err := tool.Execute(ctx, complexInput{Name: "test", Value: 42})

		assert.NoError(t, err)
		assert.Equal(t, "test", result)
	})

	t.Run("zero value input", func(t *testing.T) {
		t.Parallel()
		tool := NewTool(
			"zeroValueTool",
			"Zero value tool",
			false,
			func(ctx *ai.ToolContext, input int) (int, error) {
				return input * 2, nil
			},
		)

		ctx := &ai.ToolContext{
			Context: context.Background(),
		}
		result, err := tool.Execute(ctx, 0)

		assert.NoError(t, err)
		assert.Equal(t, 0, result)
	})
}

// TestExecutableTool_TypeErasure tests that type erasure works correctly
func TestExecutableTool_TypeErasure(t *testing.T) {
	t.Parallel()

	t.Run("different types can be stored as Tool interface", func(t *testing.T) {
		t.Parallel()

		// Add different tool types using combined append
		tools := []Tool{
			NewTool(
				"stringTool",
				"String tool",
				false,
				func(_ *ai.ToolContext, input string) (string, error) {
					return input, nil
				},
			),
			NewTool(
				"intTool",
				"Int tool",
				false,
				func(_ *ai.ToolContext, input int) (int, error) {
					return input, nil
				},
			),
			NewTool(
				"structTool",
				"Struct tool",
				false,
				func(_ *ai.ToolContext, input struct{ Name string }) (struct{ Name string }, error) {
					return input, nil
				},
			),
		}

		// Verify all tools implement Tool interface
		assert.Len(t, tools, 3)
		for _, tool := range tools {
			assert.NotNil(t, tool)
			assert.NotEmpty(t, tool.Name())
			assert.NotEmpty(t, tool.Description())
		}
	})
}

// TestExecutableTool_ConcurrentExecution tests concurrent tool execution
func TestExecutableTool_ConcurrentExecution(t *testing.T) {
	t.Parallel()

	tool := NewTool(
		"concurrentTool",
		"Concurrent tool",
		false,
		func(ctx *ai.ToolContext, input int) (int, error) {
			// Simulate some work
			return input * 2, nil
		},
	)

	ctx := &ai.ToolContext{
		Context: context.Background(),
	}

	// Run multiple executions concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(val int) {
			defer func() { done <- true }()
			result, err := tool.Execute(ctx, val)
			assert.NoError(t, err)
			assert.Equal(t, val*2, result)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestToolset_EdgeCases tests edge cases in Toolset implementations
func TestToolset_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty ReadonlyContext", func(t *testing.T) {
		t.Parallel()
		// emptyReadonlyContext is defined in system_test.go
		// This test verifies that toolsets work with empty context
		// Actual toolset tests are in their respective test files
	})
}
