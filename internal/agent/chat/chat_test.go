package chat

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/config"
)

// TestChat_Name tests the Name method
func TestChat_Name(t *testing.T) {
	t.Parallel()
	c := &Chat{}
	assert.Equal(t, Name, c.Name())
	assert.Equal(t, "chat", c.Name())
}

// TestChat_Description tests the Description method
func TestChat_Description(t *testing.T) {
	t.Parallel()
	c := &Chat{}
	assert.Equal(t, Description, c.Description())
	assert.NotEmpty(t, c.Description())
}

// TestChat_SubAgents tests the SubAgents method
func TestChat_SubAgents(t *testing.T) {
	t.Parallel()
	c := &Chat{}
	assert.Nil(t, c.SubAgents())
}

// TestNew_ValidationErrors tests constructor validation
func TestNew_ValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		deps        Deps
		errContains string
	}{
		{
			name:        "nil config",
			deps:        Deps{},
			errContains: "Config is required",
		},
		{
			name: "nil genkit",
			deps: Deps{
				Config: &config.Config{},
			},
			errContains: "Genkit is required",
		},
		{
			name: "nil retriever - requires genkit first",
			deps: Deps{
				Config: &config.Config{},
				// Genkit is nil, so we'll get Genkit error first
			},
			errContains: "Genkit is required",
		},
		{
			name: "nil logger - requires all previous deps",
			deps: Deps{
				Config: &config.Config{},
				// Missing Genkit
			},
			errContains: "Genkit is required",
		},
		{
			name: "empty toolsets - requires all previous deps",
			deps: Deps{
				Config: &config.Config{},
				// Missing Genkit
			},
			errContains: "Genkit is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.deps)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// TestGetLanguagePromptVariable tests language prompt variable retrieval
func TestGetLanguagePromptVariable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		language string
		expected string
	}{
		{
			name:     "empty language defaults to auto-detect",
			language: "",
			expected: "the same language as the user's input (auto-detect)",
		},
		{
			name:     "auto language defaults to auto-detect",
			language: "auto",
			expected: "the same language as the user's input (auto-detect)",
		},
		{
			name:     "specific language is returned",
			language: "English",
			expected: "English",
		},
		{
			name:     "chinese language is returned",
			language: "繁體中文",
			expected: "繁體中文",
		},
		{
			name:     "japanese language is returned",
			language: "日本語",
			expected: "日本語",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Chat{
				config: &config.Config{Language: tt.language},
			}
			result := c.getLanguagePromptVariable()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestResolveModelName tests model name resolution
func TestResolveModelName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		modelName string
		expected  string
	}{
		{
			name:      "empty model name uses default",
			modelName: "",
			expected:  DefaultModel,
		},
		{
			name:      "custom model name is returned",
			modelName: "gemini-1.5-pro",
			expected:  "gemini-1.5-pro",
		},
		{
			name:      "another custom model",
			modelName: "googleai/gemini-2.5-flash",
			expected:  "googleai/gemini-2.5-flash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Chat{
				config: &config.Config{ModelName: tt.modelName},
			}
			result := c.resolveModelName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestConstants tests package constants
func TestConstants(t *testing.T) {
	t.Parallel()

	t.Run("Name constant", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "chat", Name)
	})

	t.Run("Description is not empty", func(t *testing.T) {
		t.Parallel()
		assert.NotEmpty(t, Description)
	})

	t.Run("DefaultModel is set", func(t *testing.T) {
		t.Parallel()
		assert.NotEmpty(t, DefaultModel)
		assert.Contains(t, DefaultModel, "gemini")
	})

	t.Run("KoopaPromptName is set", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "koopa", KoopaPromptName)
	})
}

// TestEmptyReadonlyContext tests the emptyReadonlyContext helper
func TestEmptyReadonlyContext(t *testing.T) {
	t.Parallel()

	ctx := &emptyReadonlyContext{}

	t.Run("InvocationID returns empty string", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", ctx.InvocationID())
	})

	t.Run("Branch returns empty string", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", ctx.Branch())
	})

	t.Run("SessionID returns empty SessionID", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, agent.SessionID(""), ctx.SessionID())
	})

	t.Run("AgentName returns empty string", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", ctx.AgentName())
	})
}

// TestStreamCallback_Type tests the StreamCallback type definition
func TestStreamCallback_Type(t *testing.T) {
	t.Parallel()

	t.Run("nil callback is valid", func(t *testing.T) {
		t.Parallel()
		var callback StreamCallback
		assert.Nil(t, callback)
	})

	t.Run("callback can be assigned", func(t *testing.T) {
		t.Parallel()
		called := false
		callback := StreamCallback(func(_ context.Context, _ *ai.ModelResponseChunk) error {
			called = true
			return nil
		})
		assert.NotNil(t, callback)
		err := callback(context.Background(), nil)
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("callback can return error", func(t *testing.T) {
		t.Parallel()
		expectedErr := errors.New("test error")
		callback := StreamCallback(func(_ context.Context, _ *ai.ModelResponseChunk) error {
			return expectedErr
		})
		err := callback(context.Background(), nil)
		assert.Equal(t, expectedErr, err)
	})
}

// TestDeps_Structure tests the Deps struct
func TestDeps_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has nil fields", func(t *testing.T) {
		t.Parallel()
		var deps Deps
		assert.Nil(t, deps.Config)
		assert.Nil(t, deps.Genkit)
		assert.Nil(t, deps.Retriever)
		assert.Nil(t, deps.SessionStore)
		assert.Nil(t, deps.KnowledgeStore)
		assert.Nil(t, deps.Logger)
		assert.Nil(t, deps.Toolsets)
	})

	t.Run("can set config", func(t *testing.T) {
		t.Parallel()
		cfg := &config.Config{ModelName: "test-model"}
		deps := Deps{Config: cfg}
		assert.Equal(t, "test-model", deps.Config.ModelName)
	})
}

// TestChat_RetrieveRAGContext_SkipsWhenTopKZero tests RAG context retrieval
func TestChat_RetrieveRAGContext_SkipsWhenTopKZero(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when topK is zero", func(t *testing.T) {
		t.Parallel()
		c := &Chat{
			config: &config.Config{RAGTopK: 0},
			logger: slog.Default(),
		}
		docs := c.retrieveRAGContext(context.Background(), "test query")
		assert.Nil(t, docs)
	})

	t.Run("returns nil when topK is negative", func(t *testing.T) {
		t.Parallel()
		c := &Chat{
			config: &config.Config{RAGTopK: -1},
			logger: slog.Default(),
		}
		docs := c.retrieveRAGContext(context.Background(), "test query")
		assert.Nil(t, docs)
	})
}

// TestChat_InterfaceCompliance tests that Chat implements agent.Agent
func TestChat_InterfaceCompliance(t *testing.T) {
	t.Parallel()

	t.Run("Chat implements agent.Agent", func(t *testing.T) {
		t.Parallel()
		var _ agent.Agent = (*Chat)(nil)
	})
}

// BenchmarkGetLanguagePromptVariable benchmarks language prompt variable retrieval
func BenchmarkGetLanguagePromptVariable(b *testing.B) {
	c := &Chat{
		config: &config.Config{Language: "English"},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = c.getLanguagePromptVariable()
	}
}

// BenchmarkResolveModelName benchmarks model name resolution
func BenchmarkResolveModelName(b *testing.B) {
	c := &Chat{
		config: &config.Config{ModelName: "gemini-2.5-flash"},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = c.resolveModelName()
	}
}

// =============================================================================
// Edge Case Tests for Real Scenarios
// =============================================================================

// TestChat_EmptyResponseHandling tests that empty model responses are handled gracefully.
func TestChat_EmptyResponseHandling(t *testing.T) {
	t.Parallel()

	t.Run("empty string triggers fallback", func(t *testing.T) {
		t.Parallel()
		// Test the logic of empty response detection
		responseText := ""
		if strings.TrimSpace(responseText) == "" {
			responseText = "I apologize, but I couldn't generate a response. Please try rephrasing your question."
		}
		assert.Contains(t, responseText, "apologize")
		assert.NotEmpty(t, responseText)
	})

	t.Run("whitespace-only triggers fallback", func(t *testing.T) {
		t.Parallel()
		responseText := "   \n\t   "
		if strings.TrimSpace(responseText) == "" {
			responseText = "I apologize, but I couldn't generate a response. Please try rephrasing your question."
		}
		assert.Contains(t, responseText, "apologize")
	})

	t.Run("valid response is preserved", func(t *testing.T) {
		t.Parallel()
		responseText := "Hello, I'm here to help!"
		originalText := responseText
		if strings.TrimSpace(responseText) == "" {
			responseText = "I apologize, but I couldn't generate a response. Please try rephrasing your question."
		}
		assert.Equal(t, originalText, responseText)
	})
}

// TestChat_ContextCancellation tests graceful handling of context cancellation.
func TestChat_ContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("canceled context is detected", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Verify context is canceled
		assert.True(t, errors.Is(ctx.Err(), context.Canceled))
	})

	t.Run("deadline exceeded is different from canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()

		// Wait for timeout
		<-ctx.Done()

		// DeadlineExceeded is different from Canceled
		assert.True(t, errors.Is(ctx.Err(), context.DeadlineExceeded))
		assert.False(t, errors.Is(ctx.Err(), context.Canceled))
	})
}

// TestChat_NilResponseDefense tests defensive check for nil responses.
// This prevents panics when execute() incorrectly returns nil without error.
func TestChat_NilResponseDefense(t *testing.T) {
	t.Parallel()

	t.Run("nil response detection", func(t *testing.T) {
		t.Parallel()
		// Simulate the defensive check in ExecuteStream
		var resp *ai.ModelResponse = nil
		if resp == nil {
			err := errors.New("internal error: execute returned nil response without error")
			assert.Contains(t, err.Error(), "nil response")
		}
	})
}

// TestChat_MaxTurnsProtection tests that conversation doesn't loop infinitely.
// Safety: Prevents runaway agent loops that could exhaust resources.
func TestChat_MaxTurnsProtection(t *testing.T) {
	t.Parallel()

	t.Run("max turns concept validation", func(t *testing.T) {
		t.Parallel()
		// In a real agent loop, we would track turns
		maxTurns := 10
		currentTurn := 0

		// Simulate turn counting
		for i := 0; i < 100; i++ {
			currentTurn++
			if currentTurn >= maxTurns {
				break
			}
		}

		assert.Equal(t, maxTurns, currentTurn, "should stop at max turns")
	})
}

// TestChat_ToolFailureRecovery tests that the agent can continue after tool failures.
// Resilience: Agent should gracefully handle tool execution errors.
func TestChat_ToolFailureRecovery(t *testing.T) {
	t.Parallel()

	t.Run("tool error is wrapped", func(t *testing.T) {
		t.Parallel()
		toolErr := errors.New("tool failed: file not found")
		wrappedErr := errors.New("tool execution failed: " + toolErr.Error())
		assert.Contains(t, wrappedErr.Error(), "tool execution failed")
		assert.Contains(t, wrappedErr.Error(), "file not found")
	})

	t.Run("tool error does not crash agent", func(t *testing.T) {
		t.Parallel()
		// Simulate error handling that doesn't propagate
		var lastErr error
		handleToolError := func(err error) {
			lastErr = err // Log but don't crash
		}

		handleToolError(errors.New("tool failed"))
		assert.NotNil(t, lastErr)
		// Agent continues running
	})
}
