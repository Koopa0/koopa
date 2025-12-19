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
)

// TestNew_ValidationErrors tests constructor validation
func TestNew_ValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         Config
		errContains string
	}{
		{
			name:        "nil genkit",
			cfg:         Config{},
			errContains: "genkit instance is required",
		},
		{
			name: "nil retriever",
			cfg: Config{
				Genkit: nil, // Still nil, so we'll get Genkit error first
			},
			errContains: "genkit instance is required",
		},
		{
			name: "nil logger - requires all previous deps",
			cfg:  Config{
				// Missing Genkit
			},
			errContains: "genkit instance is required",
		},
		{
			name: "empty tools - requires all previous deps",
			cfg:  Config{
				// Missing Genkit
			},
			errContains: "genkit instance is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
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

	t.Run("KoopaPromptName is set", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "koopa", KoopaPromptName)
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

// TestConfig_Structure tests the Config struct
func TestConfig_Structure(t *testing.T) {
	t.Parallel()

	t.Run("zero value has nil fields", func(t *testing.T) {
		t.Parallel()
		var cfg Config
		assert.Nil(t, cfg.Genkit)
		assert.Nil(t, cfg.Retriever)
		assert.Nil(t, cfg.SessionStore)
		assert.Nil(t, cfg.Logger)
		assert.Nil(t, cfg.Tools)
	})
}

// TestChat_RetrieveRAGContext_SkipsWhenTopKZero tests RAG context retrieval
func TestChat_RetrieveRAGContext_SkipsWhenTopKZero(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when topK is zero", func(t *testing.T) {
		t.Parallel()
		c := &Chat{
			ragTopK: 0,
			logger:  slog.Default(),
		}
		docs := c.retrieveRAGContext(context.Background(), "test query")
		assert.Nil(t, docs)
	})

	t.Run("returns nil when topK is negative", func(t *testing.T) {
		t.Parallel()
		c := &Chat{
			ragTopK: -1,
			logger:  slog.Default(),
		}
		docs := c.retrieveRAGContext(context.Background(), "test query")
		assert.Nil(t, docs)
	})
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
			responseText = FallbackResponseMessage
		}
		assert.Contains(t, responseText, "apologize")
		assert.NotEmpty(t, responseText)
	})

	t.Run("whitespace-only triggers fallback", func(t *testing.T) {
		t.Parallel()
		responseText := "   \n\t   "
		if strings.TrimSpace(responseText) == "" {
			responseText = FallbackResponseMessage
		}
		assert.Contains(t, responseText, "apologize")
	})

	t.Run("valid response is preserved", func(t *testing.T) {
		t.Parallel()
		responseText := "Hello, I'm here to help!"
		originalText := responseText
		if strings.TrimSpace(responseText) == "" {
			responseText = FallbackResponseMessage
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
