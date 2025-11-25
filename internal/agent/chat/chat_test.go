package chat

import (
	"context"
	"errors"
	"log/slog"
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

// TestResolveLanguage tests language resolution
func TestResolveLanguage(t *testing.T) {
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
			result := c.resolveLanguage()
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

// BenchmarkResolveLanguage benchmarks language resolution
func BenchmarkResolveLanguage(b *testing.B) {
	c := &Chat{
		config: &config.Config{Language: "English"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.resolveLanguage()
	}
}

// BenchmarkResolveModelName benchmarks model name resolution
func BenchmarkResolveModelName(b *testing.B) {
	c := &Chat{
		config: &config.Config{ModelName: "gemini-2.5-flash"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.resolveModelName()
	}
}
