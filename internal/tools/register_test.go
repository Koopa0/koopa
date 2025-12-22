package tools

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestGenkit creates a Genkit instance for testing.
func setupTestGenkit(t *testing.T) *genkit.Genkit {
	t.Helper()
	return genkit.Init(context.Background())
}

// ============================================================================
// NewFileTools Tests
// ============================================================================

func TestNewFileTools(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		require.NoError(t, err)

		ft, err := NewFileTools(pathVal, testLogger())
		require.NoError(t, err)
		assert.NotNil(t, ft)
	})

	t.Run("nil path validator", func(t *testing.T) {
		t.Parallel()

		ft, err := NewFileTools(nil, testLogger())
		assert.Error(t, err)
		assert.Nil(t, ft)
		assert.Contains(t, err.Error(), "path validator is required")
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		require.NoError(t, err)

		ft, err := NewFileTools(pathVal, nil)
		assert.Error(t, err)
		assert.Nil(t, ft)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ============================================================================
// RegisterFileTools Tests
// ============================================================================

func TestRegisterFileTools(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		pathVal, err := security.NewPath([]string{})
		require.NoError(t, err)

		ft, err := NewFileTools(pathVal, testLogger())
		require.NoError(t, err)

		tools, err := RegisterFileTools(g, ft)
		require.NoError(t, err)
		assert.Len(t, tools, 5, "should register 5 file tools")

		// Verify tool names
		expectedNames := []string{ToolReadFile, ToolWriteFile, ToolListFiles, ToolDeleteFile, ToolGetFileInfo}
		actualNames := extractToolNames(tools)
		assert.ElementsMatch(t, expectedNames, actualNames)
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		require.NoError(t, err)

		ft, err := NewFileTools(pathVal, testLogger())
		require.NoError(t, err)

		tools, err := RegisterFileTools(nil, ft)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("nil FileTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterFileTools(g, nil)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "FileTools is required")
	})
}

// ============================================================================
// NewSystemTools Tests
// ============================================================================

func TestNewSystemTools(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, testLogger())
		require.NoError(t, err)
		assert.NotNil(t, st)
	})

	t.Run("nil command validator", func(t *testing.T) {
		t.Parallel()
		envVal := security.NewEnv()

		st, err := NewSystemTools(nil, envVal, testLogger())
		assert.Error(t, err)
		assert.Nil(t, st)
		assert.Contains(t, err.Error(), "command validator is required")
	})

	t.Run("nil env validator", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()

		st, err := NewSystemTools(cmdVal, nil, testLogger())
		assert.Error(t, err)
		assert.Nil(t, st)
		assert.Contains(t, err.Error(), "env validator is required")
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, nil)
		assert.Error(t, err)
		assert.Nil(t, st)
		assert.Contains(t, err.Error(), "logger is required")
	})
}

// ============================================================================
// RegisterSystemTools Tests
// ============================================================================

func TestRegisterSystemTools(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, testLogger())
		require.NoError(t, err)

		tools, err := RegisterSystemTools(g, st)
		require.NoError(t, err)
		assert.Len(t, tools, 3, "should register 3 system tools")

		// Verify tool names
		expectedNames := []string{ToolCurrentTime, ToolExecuteCommand, ToolGetEnv}
		actualNames := extractToolNames(tools)
		assert.ElementsMatch(t, expectedNames, actualNames)
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, testLogger())
		require.NoError(t, err)

		tools, err := RegisterSystemTools(nil, st)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("nil SystemTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterSystemTools(g, nil)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "SystemTools is required")
	})
}

// ============================================================================
// NewNetworkTools Tests
// ============================================================================

func TestNewNetworkTools(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		require.NoError(t, err)
		assert.NotNil(t, nt)
	})

	t.Run("empty search base URL", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{}

		nt, err := NewNetworkTools(cfg, testLogger())
		assert.Error(t, err)
		assert.Nil(t, nt)
		assert.Contains(t, err.Error(), "search base URL is required")
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, nt)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("default values applied", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080/",
			// Leave other values at zero - should get defaults
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		require.NoError(t, err)
		assert.NotNil(t, nt)
	})
}

// ============================================================================
// RegisterNetworkTools Tests
// ============================================================================

func TestRegisterNetworkTools(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		require.NoError(t, err)

		tools, err := RegisterNetworkTools(g, nt)
		require.NoError(t, err)
		assert.Len(t, tools, 2, "should register 2 network tools")

		// Verify tool names
		expectedNames := []string{ToolWebSearch, ToolWebFetch}
		actualNames := extractToolNames(tools)
		assert.ElementsMatch(t, expectedNames, actualNames)
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		require.NoError(t, err)

		tools, err := RegisterNetworkTools(nil, nt)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("nil NetworkTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterNetworkTools(g, nil)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "NetworkTools is required")
	})
}

func TestRegisterNetworkToolsForTesting(t *testing.T) {
	t.Parallel()

	t.Run("successful registration with SSRF bypass", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		tools, err := RegisterNetworkToolsForTesting(g, cfg, testLogger())
		require.NoError(t, err)
		assert.Len(t, tools, 2, "should register 2 network tools")
	})
}

// ============================================================================
// RegisterKnowledgeTools Tests
// ============================================================================

// Note: KnowledgeTools validation (nil store, nil logger) is tested in
// TestNewKnowledgeTools in knowledge_test.go. These tests verify
// RegisterKnowledgeTools parameter validation only.

func TestRegisterKnowledgeTools(t *testing.T) {
	t.Parallel()

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()

		tools, err := RegisterKnowledgeTools(nil, &KnowledgeTools{})
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "genkit instance is required")
	})

	t.Run("nil KnowledgeTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterKnowledgeTools(g, nil)
		assert.Error(t, err)
		assert.Nil(t, tools)
		assert.Contains(t, err.Error(), "KnowledgeTools is required")
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func extractToolNames(tools []ai.Tool) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name()
	}
	return names
}
