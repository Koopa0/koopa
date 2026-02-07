package tools

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
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
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFileTools(pathVal, testLogger())
		if err != nil {
			t.Fatalf("NewFileTools() unexpected error: %v", err)
		}
		if ft == nil {
			t.Fatal("NewFileTools() = nil, want non-nil")
		}
	})

	t.Run("nil path validator", func(t *testing.T) {
		t.Parallel()

		ft, err := NewFileTools(nil, testLogger())
		if err == nil {
			t.Fatal("NewFileTools(nil, logger) expected error, got nil")
		}
		if ft != nil {
			t.Errorf("NewFileTools(nil, logger) = %v, want nil", ft)
		}
		if !strings.Contains(err.Error(), "path validator is required") {
			t.Errorf("NewFileTools(nil, logger) error = %q, want contains %q", err.Error(), "path validator is required")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFileTools(pathVal, nil)
		if err == nil {
			t.Fatal("NewFileTools(pathVal, nil) expected error, got nil")
		}
		if ft != nil {
			t.Errorf("NewFileTools(pathVal, nil) = %v, want nil", ft)
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewFileTools(pathVal, nil) error = %q, want contains %q", err.Error(), "logger is required")
		}
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
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFileTools(pathVal, testLogger())
		if err != nil {
			t.Fatalf("NewFileTools() unexpected error: %v", err)
		}

		tools, err := RegisterFileTools(g, ft)
		if err != nil {
			t.Fatalf("RegisterFileTools() unexpected error: %v", err)
		}
		if got, want := len(tools), 5; got != want {
			t.Errorf("RegisterFileTools() tool count = %d, want %d (should register 5 file tools)", got, want)
		}

		// Verify tool names
		expectedNames := []string{ToolReadFile, ToolWriteFile, ToolListFiles, ToolDeleteFile, ToolGetFileInfo}
		actualNames := extractToolNames(tools)
		if !slicesEqual(expectedNames, actualNames) {
			t.Errorf("RegisterFileTools() tool names = %v, want %v", actualNames, expectedNames)
		}
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{})
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFileTools(pathVal, testLogger())
		if err != nil {
			t.Fatalf("NewFileTools() unexpected error: %v", err)
		}

		tools, err := RegisterFileTools(nil, ft)
		if err == nil {
			t.Fatal("RegisterFileTools(nil, ft) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterFileTools(nil, ft) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterFileTools(nil, ft) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil FileTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterFileTools(g, nil)
		if err == nil {
			t.Fatal("RegisterFileTools(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterFileTools(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "FileTools is required") {
			t.Errorf("RegisterFileTools(g, nil) error = %q, want contains %q", err.Error(), "FileTools is required")
		}
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
		if err != nil {
			t.Fatalf("NewSystemTools() unexpected error: %v", err)
		}
		if st == nil {
			t.Fatal("NewSystemTools() = nil, want non-nil")
		}
	})

	t.Run("nil command validator", func(t *testing.T) {
		t.Parallel()
		envVal := security.NewEnv()

		st, err := NewSystemTools(nil, envVal, testLogger())
		if err == nil {
			t.Fatal("NewSystemTools(nil, envVal, logger) expected error, got nil")
		}
		if st != nil {
			t.Errorf("NewSystemTools(nil, envVal, logger) = %v, want nil", st)
		}
		if !strings.Contains(err.Error(), "command validator is required") {
			t.Errorf("NewSystemTools(nil, envVal, logger) error = %q, want contains %q", err.Error(), "command validator is required")
		}
	})

	t.Run("nil env validator", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()

		st, err := NewSystemTools(cmdVal, nil, testLogger())
		if err == nil {
			t.Fatal("NewSystemTools(cmdVal, nil, logger) expected error, got nil")
		}
		if st != nil {
			t.Errorf("NewSystemTools(cmdVal, nil, logger) = %v, want nil", st)
		}
		if !strings.Contains(err.Error(), "env validator is required") {
			t.Errorf("NewSystemTools(cmdVal, nil, logger) error = %q, want contains %q", err.Error(), "env validator is required")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, nil)
		if err == nil {
			t.Fatal("NewSystemTools(cmdVal, envVal, nil) expected error, got nil")
		}
		if st != nil {
			t.Errorf("NewSystemTools(cmdVal, envVal, nil) = %v, want nil", st)
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewSystemTools(cmdVal, envVal, nil) error = %q, want contains %q", err.Error(), "logger is required")
		}
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
		if err != nil {
			t.Fatalf("NewSystemTools() unexpected error: %v", err)
		}

		tools, err := RegisterSystemTools(g, st)
		if err != nil {
			t.Fatalf("RegisterSystemTools() unexpected error: %v", err)
		}
		if got, want := len(tools), 3; got != want {
			t.Errorf("RegisterSystemTools() tool count = %d, want %d (should register 3 system tools)", got, want)
		}

		// Verify tool names
		expectedNames := []string{ToolCurrentTime, ToolExecuteCommand, ToolGetEnv}
		actualNames := extractToolNames(tools)
		if !slicesEqual(expectedNames, actualNames) {
			t.Errorf("RegisterSystemTools() tool names = %v, want %v", actualNames, expectedNames)
		}
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystemTools(cmdVal, envVal, testLogger())
		if err != nil {
			t.Fatalf("NewSystemTools() unexpected error: %v", err)
		}

		tools, err := RegisterSystemTools(nil, st)
		if err == nil {
			t.Fatal("RegisterSystemTools(nil, st) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterSystemTools(nil, st) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterSystemTools(nil, st) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil SystemTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterSystemTools(g, nil)
		if err == nil {
			t.Fatal("RegisterSystemTools(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterSystemTools(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "SystemTools is required") {
			t.Errorf("RegisterSystemTools(g, nil) error = %q, want contains %q", err.Error(), "SystemTools is required")
		}
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
		if err != nil {
			t.Fatalf("NewNetworkTools() unexpected error: %v", err)
		}
		if nt == nil {
			t.Fatal("NewNetworkTools() = nil, want non-nil")
		}
	})

	t.Run("empty search base URL", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{}

		nt, err := NewNetworkTools(cfg, testLogger())
		if err == nil {
			t.Fatal("NewNetworkTools(empty config) expected error, got nil")
		}
		if nt != nil {
			t.Errorf("NewNetworkTools(empty config) = %v, want nil", nt)
		}
		if !strings.Contains(err.Error(), "search base URL is required") {
			t.Errorf("NewNetworkTools(empty config) error = %q, want contains %q", err.Error(), "search base URL is required")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, nil)
		if err == nil {
			t.Fatal("NewNetworkTools(cfg, nil) expected error, got nil")
		}
		if nt != nil {
			t.Errorf("NewNetworkTools(cfg, nil) = %v, want nil", nt)
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewNetworkTools(cfg, nil) error = %q, want contains %q", err.Error(), "logger is required")
		}
	})

	t.Run("default values applied", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080/",
			// Leave other values at zero - should get defaults
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		if err != nil {
			t.Fatalf("NewNetworkTools() unexpected error: %v", err)
		}
		if nt == nil {
			t.Fatal("NewNetworkTools() = nil, want non-nil")
		}
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
		if err != nil {
			t.Fatalf("NewNetworkTools() unexpected error: %v", err)
		}

		tools, err := RegisterNetworkTools(g, nt)
		if err != nil {
			t.Fatalf("RegisterNetworkTools() unexpected error: %v", err)
		}
		if got, want := len(tools), 2; got != want {
			t.Errorf("RegisterNetworkTools() tool count = %d, want %d (should register 2 network tools)", got, want)
		}

		// Verify tool names
		expectedNames := []string{ToolWebSearch, ToolWebFetch}
		actualNames := extractToolNames(tools)
		if !slicesEqual(expectedNames, actualNames) {
			t.Errorf("RegisterNetworkTools() tool names = %v, want %v", actualNames, expectedNames)
		}
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		cfg := NetworkConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetworkTools(cfg, testLogger())
		if err != nil {
			t.Fatalf("NewNetworkTools() unexpected error: %v", err)
		}

		tools, err := RegisterNetworkTools(nil, nt)
		if err == nil {
			t.Fatal("RegisterNetworkTools(nil, nt) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterNetworkTools(nil, nt) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterNetworkTools(nil, nt) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil NetworkTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterNetworkTools(g, nil)
		if err == nil {
			t.Fatal("RegisterNetworkTools(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterNetworkTools(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "NetworkTools is required") {
			t.Errorf("RegisterNetworkTools(g, nil) error = %q, want contains %q", err.Error(), "NetworkTools is required")
		}
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
		if err == nil {
			t.Fatal("RegisterKnowledgeTools(nil, kt) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterKnowledgeTools(nil, kt) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterKnowledgeTools(nil, kt) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil KnowledgeTools", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterKnowledgeTools(g, nil)
		if err == nil {
			t.Fatal("RegisterKnowledgeTools(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterKnowledgeTools(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "KnowledgeTools is required") {
			t.Errorf("RegisterKnowledgeTools(g, nil) error = %q, want contains %q", err.Error(), "KnowledgeTools is required")
		}
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

// slicesEqual checks if two string slices contain the same elements (order-independent).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	slices.Sort(aCopy)
	slices.Sort(bCopy)
	return slices.Equal(aCopy, bCopy)
}
