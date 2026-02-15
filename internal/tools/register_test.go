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

func TestNewFile(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{}, nil)
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFile(pathVal, testLogger())
		if err != nil {
			t.Fatalf("NewFile() unexpected error: %v", err)
		}
		if ft == nil {
			t.Fatal("NewFile() = nil, want non-nil")
		}
	})

	t.Run("nil path validator", func(t *testing.T) {
		t.Parallel()

		ft, err := NewFile(nil, testLogger())
		if err == nil {
			t.Fatal("NewFile(nil, logger) expected error, got nil")
		}
		if ft != nil {
			t.Errorf("NewFile(nil, logger) = %v, want nil", ft)
		}
		if !strings.Contains(err.Error(), "path validator is required") {
			t.Errorf("NewFile(nil, logger) error = %q, want contains %q", err.Error(), "path validator is required")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{}, nil)
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFile(pathVal, nil)
		if err == nil {
			t.Fatal("NewFile(pathVal, nil) expected error, got nil")
		}
		if ft != nil {
			t.Errorf("NewFile(pathVal, nil) = %v, want nil", ft)
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewFile(pathVal, nil) error = %q, want contains %q", err.Error(), "logger is required")
		}
	})
}

func TestRegisterFile(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		pathVal, err := security.NewPath([]string{}, nil)
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFile(pathVal, testLogger())
		if err != nil {
			t.Fatalf("NewFile() unexpected error: %v", err)
		}

		tools, err := RegisterFile(g, ft)
		if err != nil {
			t.Fatalf("RegisterFile() unexpected error: %v", err)
		}
		if got, want := len(tools), 5; got != want {
			t.Errorf("RegisterFile() tool count = %d, want %d (should register 5 file tools)", got, want)
		}

		// Verify tool names
		expectedNames := []string{ReadFileName, WriteFileName, ListFilesName, DeleteFileName, FileInfoName}
		actualNames := extractToolNames(tools)
		if !slicesEqual(expectedNames, actualNames) {
			t.Errorf("RegisterFile() tool names = %v, want %v", actualNames, expectedNames)
		}
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		pathVal, err := security.NewPath([]string{}, nil)
		if err != nil {
			t.Fatalf("NewPath() unexpected error: %v", err)
		}

		ft, err := NewFile(pathVal, testLogger())
		if err != nil {
			t.Fatalf("NewFile() unexpected error: %v", err)
		}

		tools, err := RegisterFile(nil, ft)
		if err == nil {
			t.Fatal("RegisterFile(nil, ft) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterFile(nil, ft) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterFile(nil, ft) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil File", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterFile(g, nil)
		if err == nil {
			t.Fatal("RegisterFile(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterFile(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "File is required") {
			t.Errorf("RegisterFile(g, nil) error = %q, want contains %q", err.Error(), "File is required")
		}
	})
}

func TestNewSystem(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystem(cmdVal, envVal, testLogger())
		if err != nil {
			t.Fatalf("NewSystem() unexpected error: %v", err)
		}
		if st == nil {
			t.Fatal("NewSystem() = nil, want non-nil")
		}
	})

	t.Run("nil command validator", func(t *testing.T) {
		t.Parallel()
		envVal := security.NewEnv()

		st, err := NewSystem(nil, envVal, testLogger())
		if err == nil {
			t.Fatal("NewSystem(nil, envVal, logger) expected error, got nil")
		}
		if st != nil {
			t.Errorf("NewSystem(nil, envVal, logger) = %v, want nil", st)
		}
		if !strings.Contains(err.Error(), "command validator is required") {
			t.Errorf("NewSystem(nil, envVal, logger) error = %q, want contains %q", err.Error(), "command validator is required")
		}
	})

	t.Run("nil env validator", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()

		st, err := NewSystem(cmdVal, nil, testLogger())
		if err == nil {
			t.Fatal("NewSystem(cmdVal, nil, logger) expected error, got nil")
		}
		if st != nil {
			t.Errorf("NewSystem(cmdVal, nil, logger) = %v, want nil", st)
		}
		if !strings.Contains(err.Error(), "env validator is required") {
			t.Errorf("NewSystem(cmdVal, nil, logger) error = %q, want contains %q", err.Error(), "env validator is required")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystem(cmdVal, envVal, nil)
		if err == nil {
			t.Fatal("NewSystem(cmdVal, envVal, nil) expected error, got nil")
		}
		if st != nil {
			t.Errorf("NewSystem(cmdVal, envVal, nil) = %v, want nil", st)
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewSystem(cmdVal, envVal, nil) error = %q, want contains %q", err.Error(), "logger is required")
		}
	})
}

func TestRegisterSystem(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystem(cmdVal, envVal, testLogger())
		if err != nil {
			t.Fatalf("NewSystem() unexpected error: %v", err)
		}

		tools, err := RegisterSystem(g, st)
		if err != nil {
			t.Fatalf("RegisterSystem() unexpected error: %v", err)
		}
		if got, want := len(tools), 3; got != want {
			t.Errorf("RegisterSystem() tool count = %d, want %d (should register 3 system tools)", got, want)
		}

		// Verify tool names
		expectedNames := []string{CurrentTimeName, ExecuteCommandName, GetEnvName}
		actualNames := extractToolNames(tools)
		if !slicesEqual(expectedNames, actualNames) {
			t.Errorf("RegisterSystem() tool names = %v, want %v", actualNames, expectedNames)
		}
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		cmdVal := security.NewCommand()
		envVal := security.NewEnv()

		st, err := NewSystem(cmdVal, envVal, testLogger())
		if err != nil {
			t.Fatalf("NewSystem() unexpected error: %v", err)
		}

		tools, err := RegisterSystem(nil, st)
		if err == nil {
			t.Fatal("RegisterSystem(nil, st) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterSystem(nil, st) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterSystem(nil, st) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil System", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterSystem(g, nil)
		if err == nil {
			t.Fatal("RegisterSystem(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterSystem(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "System is required") {
			t.Errorf("RegisterSystem(g, nil) error = %q, want contains %q", err.Error(), "System is required")
		}
	})
}

func TestNewNetwork(t *testing.T) {
	t.Parallel()

	t.Run("successful creation", func(t *testing.T) {
		t.Parallel()
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err != nil {
			t.Fatalf("NewNetwork() unexpected error: %v", err)
		}
		if nt == nil {
			t.Fatal("NewNetwork() = nil, want non-nil")
		}
	})

	t.Run("empty search base URL", func(t *testing.T) {
		t.Parallel()
		cfg := NetConfig{}

		nt, err := NewNetwork(cfg, testLogger())
		if err == nil {
			t.Fatal("NewNetwork(empty config) expected error, got nil")
		}
		if nt != nil {
			t.Errorf("NewNetwork(empty config) = %v, want nil", nt)
		}
		if !strings.Contains(err.Error(), "search base URL is required") {
			t.Errorf("NewNetwork(empty config) error = %q, want contains %q", err.Error(), "search base URL is required")
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		t.Parallel()
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetwork(cfg, nil)
		if err == nil {
			t.Fatal("NewNetwork(cfg, nil) expected error, got nil")
		}
		if nt != nil {
			t.Errorf("NewNetwork(cfg, nil) = %v, want nil", nt)
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("NewNetwork(cfg, nil) error = %q, want contains %q", err.Error(), "logger is required")
		}
	})

	t.Run("default values applied", func(t *testing.T) {
		t.Parallel()
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080/",
			// Leave other values at zero - should get defaults
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err != nil {
			t.Fatalf("NewNetwork() unexpected error: %v", err)
		}
		if nt == nil {
			t.Fatal("NewNetwork() = nil, want non-nil")
		}
	})
}

func TestRegisterNetwork(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err != nil {
			t.Fatalf("NewNetwork() unexpected error: %v", err)
		}

		tools, err := RegisterNetwork(g, nt)
		if err != nil {
			t.Fatalf("RegisterNetwork() unexpected error: %v", err)
		}
		if got, want := len(tools), 2; got != want {
			t.Errorf("RegisterNetwork() tool count = %d, want %d (should register 2 network tools)", got, want)
		}

		// Verify tool names
		expectedNames := []string{WebSearchName, WebFetchName}
		actualNames := extractToolNames(tools)
		if !slicesEqual(expectedNames, actualNames) {
			t.Errorf("RegisterNetwork() tool names = %v, want %v", actualNames, expectedNames)
		}
	})

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()
		cfg := NetConfig{
			SearchBaseURL: "http://localhost:8080",
		}

		nt, err := NewNetwork(cfg, testLogger())
		if err != nil {
			t.Fatalf("NewNetwork() unexpected error: %v", err)
		}

		tools, err := RegisterNetwork(nil, nt)
		if err == nil {
			t.Fatal("RegisterNetwork(nil, nt) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterNetwork(nil, nt) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterNetwork(nil, nt) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil Network", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterNetwork(g, nil)
		if err == nil {
			t.Fatal("RegisterNetwork(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterNetwork(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "Network is required") {
			t.Errorf("RegisterNetwork(g, nil) error = %q, want contains %q", err.Error(), "Network is required")
		}
	})
}

// Note: Knowledge validation (nil store, nil logger) is tested in
// TestNewKnowledge in knowledge_test.go. These tests verify
// RegisterKnowledge parameter validation only.

func TestRegisterKnowledge(t *testing.T) {
	t.Parallel()

	t.Run("nil genkit", func(t *testing.T) {
		t.Parallel()

		tools, err := RegisterKnowledge(nil, &Knowledge{})
		if err == nil {
			t.Fatal("RegisterKnowledge(nil, kt) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterKnowledge(nil, kt) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "genkit instance is required") {
			t.Errorf("RegisterKnowledge(nil, kt) error = %q, want contains %q", err.Error(), "genkit instance is required")
		}
	})

	t.Run("nil Knowledge", func(t *testing.T) {
		t.Parallel()
		g := setupTestGenkit(t)

		tools, err := RegisterKnowledge(g, nil)
		if err == nil {
			t.Fatal("RegisterKnowledge(g, nil) expected error, got nil")
		}
		if tools != nil {
			t.Errorf("RegisterKnowledge(g, nil) = %v, want nil", tools)
		}
		if !strings.Contains(err.Error(), "Knowledge is required") {
			t.Errorf("RegisterKnowledge(g, nil) error = %q, want contains %q", err.Error(), "Knowledge is required")
		}
	})
}

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
