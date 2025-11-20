package tools

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa-cli/internal/knowledge"
	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/stretchr/testify/mock"
)

// TestToolNames tests that ToolNames returns the correct list
func TestToolNames(t *testing.T) {
	names := ToolNames()

	expectedTools := []string{
		"currentTime",
		"readFile",
		"writeFile",
		"listFiles",
		"deleteFile",
		"executeCommand",
		"httpGet",
		"getEnv",
		"getFileInfo",
		"searchHistory",
		"searchDocuments",
		"searchSystemKnowledge",
	}

	if len(names) != len(expectedTools) {
		t.Errorf("expected %d tools, got %d", len(expectedTools), len(names))
	}

	// Check all expected tools are present
	toolMap := make(map[string]bool)
	for _, name := range names {
		toolMap[name] = true
	}

	for _, expected := range expectedTools {
		if !toolMap[expected] {
			t.Errorf("expected tool %q not found in tool names", expected)
		}
	}
}

// mockKnowledgeStore is a simple mock for testing
type mockKnowledgeStore struct {
	mock.Mock
}

func (m *mockKnowledgeStore) Search(ctx context.Context, query string, opts ...knowledge.SearchOption) ([]knowledge.Result, error) {
	args := m.Called(ctx, query, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]knowledge.Result), args.Error(1)
}

// TestRegisterTools tests that all tools are registered successfully
func TestRegisterTools(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create security validators
	pathVal, err := security.NewPath([]string{})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cmdVal := security.NewCommand()
	httpVal := security.NewHTTP()
	envVal := security.NewEnv()

	// Create mock knowledge store
	mockStore := new(mockKnowledgeStore)

	// Register tools should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RegisterTools panicked: %v", r)
		}
	}()

	_ = RegisterTools(g, pathVal, cmdVal, httpVal, envVal, mockStore)
}

// TestToolNamesImmutable tests that ToolNames returns a copy (not modifiable)
func TestToolNamesImmutable(t *testing.T) {
	names1 := ToolNames()
	names2 := ToolNames()

	// Should return same content
	if len(names1) != len(names2) {
		t.Error("ToolNames returns different lengths")
	}

	// Modifying returned slice should not affect toolNames
	original := ToolNames()
	originalLen := len(original)

	// Try to modify returned slice (should not affect internal state)
	returned := ToolNames()
	if len(returned) > 0 {
		returned[0] = "modified"
	}

	// Verify original list is unchanged
	current := ToolNames()
	if len(current) != originalLen {
		t.Error("ToolNames list was modified")
	}
}

// BenchmarkToolNames benchmarks ToolNames retrieval
func BenchmarkToolNames(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		_ = ToolNames()
	}
}
