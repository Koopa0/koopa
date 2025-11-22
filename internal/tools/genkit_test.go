package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/googlegenai"
	"github.com/koopa0/koopa-cli/internal/security"
)

// TestGenkit_ToolDefinition tests that Kit tools can be registered with Genkit
func TestGenkit_ToolDefinition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Genkit integration test in short mode")
	}

	ctx := context.Background()

	// Initialize Genkit (returns only one value)
	g := genkit.Init(ctx, genkit.WithPlugins(&googlegenai.GoogleAI{}))

	// Create Kit
	tmpDir := resolveSymlinks(t, t.TempDir())
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		t.Fatalf("failed to create path validator: %v", err)
	}

	cfg := KitConfig{
		PathVal:        pathVal,
		CmdVal:         security.NewCommand(),
		EnvVal:         security.NewEnv(),
		HTTPVal:        &mockHTTPValidator{},
		KnowledgeStore: &mockKnowledgeSearcherKit{},
	}

	kit, err := NewKit(cfg)
	if err != nil {
		t.Fatalf("failed to create kit: %v", err)
	}

	// Define a tool (ReadFile)
	genkit.DefineTool(g, "readFile",
		"Read the content of a file",
		kit.ReadFile,
	)

	// Lookup the tool
	tool := genkit.LookupTool(g, "readFile")
	if tool == nil {
		t.Fatal("tool 'readFile' not found")
	}

	// Verify tool can be called
	// Note: This won't actually call ReadFile, just verifies registration
	t.Logf("Tool 'readFile' successfully registered")
}

// TestGenkit_ResultSerialization tests that Result is properly serialized
func TestGenkit_ResultSerialization(t *testing.T) {
	// This test verifies that Genkit can serialize our Result struct
	// In practice, Genkit will JSON-encode the Result and pass to LLM

	result := Result{
		Status:  StatusSuccess,
		Message: "File read successfully",
		Data: map[string]any{
			"path":    "/test/file.txt",
			"content": "Hello",
			"size":    5,
		},
	}

	// Simulate what Genkit does
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to serialize Result: %v", err)
	}

	t.Logf("Serialized Result: %s", string(data))

	// Verify structure
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// LLM should see these fields
	if decoded["status"] != "success" {
		t.Errorf("status = %v, want success", decoded["status"])
	}
	if decoded["message"] == nil {
		t.Error("message field missing")
	}
	if decoded["data"] == nil {
		t.Error("data field missing")
	}
}

// TestGenkit_ErrorSerialization tests that Error is properly serialized
func TestGenkit_ErrorSerialization(t *testing.T) {
	result := Result{
		Status:  StatusError,
		Message: "File not found",
		Error: &Error{
			Code:    ErrCodeNotFound,
			Message: "file not found: /test/missing.txt",
			Details: map[string]any{
				"path": "/test/missing.txt",
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to serialize Result: %v", err)
	}

	t.Logf("Serialized Error Result: %s", string(data))

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// Verify error structure
	if decoded["status"] != "error" {
		t.Errorf("status = %v, want error", decoded["status"])
	}

	errorField, ok := decoded["error"].(map[string]any)
	if !ok {
		t.Fatal("error field is not a map")
	}

	if errorField["code"] != string(ErrCodeNotFound) {
		t.Errorf("error.code = %v, want %v", errorField["code"], ErrCodeNotFound)
	}

	if errorField["message"] == nil {
		t.Error("error.message field missing")
	}
}
