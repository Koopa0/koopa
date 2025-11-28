package mcp

import (
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/security"
	"github.com/koopa0/koopa-cli/internal/tools"
)

// Performance Expectations (from TESTING_STRATEGY_v3.md):
// - JSON-RPC parse: < 1ms

// BenchmarkServer_Creation benchmarks MCP server creation.
// Run with: go test -bench=BenchmarkServer_Creation -benchmem ./internal/mcp/...
func BenchmarkServer_Creation(b *testing.B) {
	for b.Loop() {
		tmpDir := b.TempDir()
		pathVal, err := security.NewPath([]string{tmpDir})
		if err != nil {
			b.Fatalf("Failed to create path validator: %v", err)
		}

		fileToolset, err := tools.NewFileToolset(pathVal, slog.Default())
		if err != nil {
			b.Fatalf("Failed to create file toolset: %v", err)
		}

		cmdVal := security.NewCommand()
		envVal := security.NewEnv()
		systemToolset, err := tools.NewSystemToolset(cmdVal, envVal, slog.Default())
		if err != nil {
			b.Fatalf("Failed to create system toolset: %v", err)
		}

		networkToolset, err := tools.NewNetworkToolset(
			"http://localhost:8080", // test SearXNG URL
			2,                       // parallelism
			100*time.Millisecond,    // delay
			30*time.Second,          // timeout
			slog.Default(),
		)
		if err != nil {
			b.Fatalf("Failed to create network toolset: %v", err)
		}

		cfg := Config{
			Name:           "benchmark-server",
			Version:        "1.0.0",
			FileToolset:    fileToolset,
			SystemToolset:  systemToolset,
			NetworkToolset: networkToolset,
		}

		_, err = NewServer(cfg)
		if err != nil {
			b.Fatalf("NewServer failed: %v", err)
		}
	}
}

// BenchmarkJSONRPC_Parse benchmarks JSON-RPC message parsing.
// This tests the raw JSON parsing performance which is critical for MCP.
func BenchmarkJSONRPC_Parse(b *testing.B) {
	// Sample JSON-RPC request message
	requestJSON := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}`

	b.ResetTimer()
	for b.Loop() {
		var request map[string]any
		if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
			b.Fatalf("JSON unmarshal failed: %v", err)
		}
	}
}

// BenchmarkJSONRPC_Parse_LargePayload benchmarks parsing larger JSON-RPC messages.
func BenchmarkJSONRPC_Parse_LargePayload(b *testing.B) {
	// Larger JSON-RPC response message (simulating file content return)
	response := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": generateLargeContent(10000), // 10KB content
				},
			},
		},
	}
	responseJSON, _ := json.Marshal(response)

	b.ResetTimer()
	for b.Loop() {
		var parsed map[string]any
		if err := json.Unmarshal(responseJSON, &parsed); err != nil {
			b.Fatalf("JSON unmarshal failed: %v", err)
		}
	}
}

// BenchmarkJSONRPC_Serialize benchmarks JSON-RPC message serialization.
func BenchmarkJSONRPC_Serialize(b *testing.B) {
	response := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": "File content here",
				},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := json.Marshal(response)
		if err != nil {
			b.Fatalf("JSON marshal failed: %v", err)
		}
	}
}

// BenchmarkJSONRPC_Serialize_LargePayload benchmarks serializing larger responses.
func BenchmarkJSONRPC_Serialize_LargePayload(b *testing.B) {
	response := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": generateLargeContent(100000), // 100KB content
				},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := json.Marshal(response)
		if err != nil {
			b.Fatalf("JSON marshal failed: %v", err)
		}
	}
}

// BenchmarkReadFileInput_Parse benchmarks parsing ReadFileInput from JSON.
func BenchmarkReadFileInput_Parse(b *testing.B) {
	inputJSON := `{"path":"/tmp/test/path/to/file.txt"}`

	b.ResetTimer()
	for b.Loop() {
		var input tools.ReadFileInput
		if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
			b.Fatalf("JSON unmarshal failed: %v", err)
		}
	}
}

// BenchmarkConfig_Validation benchmarks Config validation.
func BenchmarkConfig_Validation(b *testing.B) {
	tmpDir := b.TempDir()
	pathVal, err := security.NewPath([]string{tmpDir})
	if err != nil {
		b.Fatalf("Failed to create path validator: %v", err)
	}

	fileToolset, err := tools.NewFileToolset(pathVal, slog.Default())
	if err != nil {
		b.Fatalf("Failed to create file toolset: %v", err)
	}

	cmdVal := security.NewCommand()
	envVal := security.NewEnv()
	systemToolset, err := tools.NewSystemToolset(cmdVal, envVal, slog.Default())
	if err != nil {
		b.Fatalf("Failed to create system toolset: %v", err)
	}

	networkToolset, err := tools.NewNetworkToolset(
		"http://localhost:8080", // test SearXNG URL
		2,                       // parallelism
		100*time.Millisecond,    // delay
		30*time.Second,          // timeout
		slog.Default(),
	)
	if err != nil {
		b.Fatalf("Failed to create network toolset: %v", err)
	}

	cfg := Config{
		Name:           "validation-test",
		Version:        "1.0.0",
		FileToolset:    fileToolset,
		SystemToolset:  systemToolset,
		NetworkToolset: networkToolset,
	}

	b.ResetTimer()
	for b.Loop() {
		// Validate config by attempting to create server
		// (validation happens in NewServer)
		_, _ = NewServer(cfg)
	}
}

// generateLargeContent generates a string of approximately the specified size.
func generateLargeContent(size int) string {
	content := make([]byte, size)
	for i := range content {
		content[i] = byte('a' + (i % 26))
	}
	return string(content)
}
