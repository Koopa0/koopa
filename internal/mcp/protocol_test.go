package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectServer creates a Koopa MCP server from the given config and an SDK
// client connected via in-memory transports. Returns the client session for
// making protocol calls. Both sessions are cleaned up via t.Cleanup.
func connectServer(t *testing.T, cfg Config) *mcp.ClientSession {
	t.Helper()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() unexpected error: %v", err)
	}

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	serverSession, err := server.mcpServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}, nil)

	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession
}

// connectTestServer creates a Koopa MCP server without knowledge tools
// and an SDK client connected via in-memory transports.
func connectTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()
	h := newTestHelper(t)
	return connectServer(t, h.createValidConfig())
}

// connectTestServerWithKnowledge creates a Koopa MCP server including
// knowledge tools (backed by a mock retriever) and an SDK client.
func connectTestServerWithKnowledge(t *testing.T) *mcp.ClientSession {
	t.Helper()
	h := newTestHelper(t)
	return connectServer(t, h.createConfigWithKnowledge())
}

// TestProtocol_ListTools verifies that the MCP JSON-RPC tools/list
// endpoint returns all registered tools with correct names.
func TestProtocol_ListTools(t *testing.T) {
	session := connectTestServer(t)

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() unexpected error: %v", err)
	}

	// Extract tool names
	var names []string
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)

	// Expect 10 tools (5 file + 3 system + 2 network, no knowledge tools in this config)
	wantNames := []string{
		"current_time",
		"delete_file",
		"execute_command",
		"get_env",
		"get_file_info",
		"list_files",
		"read_file",
		"web_fetch",
		"web_search",
		"write_file",
	}

	if len(names) != len(wantNames) {
		t.Fatalf("ListTools() returned %d tools, want %d\ngot:  %v\nwant: %v", len(names), len(wantNames), names, wantNames)
	}

	for i, got := range names {
		if got != wantNames[i] {
			t.Errorf("ListTools() tool[%d] = %q, want %q", i, got, wantNames[i])
		}
	}
}

// TestProtocol_ListTools_HaveDescriptions verifies that all tools
// include non-empty descriptions (required by MCP spec).
func TestProtocol_ListTools_HaveDescriptions(t *testing.T) {
	session := connectTestServer(t)

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() unexpected error: %v", err)
	}

	for _, tool := range result.Tools {
		if tool.Description == "" {
			t.Errorf("ListTools() tool %q has empty description", tool.Name)
		}
	}
}

// TestProtocol_CallTool_CurrentTime verifies that tools/call works
// end-to-end through the JSON-RPC layer for the current_time tool.
func TestProtocol_CallTool_CurrentTime(t *testing.T) {
	session := connectTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "current_time",
	})
	if err != nil {
		t.Fatalf("CallTool(current_time) unexpected error: %v", err)
	}

	if result.IsError {
		t.Fatalf("CallTool(current_time) returned error result")
	}

	if len(result.Content) == 0 {
		t.Fatal("CallTool(current_time) returned empty content")
	}

	// The first content item should be TextContent containing a timestamp
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("CallTool(current_time) content[0] type = %T, want *mcp.TextContent", result.Content[0])
	}

	// Parse the JSON text result (contains mixed types: strings and numbers)
	var timeResult map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &timeResult); err != nil {
		t.Fatalf("CallTool(current_time) parsing JSON: %v\ntext: %s", err, textContent.Text)
	}

	// Should contain time fields
	if len(timeResult) == 0 {
		t.Error("CallTool(current_time) returned empty JSON object")
	}
}

// TestProtocol_CallTool_UnknownTool verifies that calling a non-existent
// tool returns a proper error through the JSON-RPC layer.
func TestProtocol_CallTool_UnknownTool(t *testing.T) {
	session := connectTestServer(t)

	_, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "nonexistent_tool",
	})

	// The SDK should return an error for unknown tools
	if err == nil {
		t.Fatal("CallTool(nonexistent_tool) expected error, got nil")
	}

	if !strings.Contains(err.Error(), "nonexistent_tool") {
		t.Errorf("CallTool(nonexistent_tool) error = %q, want to contain tool name", err.Error())
	}
}

// TestProtocol_ListTools_WithKnowledge verifies that knowledge search tools
// are registered when Knowledge is configured. knowledge_store is excluded
// because the test helper creates Knowledge with docStore=nil.
func TestProtocol_ListTools_WithKnowledge(t *testing.T) {
	session := connectTestServerWithKnowledge(t)

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() unexpected error: %v", err)
	}

	var names []string
	for _, tool := range result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)

	// 10 base + 3 knowledge search tools (knowledge_store excluded: docStore=nil)
	wantNames := []string{
		"current_time",
		"delete_file",
		"execute_command",
		"get_env",
		"get_file_info",
		"list_files",
		"read_file",
		"search_documents",
		"search_history",
		"search_system_knowledge",
		"web_fetch",
		"web_search",
		"write_file",
	}

	if len(names) != len(wantNames) {
		t.Fatalf("ListTools() returned %d tools, want %d\ngot:  %v\nwant: %v", len(names), len(wantNames), names, wantNames)
	}

	for i, got := range names {
		if got != wantNames[i] {
			t.Errorf("ListTools() tool[%d] = %q, want %q", i, got, wantNames[i])
		}
	}
}

// TestProtocol_CallTool_KnowledgeSearch verifies that each knowledge search
// tool can be called through the MCP JSON-RPC layer and returns results.
func TestProtocol_CallTool_KnowledgeSearch(t *testing.T) {
	session := connectTestServerWithKnowledge(t)

	tests := []struct {
		name     string
		toolName string
	}{
		{name: "search_history", toolName: "search_history"},
		{name: "search_documents", toolName: "search_documents"},
		{name: "search_system_knowledge", toolName: "search_system_knowledge"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name: tt.toolName,
				Arguments: map[string]any{
					"query": "test query",
					"topK":  3,
				},
			})
			if err != nil {
				t.Fatalf("CallTool(%q) unexpected error: %v", tt.toolName, err)
			}

			if result.IsError {
				t.Fatalf("CallTool(%q) returned error result", tt.toolName)
			}

			if len(result.Content) == 0 {
				t.Fatalf("CallTool(%q) returned empty content", tt.toolName)
			}

			textContent, ok := result.Content[0].(*mcp.TextContent)
			if !ok {
				t.Fatalf("CallTool(%q) content[0] type = %T, want *mcp.TextContent", tt.toolName, result.Content[0])
			}

			// Parse JSON and verify result structure
			var parsed map[string]any
			if err := json.Unmarshal([]byte(textContent.Text), &parsed); err != nil {
				t.Fatalf("CallTool(%q) parsing JSON: %v\ntext: %s", tt.toolName, err, textContent.Text)
			}

			if parsed["query"] != "test query" {
				t.Errorf("CallTool(%q) query = %v, want %q", tt.toolName, parsed["query"], "test query")
			}

			// mock retriever returns 1 document
			if count, ok := parsed["result_count"].(float64); !ok || count != 1 {
				t.Errorf("CallTool(%q) result_count = %v, want 1", tt.toolName, parsed["result_count"])
			}
		})
	}
}

// TestProtocol_CallTool_KnowledgeStore_NoDocStore verifies that
// knowledge_store is not registered when docStore is nil.
func TestProtocol_CallTool_KnowledgeStore_NoDocStore(t *testing.T) {
	session := connectTestServerWithKnowledge(t)

	_, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "knowledge_store",
		Arguments: map[string]any{
			"title":   "test",
			"content": "test content",
		},
	})
	if err == nil {
		t.Fatal("CallTool(knowledge_store) expected error for unregistered tool, got nil")
	}

	if !strings.Contains(err.Error(), "knowledge_store") {
		t.Errorf("CallTool(knowledge_store) error = %q, want to contain tool name", err.Error())
	}
}
