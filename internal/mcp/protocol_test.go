package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectTestServer creates a Koopa MCP server and an SDK client connected
// via in-memory transports. Returns the client session for making protocol calls.
// The server session and client session are cleaned up via t.Cleanup.
func connectTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	h := newTestHelper(t)
	cfg := h.createValidConfig()

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer() unexpected error: %v", err)
	}

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	// Connect server side
	serverSession, err := server.mcpServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	// Connect client side
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
		t.Fatalf("CallTool(current_time) failed to parse JSON: %v\ntext: %s", err, textContent.Text)
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
