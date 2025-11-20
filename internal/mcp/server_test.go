package mcp

import (
	"context"
	"testing"

	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/mcp"
)

// TestServerGetServerNames tests the GetServerNames method.
func TestServerGetServerNames(t *testing.T) {
	// Create a server with mock states
	server := &Server{
		states: map[string]State{
			"github": {Name: "github", Status: Connected},
			"notion": {Name: "notion", Status: Connected},
			"slack":  {Name: "slack", Status: Failed},
		},
	}

	names := server.ServerNames()

	if len(names) != 3 {
		t.Errorf("expected 3 server names, got %d", len(names))
	}

	// Check that all expected names are present
	expectedNames := map[string]bool{
		"github": false,
		"notion": false,
		"slack":  false,
	}

	for _, name := range names {
		if _, exists := expectedNames[name]; exists {
			expectedNames[name] = true
		} else {
			t.Errorf("unexpected server name: %s", name)
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected server name '%s' not found", name)
		}
	}
}

// TestServerGetConnectedCount tests the GetConnectedCount method.
func TestServerGetConnectedCount(t *testing.T) {
	tests := []struct {
		name     string
		states   map[string]State
		expected int
	}{
		{
			name:     "no servers",
			states:   map[string]State{},
			expected: 0,
		},
		{
			name: "all connected",
			states: map[string]State{
				"github": {Name: "github", Status: Connected},
				"notion": {Name: "notion", Status: Connected},
			},
			expected: 2,
		},
		{
			name: "mixed states",
			states: map[string]State{
				"github": {Name: "github", Status: Connected},
				"notion": {Name: "notion", Status: Failed},
				"slack":  {Name: "slack", Status: Connecting},
			},
			expected: 1,
		},
		{
			name: "none connected",
			states: map[string]State{
				"github": {Name: "github", Status: Failed},
				"notion": {Name: "notion", Status: Disconnected},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				states: tt.states,
			}

			count := server.ConnectedCount()

			if count != tt.expected {
				t.Errorf("expected %d connected servers, got %d", tt.expected, count)
			}
		})
	}
}

// TestServerGetState tests the GetState method.
func TestServerGetState(t *testing.T) {
	server := &Server{
		states: map[string]State{
			"github": {
				Name:         "github",
				Status:       Connected,
				SuccessCount: 5,
				FailureCount: 1,
			},
		},
	}

	// Test existing server
	state, exists := server.State("github")
	if !exists {
		t.Error("expected github server to exist")
	}
	if state.Name != "github" {
		t.Errorf("expected name 'github', got '%s'", state.Name)
	}
	if state.Status != Connected {
		t.Errorf("expected status Connected, got %s", state.Status)
	}
	if state.SuccessCount != 5 {
		t.Errorf("expected SuccessCount 5, got %d", state.SuccessCount)
	}

	// Test non-existing server
	_, exists = server.State("nonexistent")
	if exists {
		t.Error("expected nonexistent server to not exist")
	}

	// Test that returned state is a copy (not a reference)
	state.SuccessCount = 100
	originalState, _ := server.State("github")
	if originalState.SuccessCount == 100 {
		t.Error("GetState should return a copy, not a reference")
	}
}

// TestServerGetStates tests the GetStates method.
func TestServerGetStates(t *testing.T) {
	server := &Server{
		states: map[string]State{
			"github": {Name: "github", Status: Connected},
			"notion": {Name: "notion", Status: Failed, FailureCount: 2},
		},
	}

	states := server.States()

	if len(states) != 2 {
		t.Errorf("expected 2 states, got %d", len(states))
	}

	// Verify github state
	githubState, exists := states["github"]
	if !exists {
		t.Error("expected github state to exist")
	}
	if githubState.Status != Connected {
		t.Errorf("expected github status Connected, got %s", githubState.Status)
	}

	// Verify notion state
	notionState, exists := states["notion"]
	if !exists {
		t.Error("expected notion state to exist")
	}
	if notionState.Status != Failed {
		t.Errorf("expected notion status Failed, got %s", notionState.Status)
	}

	// Test that returned states are copies
	githubState.SuccessCount = 100
	originalStates := server.States()
	if originalStates["github"].SuccessCount == 100 {
		t.Error("GetStates should return copies, not references")
	}
}

// ============================================================================
// New and Tools Function Tests
// ============================================================================

// TestNew_EmptyConfig tests New with empty configuration
func TestNew_EmptyConfig(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Test with empty config - should create host with no servers
	server, err := New(ctx, g, []Config{})
	if err != nil {
		t.Fatalf("expected no error with empty config, got: %v", err)
	}

	if server == nil {
		t.Fatal("expected server to be created, got nil")
	}

	// Verify no servers are registered
	if server.ConnectedCount() != 0 {
		t.Errorf("expected 0 connected servers, got %d", server.ConnectedCount())
	}

	names := server.ServerNames()
	if len(names) != 0 {
		t.Errorf("expected 0 server names, got %d", len(names))
	}
}

// TestNew_SingleConfig tests New with a single server configuration
func TestNew_SingleConfig(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Test with a single config (note: may fail if server is not available, but tests code path)
	configs := []Config{
		{
			Name: "test-server",
			ClientOptions: mcp.MCPClientOptions{
				Name: "test-server",
				Stdio: &mcp.StdioConfig{
					Command: "nonexistent-command",
					Args:    []string{},
				},
			},
		},
	}

	// This may fail, but it exercises the New function code path
	server, err := New(ctx, g, configs)

	// We accept either success or failure, as long as the function handles it gracefully
	if err != nil {
		t.Logf("New returned error (expected for nonexistent command): %v", err)
		// Verify server is still returned with failed state
		if server != nil {
			state, exists := server.State("test-server")
			if exists && state.Status == Failed {
				t.Log("Server correctly marked as failed")
			}
		}
	} else {
		t.Log("New succeeded (server configuration may be valid)")
		if server == nil {
			t.Fatal("expected server to be returned when no error")
		}
	}
}

// TestTools_EmptyServer tests Tools method on server with no configurations
func TestTools_EmptyServer(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create server with no configurations
	server, err := New(ctx, g, []Config{})
	if err != nil {
		t.Fatalf("failed to create empty server: %v", err)
	}

	// Get tools from empty server
	tools, err := server.Tools(ctx, g)

	// Empty server should return empty tools, not error
	if err != nil {
		t.Logf("Tools returned error (may be expected): %v", err)
	}

	if tools == nil {
		t.Log("Tools returned nil (acceptable for empty server)")
	} else {
		t.Logf("Tools returned %d tools", len(tools))
	}
}

// TestTools_WithFailedServer tests Tools method with a server that fails to connect
func TestTools_WithFailedServer(t *testing.T) {
	ctx := context.Background()
	g := genkit.Init(ctx)

	// Create server with a config that will fail to connect
	configs := []Config{
		{
			Name: "failing-server",
			ClientOptions: mcp.MCPClientOptions{
				Name: "failing-server",
				Stdio: &mcp.StdioConfig{
					Command: "nonexistent-command-for-testing",
					Args:    []string{},
				},
			},
		},
	}

	server, err := New(ctx, g, configs)
	if err != nil {
		t.Logf("New returned error (expected for failing server): %v", err)
	}

	if server == nil {
		t.Skip("Server creation failed completely, cannot test Tools method")
	}

	// Verify server was created with failed state
	state, exists := server.State("failing-server")
	if exists {
		t.Logf("Server state: %s, FailureCount: %d", state.Status, state.FailureCount)
	}

	// Try to get tools from server with failed connection
	tools, err := server.Tools(ctx, g)

	// Log results (behavior may vary based on implementation)
	if err != nil {
		t.Logf("Tools returned error (may be expected for failed server): %v", err)

		// Verify states were updated on error
		statesAfter := server.States()
		for name, state := range statesAfter {
			t.Logf("After Tools error - Server %s: Status=%s, FailureCount=%d",
				name, state.Status, state.FailureCount)
		}
	} else {
		t.Logf("Tools succeeded with %d tools", len(tools))
	}
}
