package mcp

import (
	"testing"
)

// TestServerGetServerNames tests the GetServerNames method.
func TestServerGetServerNames(t *testing.T) {
	// Create a server with mock states
	server := &Server{
		states: map[string]*State{
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
		states   map[string]*State
		expected int
	}{
		{
			name:     "no servers",
			states:   map[string]*State{},
			expected: 0,
		},
		{
			name: "all connected",
			states: map[string]*State{
				"github": {Name: "github", Status: Connected},
				"notion": {Name: "notion", Status: Connected},
			},
			expected: 2,
		},
		{
			name: "mixed states",
			states: map[string]*State{
				"github": {Name: "github", Status: Connected},
				"notion": {Name: "notion", Status: Failed},
				"slack":  {Name: "slack", Status: Connecting},
			},
			expected: 1,
		},
		{
			name: "none connected",
			states: map[string]*State{
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
		states: map[string]*State{
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
		states: map[string]*State{
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
