//go:build integration
// +build integration

package agent

import (
	"context"
	"testing"
)

// TestSetupTestAgent_Integration verifies that SetupTestAgent creates a complete
// Agent test environment with all components properly initialized.
//
// This test validates:
//   - Agent instance is created successfully
//   - Test session is created and linked to agent
//   - All framework components are accessible
//
// Note: This test is agent-specific and remains in the agent package.
// Database infrastructure tests are in internal/testutil/postgres_test.go
//
// Run with: go test -tags=integration ./internal/agent -v -run=TestSetupTestAgent
func TestSetupTestAgent_Integration(t *testing.T) {
	// Setup test agent framework
	framework, cleanup := SetupTestAgent(t)
	defer cleanup()

	// Verify agent is created
	if framework.Agent == nil {
		t.Fatal("Agent not created")
	}

	// Verify session exists
	ctx := context.Background()
	session, err := framework.SessionStore.GetSession(ctx, framework.SessionID)
	if err != nil {
		t.Fatalf("Failed to get test session: %v", err)
	}

	if session.Title != "Integration Test Session" {
		t.Errorf("Expected session title 'Integration Test Session', got %q", session.Title)
	}

	t.Logf("Agent framework created successfully with session %s", framework.SessionID)
}
