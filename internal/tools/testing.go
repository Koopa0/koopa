package tools

import (
	"context"
	"testing"

	"github.com/koopa0/koopa-cli/internal/agent"
	"github.com/koopa0/koopa-cli/internal/log"
)

// This file contains shared test helpers for the tools package.

// testLogger returns a logger for testing that discards all output.
// Use this instead of defining mockLogger in each test file.
func testLogger() log.Logger {
	return log.NewNop()
}

// createTestInvocationContext creates a test invocation context for toolset testing.
// Uses t.Fatalf for proper test failure reporting instead of panic.
func createTestInvocationContext(t *testing.T) agent.ReadonlyContext {
	t.Helper()
	sessionID, err := agent.NewSessionID("test-session")
	if err != nil {
		t.Fatalf("createTestInvocationContext: invalid session ID: %v", err)
	}
	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-invocation-id",
		"test-branch",
		sessionID,
		"test-agent",
	)
	return ctx
}
