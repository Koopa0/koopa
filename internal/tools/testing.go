package tools

import (
	"context"

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
// Panics if session ID creation fails (should never happen with hardcoded valid value).
func createTestInvocationContext() agent.ReadonlyContext {
	sessionID, err := agent.NewSessionID("test-session")
	if err != nil {
		panic("createTestInvocationContext: invalid session ID: " + err.Error())
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
