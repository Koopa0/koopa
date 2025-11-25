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
func createTestInvocationContext() agent.ReadonlyContext {
	ctx := agent.NewInvocationContext(
		context.Background(),
		"test-invocation-id",
		"test-branch",
		agent.NewSessionID("test-session"),
		"test-agent",
	)
	return ctx
}
