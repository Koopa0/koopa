package tools

import (
	"testing"

	"github.com/koopa0/koopa/internal/log"
)

// testLogger returns a no-op logger for testing.
func testLogger() log.Logger {
	return log.NewNop()
}

// newNetworkToolsForTesting creates a NetworkTools instance with SSRF protection
// disabled. This allows tests to use httptest.Server (which binds to localhost).
// Only accessible within tools package tests (unexported).
func newNetworkToolsForTesting(tb testing.TB, cfg NetworkConfig, logger log.Logger) *NetworkTools {
	tb.Helper()
	nt, err := NewNetworkTools(cfg, logger)
	if err != nil {
		tb.Fatalf("NewNetworkTools() unexpected error: %v", err)
	}
	nt.skipSSRFCheck = true
	return nt
}
