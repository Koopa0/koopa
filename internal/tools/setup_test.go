package tools

import (
	"log/slog"
	"testing"
)

// testLogger returns a no-op logger for testing.
func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newNetworkForTesting creates a Network instance with SSRF protection
// disabled. This allows tests to use httptest.Server (which binds to localhost).
// Only accessible within tools package tests (unexported).
func newNetworkForTesting(tb testing.TB, cfg NetConfig, logger *slog.Logger) *Network {
	tb.Helper()
	nt, err := NewNetwork(cfg, logger)
	if err != nil {
		tb.Fatalf("NewNetwork() unexpected error: %v", err)
	}
	nt.skipSSRFCheck = true
	nt.searchClient.Transport = nil // allow localhost in tests
	return nt
}
