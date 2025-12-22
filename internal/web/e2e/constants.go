//go:build e2e

// Package e2e provides end-to-end testing utilities for the web package.
package e2e

import "time"

// Test timeouts for E2E browser tests.
// These are centralized to avoid duplication and ensure consistency.
const (
	// BrowserStartTimeout is the maximum time to wait for browser launch.
	BrowserStartTimeout = 10 * time.Second

	// PageLoadTimeout is the maximum time to wait for page navigation.
	PageLoadTimeout = 3 * time.Second

	// InteractionTimeout is the maximum time to wait for UI interactions.
	InteractionTimeout = 5 * time.Second

	// StreamingTimeout is the maximum time to wait for SSE streaming completion.
	StreamingTimeout = 15 * time.Second

	// ElementVisibleTimeout is the maximum time to wait for element visibility.
	ElementVisibleTimeout = 5 * time.Second

	// SSEWaitTimeout is the maximum time to wait for SSE events (tool indicators, etc).
	// Longer than InteractionTimeout because SSE streaming may take time.
	SSEWaitTimeout = 10 * time.Second
)

// TimeoutMillis returns the timeout in milliseconds for Playwright APIs.
func TimeoutMillis(d time.Duration) float64 {
	return float64(d.Milliseconds())
}
