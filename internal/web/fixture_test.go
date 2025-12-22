//go:build e2e

package web // Test helpers need access to internal package state

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/koopa0/koopa/internal/config"
	"github.com/koopa0/koopa/internal/session"
	"github.com/koopa0/koopa/internal/sqlc"
	"github.com/koopa0/koopa/internal/testutil"
	"github.com/koopa0/koopa/internal/web/e2e"
	"github.com/playwright-community/playwright-go"
)

// BrowserTestFixture manages Playwright browser instance for E2E tests.
// Renamed from E2EBrowserFixture per Go naming conventions (no redundant prefix).
// Follows same pattern as handlers.TestFramework (setup_test.go:35-53)
type BrowserTestFixture struct {
	pw         *playwright.Playwright
	browser    playwright.Browser
	BrowserCtx playwright.BrowserContext // Exported: Renamed from 'ctx' to avoid confusion with context.Context
}

// SetupBrowserFixture initializes Playwright browser for E2E testing.
// Returns fixture and cleanup function (following Go test best practices).
//
// Usage:
//
//	fixture, cleanup := SetupBrowserFixture(t)
//	t.Cleanup(cleanup)  // Recommended: ensures cleanup even on t.Fatal()
func SetupBrowserFixture(t *testing.T) (*BrowserTestFixture, func()) {
	t.Helper()

	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright.Run: %v", err)
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Timeout:  playwright.Float(e2e.TimeoutMillis(e2e.BrowserStartTimeout)),
	})
	if err != nil {
		pw.Stop()
		t.Fatalf("launch chromium: %v", err)
	}

	BrowserCtx, err := browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 1280, Height: 720},
	})
	if err != nil {
		browser.Close()
		pw.Stop()
		t.Fatalf("new browser context: %v", err)
	}

	cleanup := func() {
		if BrowserCtx != nil {
			BrowserCtx.Close()
		}
		if browser != nil {
			browser.Close()
		}
		if pw != nil {
			pw.Stop()
		}
	}

	fixture := &BrowserTestFixture{pw: pw, browser: browser, BrowserCtx: BrowserCtx}
	return fixture, cleanup
}

// StartTestServer starts HTTP server for E2E tests with full dependencies.
// Uses testutil primitives directly for testcontainers-based data isolation.
//
// Following user suggestion: Use testcontainers for E2E test data isolation.
// Each test gets a fresh PostgreSQL container → ensures test idempotency.
//
// Uses simulation mode (ChatFlow = nil) to avoid GEMINI_API_KEY dependency.
// This makes tests deterministic and removes external API dependency.
func StartTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	// Setup PostgreSQL testcontainer for data isolation
	dbContainer, dbCleanup := testutil.SetupTestDB(t)

	// Create session store with test database
	queries := sqlc.New(dbContainer.Pool)
	sessionStore := session.New(queries, dbContainer.Pool, testutil.DiscardLogger())

	// Use simulation mode (ChatFlow = nil) to avoid GEMINI_API_KEY dependency
	// This makes tests deterministic and removes external API dependency
	// The chat handler has built-in simulation mode for development/testing

	// Build full web server with real routes
	// (Following internal/web/server.go API)
	srv, err := NewServer(ServerConfig{
		Logger:       testutil.DiscardLogger(),
		ChatFlow:     nil, // ← nil enables simulation mode (deterministic responses)
		SessionStore: sessionStore,
		CSRFSecret:   []byte("test-csrf-secret-32-bytes-long!!"),
		Config:       &config.Config{}, // ← Minimal config for E2E testing
		IsDev:        true,             // ← Enable relaxed CSP for E2E testing (allows axe-core eval)
	})
	if err != nil {
		dbCleanup()
		t.Fatalf("Failed to create test server: %v", err)
	}

	server := httptest.NewServer(srv)

	cleanup := func() {
		server.Close()
		dbCleanup() // Clean up DB container
	}

	return server, cleanup
}

// =============================================================================
// SSE Event Capture
// =============================================================================

// SSECapture captures SSE events from network requests for testing.
// Uses Playwright route interception at the network level.
type SSECapture struct {
	mu     sync.Mutex
	events []SSEEvent
}

// SSEEvent represents a captured SSE event.
type SSEEvent struct {
	Type string // "chunk", "done", "error"
	Data string // Raw event data
}

// Events returns a copy of captured events (thread-safe).
func (c *SSECapture) Events() []SSEEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]SSEEvent, len(c.events))
	copy(result, c.events)
	return result
}

// HasEventType checks if an event type was captured.
func (c *SSECapture) HasEventType(eventType string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == eventType {
			return true
		}
	}
	return false
}

// ContainsData checks if any event contains the specified data substring.
func (c *SSECapture) ContainsData(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if strings.Contains(e.Data, substr) {
			return true
		}
	}
	return false
}

// addEvent adds an event (thread-safe).
func (c *SSECapture) addEvent(eventType, data string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, SSEEvent{Type: eventType, Data: data})
}

// CaptureSSEEvents sets up SSE event capture via Playwright route interception.
// Returns an SSECapture that accumulates events for later inspection.
//
// Usage:
//
//	capture := fixture.CaptureSSEEvents(page)
//	// ... trigger action that causes SSE ...
//	events := capture.Events()
func (f *BrowserTestFixture) CaptureSSEEvents(page playwright.Page) *SSECapture {
	capture := &SSECapture{}

	// Intercept SSE requests to /genui/stream
	page.Route("**/genui/stream**", func(route playwright.Route) {
		// Continue the request but capture response
		response, err := route.Fetch()
		if err != nil {
			route.Continue()
			return
		}

		// Get response body (SSE events)
		body, err := response.Body()
		if err != nil {
			route.Fulfill(playwright.RouteFulfillOptions{Response: response})
			return
		}

		// Parse SSE events from body
		parseSSEEvents(string(body), capture)

		// Fulfill with original response
		route.Fulfill(playwright.RouteFulfillOptions{Response: response})
	})

	return capture
}

// parseSSEEvents extracts event types and data from SSE stream.
func parseSSEEvents(body string, capture *SSECapture) {
	lines := strings.Split(body, "\n")
	var currentEvent, currentData string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			currentData = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		} else if line == "" && currentEvent != "" {
			// End of event block
			capture.addEvent(currentEvent, currentData)
			currentEvent = ""
			currentData = ""
		}
	}

	// Handle last event if no trailing newline
	if currentEvent != "" {
		capture.addEvent(currentEvent, currentData)
	}
}

// =============================================================================
// Viewport Helpers
// =============================================================================

// SetViewport sets the page viewport to the specified dimensions.
// Use for responsive design testing.
//
// Common breakpoints:
//   - Mobile: 375x667 (iPhone SE)
//   - Tablet: 768x1024 (iPad)
//   - Desktop: 1280x720 (default)
//   - Large: 1024x768 (lg breakpoint)
//   - XL: 1536x864 (2xl breakpoint)
func SetViewport(page playwright.Page, width, height int) error {
	return page.SetViewportSize(width, height)
}
