//go:build e2e

package web // Test helpers need access to internal package state

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/session"
	"github.com/koopa0/koopa-cli/internal/sqlc"
	"github.com/koopa0/koopa-cli/internal/testutil"
	"github.com/playwright-community/playwright-go"
)

// E2E test timeouts (following cmd/e2e_test.go pattern)
const (
	browserStartTimeout = 10 * time.Second
	pageLoadTimeout     = 3 * time.Second
	streamingTimeout    = 15 * time.Second // AI response timeout
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
		Timeout:  playwright.Float(float64(browserStartTimeout.Milliseconds())),
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
	srv, err := NewServer(ServerDeps{
		Logger:       testutil.DiscardLogger(),
		ChatFlow:     nil, // ← nil enables simulation mode (deterministic responses)
		SessionStore: sessionStore,
		CSRFSecret:   []byte("test-csrf-secret-32-bytes-long!!"),
		IsDev:        true, // ← Enable relaxed CSP for E2E testing (allows axe-core eval)
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
