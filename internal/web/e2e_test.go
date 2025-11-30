//go:build e2e

package web_test // Black-box testing (test helpers in package web)

import (
	"strings"
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/web"
	"github.com/koopa0/koopa-cli/internal/web/e2e"
	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pageLoadTimeout is imported from fixture_test.go via package web
const (
	pageLoadTimeout  = 3 * time.Second
	streamingTimeout = 15 * time.Second
)

func TestE2E_ChatMessageFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Start real server (calls helper from package web)
	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	// Setup browser (calls helper from package web)
	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	// Navigate to chat page
	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// 1. Verify initial page load
	assert.Eventually(t, func() bool {
		title, err := page.Title()
		if err != nil {
			t.Logf("failed to get page title: %v", err)
			return false
		}
		return title == "Chat - Koopa"
	}, pageLoadTimeout, 100*time.Millisecond, "page should load with correct title")

	// 2. Type message (using input#message-input, not textarea)
	err = page.Fill("input[name='content']", "What is 2+2?")
	require.NoError(t, err, "failed to fill textarea")

	// 3. Submit form (use specific selector to avoid clicking "New Chat" button)
	err = page.Click("form[action='/genui/chat/send'] button[type='submit']")
	require.NoError(t, err, "failed to click submit button")

	// 4. Verify user message appears
	userMsg := page.Locator("article[id^='msg-user-']")
	err = userMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "user message should appear after submit")

	// 5. Verify assistant message shell appears (with SSE connection)
	// In simulation mode (ChatFlow = nil), the handler sends simulated streaming response
	assistantShell := page.Locator("article[id^='msg-assistant-'][hx-ext='sse']")
	err = assistantShell.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "assistant message shell should appear with SSE connection")

	// 6. Wait for SSE streaming to complete (simulation mode sends test text)
	// The final message replaces the shell via hx-swap-oob, losing hx-ext attribute
	finalMsg := page.Locator("article[id^='msg-assistant-']:not([hx-ext])")
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(float64(streamingTimeout.Milliseconds())),
	})
	require.NoError(t, err, "assistant message should complete streaming")

	// 7. Verify final message contains simulated response text
	msgContent, err := finalMsg.TextContent()
	require.NoError(t, err, "failed to get message content")
	assert.Contains(t, msgContent, "I received your message",
		"assistant message should contain simulated response")

	t.Log("✅ Chat message flow validated (simulation mode)")
	t.Log("   • User message appears after form submit")
	t.Log("   • Assistant SSE shell created with streaming attributes")
	t.Log("   • SSE streaming completes and replaces shell with final message")
	t.Log("   • Final message contains expected test text")
}

func TestE2E_SessionSwitching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// Wait for initial redirect to complete
	err = page.WaitForURL("**/genui?session=**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "initial page should redirect to include session parameter")

	// Create multiple sessions via "New Chat" button
	for i := 0; i < 3; i++ {
		err = page.Click("button:has-text('New Chat')")
		require.NoError(t, err, "failed to click New Chat button")

		err = page.WaitForURL("**/genui?session=**", playwright.PageWaitForURLOptions{
			Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
		})
		require.NoError(t, err, "failed to navigate to new session")
	}

	// Click on an older session in sidebar
	firstSession := page.Locator("#session-list a").First()
	sessionHref, err := firstSession.GetAttribute("href")
	require.NoError(t, err, "failed to get session href")
	require.NotEmpty(t, sessionHref, "session link should have href attribute")

	err = firstSession.Click()
	require.NoError(t, err, "failed to click session link")

	// Verify:
	// 1. URL updated (query parameter)
	err = page.WaitForURL("**"+sessionHref, playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "URL should update to selected session")

	// 2. Page reloaded (full page, not partial)
	// Check that sidebar is still present (not nested)
	sidebar := page.Locator("#sidebar")
	isVisible, err := sidebar.IsVisible()
	require.NoError(t, err, "failed to check sidebar visibility")
	assert.True(t, isVisible, "sidebar should be visible (not nested)")

	// 3. No duplicate chat containers (regression test for nesting bug)
	chatContainers := page.Locator("#message-list")
	count, err := chatContainers.Count()
	require.NoError(t, err, "failed to count message-list elements")
	assert.Equal(t, 1, count, "should have exactly ONE message-list (no nesting)")

	t.Log("✅ Session switching works without UI nesting")
}

func TestE2E_CSSLoaded(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// Verify Tailwind CSS utility classes applied
	sidebar := page.Locator("#sidebar")

	// Check computed background color (from bg-white / dark:bg-surface-900)
	bgColor, err := sidebar.Evaluate("el => window.getComputedStyle(el).backgroundColor", nil)
	require.NoError(t, err, "failed to get computed background color")
	assert.NotEqual(t, "rgba(0, 0, 0, 0)", bgColor,
		"sidebar should have background color (CSS loaded)")

	// Check specific Tailwind class presence in DOM
	hasClass, err := page.Evaluate(`
		() => {
			const sidebar = document.getElementById('sidebar');
			return sidebar.classList.contains('border-r');
		}
	`)
	require.NoError(t, err, "failed to check for border-r class")
	hasClassBool, ok := hasClass.(bool)
	require.True(t, ok, "expected bool, got %T", hasClass)
	assert.True(t, hasClassBool, "sidebar should have border-r class")

	// Verify CSS file loaded
	cssLoaded, err := page.Evaluate(`
		() => {
			const link = document.querySelector('link[href*="output.css"]');
			return link !== null;
		}
	`)
	require.NoError(t, err, "failed to check for output.css link")
	cssLoadedBool, ok := cssLoaded.(bool)
	require.True(t, ok, "expected bool, got %T", cssLoaded)
	assert.True(t, cssLoadedBool, "output.css should be loaded")

	t.Log("✅ CSS build pipeline validated")
}

func TestE2E_JavaScriptLoaded(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// Verify HTMX JavaScript loaded
	htmxLoaded, err := page.Evaluate(`() => typeof htmx !== 'undefined'`)
	require.NoError(t, err, "failed to check HTMX presence")
	htmxLoadedBool, ok := htmxLoaded.(bool)
	require.True(t, ok, "expected bool, got %T", htmxLoaded)
	assert.True(t, htmxLoadedBool, "HTMX should be loaded")

	// Verify Alpine.js loaded (defer script may need time to initialize)
	// Wait for Alpine to be available on window object
	alpineLoaded, err := page.Evaluate(`
		async () => {
			// Alpine.js uses defer, wait for it to be available
			for (let i = 0; i < 50; i++) {
				if (typeof Alpine !== 'undefined') return true;
				await new Promise(resolve => setTimeout(resolve, 100));
			}
			return false;
		}
	`)
	require.NoError(t, err, "failed to check Alpine.js presence")
	alpineLoadedBool, ok := alpineLoaded.(bool)
	require.True(t, ok, "expected bool, got %T", alpineLoaded)
	assert.True(t, alpineLoadedBool, "Alpine.js should be loaded")

	// Verify HTMX SSE extension loaded
	// The SSE extension adds htmx.createEventSource function when loaded
	// (see htmx-sse.js line 25-27)
	sseExtLoaded, err := page.Evaluate(`
		() => {
			return typeof htmx !== 'undefined' &&
			       typeof htmx.createEventSource === 'function';
		}
	`)
	require.NoError(t, err, "failed to check HTMX SSE extension")
	sseExtLoadedBool, ok := sseExtLoaded.(bool)
	require.True(t, ok, "expected bool, got %T", sseExtLoaded)
	assert.True(t, sseExtLoadedBool, "HTMX SSE extension should be loaded")

	t.Log("✅ JavaScript dependencies verified")
}

func TestE2E_SessionPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// Wait for redirect to complete (page should auto-redirect to include session)
	err = page.WaitForURL("**/genui?session=**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "page should redirect to include session parameter")

	// Verify URL contains session parameter (should auto-redirect)
	currentURL := page.URL()
	require.Contains(t, currentURL, "session=", "URL should contain session parameter after initial load")

	// Extract session ID from URL
	// URL format: http://host/genui?session=UUID
	sessionParam := ""
	if idx := strings.Index(currentURL, "session="); idx != -1 {
		sessionParam = currentURL[idx+8:] // "session=" is 8 chars
		if endIdx := strings.Index(sessionParam, "&"); endIdx != -1 {
			sessionParam = sessionParam[:endIdx]
		}
	}
	require.NotEmpty(t, sessionParam, "should extract session ID from URL")

	// Hard reload (simulates browser refresh)
	_, err = page.Reload(playwright.PageReloadOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	require.NoError(t, err, "failed to reload page")

	// Verify session ID persists in URL after reload
	reloadedURL := page.URL()
	assert.Contains(t, reloadedURL, "session="+sessionParam,
		"session ID should persist in URL across reload")

	// Verify page still renders correctly (sidebar + chat input)
	sidebar := page.Locator("#sidebar")
	err = sidebar.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "sidebar should be visible after reload")

	chatInput := page.Locator("input[name='content']")
	err = chatInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(float64(pageLoadTimeout.Milliseconds())),
	})
	require.NoError(t, err, "chat input should be visible after reload")

	t.Log("✅ Session URL persistence validated (hypermedia principle)")
}

func TestE2E_AccessibilityCompliance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// Inject axe-core accessibility testing library from embedded file
	// Using local bundle instead of CDN to avoid CSP violations and enable offline testing
	_, err = page.Evaluate(e2e.AxeCoreJS)
	require.NoError(t, err, "failed to inject axe-core library")

	// Run accessibility scan
	axeResults, err := page.Evaluate(`
		async () => {
			const results = await axe.run();
			return {
				violations: results.violations.map(v => ({
					id: v.id,
					impact: v.impact,
					description: v.description,
					nodes: v.nodes.length,
					targets: v.nodes.map(n => ({
						target: n.target.join(' '),
						html: n.html,
						failureSummary: n.failureSummary
					}))
				}))
			};
		}
	`)
	require.NoError(t, err, "failed to run axe accessibility scan")

	// Convert to map for inspection
	resultsMap, ok := axeResults.(map[string]interface{})
	require.True(t, ok, "expected map, got %T", axeResults)

	violations, ok := resultsMap["violations"].([]interface{})
	require.True(t, ok, "expected violations array, got %T", resultsMap["violations"])

	// Filter to critical and serious violations only
	var criticalViolations []interface{}
	for _, v := range violations {
		vMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		impact, ok := vMap["impact"].(string)
		if !ok {
			continue
		}
		if impact == "critical" || impact == "serious" {
			criticalViolations = append(criticalViolations, v)
		}
	}

	// Log violations for debugging
	if len(criticalViolations) > 0 {
		t.Logf("Found %d critical/serious accessibility violations:", len(criticalViolations))
		for i, v := range criticalViolations {
			vMap := v.(map[string]interface{})
			t.Logf("  %d. [%s] %s (affects %v elements)",
				i+1, vMap["impact"], vMap["description"], vMap["nodes"])

			// Log detailed target information
			if targets, ok := vMap["targets"].([]interface{}); ok {
				for j, target := range targets {
					if tMap, ok := target.(map[string]interface{}); ok {
						t.Logf("     Element %d: %s", j+1, tMap["target"])
						if html, ok := tMap["html"].(string); ok && len(html) < 200 {
							t.Logf("     HTML: %s", html)
						}
					}
				}
			}
		}
	}

	// Assert no critical/serious violations
	assert.Empty(t, criticalViolations,
		"Page should have no critical or serious accessibility violations")

	t.Log("✅ Accessibility compliance validated")
}

func TestE2E_NetworkErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	t.Skip("Requires (UI Component Library - Toast notifications) - not yet implemented")

}
