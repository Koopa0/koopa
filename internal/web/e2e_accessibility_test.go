//go:build e2e

package web_test

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

// =============================================================================
// ACCESSIBILITY & WCAG COMPLIANCE TESTS
// =============================================================================
// These tests verify accessibility requirements using axe-core and manual checks.

// TestE2E_Accessibility_AxeCoreCompliance runs axe-core accessibility audit.
func TestE2E_Accessibility_AxeCoreCompliance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Inject axe-core
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
	require.NoError(t, err, "failed to run axe scan")

	resultsMap, ok := axeResults.(map[string]interface{})
	require.True(t, ok)

	violations, ok := resultsMap["violations"].([]interface{})
	require.True(t, ok)

	// Filter critical and serious violations
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
		}
	}

	assert.Empty(t, criticalViolations,
		"Page should have no critical or serious accessibility violations")
}

// TestE2E_Accessibility_SidebarARIA verifies sidebar ARIA labels.
func TestE2E_Accessibility_SidebarARIA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	// Desktop viewport
	err = page.SetViewportSize(1400, 900)
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Verify desktop sidebar exists
	desktopSidebar := page.Locator("#desktop-sidebar")
	err = desktopSidebar.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	require.NoError(t, err, "Desktop sidebar should be visible")

	// Verify nav has aria-label
	nav := page.Locator("#desktop-sidebar nav[aria-label='Chat history']")
	navCount, _ := nav.Count()
	assert.GreaterOrEqual(t, navCount, 1, "sidebar nav should have aria-label='Chat history'")

	// Verify session list has aria-labelledby
	sessionList := page.Locator("#desktop-sidebar ul[aria-labelledby='desktop-chats-heading']")
	listCount, _ := sessionList.Count()
	assert.GreaterOrEqual(t, listCount, 1, "session list should have aria-labelledby")

	// Verify chats heading exists
	chatsHeading := page.Locator("#desktop-chats-heading")
	headingCount, _ := chatsHeading.Count()
	assert.Equal(t, 1, headingCount, "chats heading should exist")

	headingText, _ := chatsHeading.TextContent()
	assert.Equal(t, "Chats", headingText)
}

// TestE2E_Accessibility_NoDuplicateIDs verifies no duplicate IDs in DOM.
func TestE2E_Accessibility_NoDuplicateIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	err = page.SetViewportSize(1400, 900)
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Check for duplicate IDs
	result, err := page.Evaluate(`() => {
		const ids = Array.from(document.querySelectorAll('[id]')).map(el => el.id);
		const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
		return {
			totalIds: ids.length,
			duplicates: [...new Set(duplicates)]
		};
	}`, nil)
	require.NoError(t, err)

	resultMap := result.(map[string]interface{})
	duplicates := resultMap["duplicates"].([]interface{})

	assert.Empty(t, duplicates, "There should be no duplicate IDs. Found: %v", duplicates)
}

// TestE2E_Accessibility_ModeToggleARIA verifies mode toggle accessibility.
func TestE2E_Accessibility_ModeToggleARIA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL+"/genui", playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	require.NoError(t, err)

	// Find Chat button
	chatBtn := page.Locator("#mode-toggle button[value='chat']")
	err = chatBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	require.NoError(t, err)

	// Verify aria-pressed on Chat button
	ariaPressedChat, err := chatBtn.GetAttribute("aria-pressed")
	require.NoError(t, err)
	assert.Equal(t, "true", ariaPressedChat, "Chat button should be pressed by default")

	// Verify Canvas button not pressed
	canvasBtn := page.Locator("#mode-toggle button[value='canvas']")
	ariaPressedCanvas, _ := canvasBtn.GetAttribute("aria-pressed")
	assert.Equal(t, "false", ariaPressedCanvas, "Canvas button should not be pressed")
}

// =============================================================================
// PROGRESSIVE ENHANCEMENT TESTS
// =============================================================================
// These tests verify forms work without JavaScript (hypermedia principle).

// TestE2E_ProgressiveEnhancement_FormFallback verifies forms have action attributes.
func TestE2E_ProgressiveEnhancement_FormFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL+"/genui", playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	require.NoError(t, err)

	// Verify chat form has action
	chatForm := page.Locator("#chat-form")
	action, err := chatForm.GetAttribute("action")
	require.NoError(t, err)
	assert.Equal(t, "/genui/send", action, "Chat form should have action for non-JS fallback")

	method, err := chatForm.GetAttribute("method")
	require.NoError(t, err)
	assert.Equal(t, "POST", method)

	// Verify mode toggle form has action
	modeForm := page.Locator("#mode-toggle")
	modeAction, _ := modeForm.GetAttribute("action")
	assert.Equal(t, "/genui/mode", modeAction)

	modeMethod, _ := modeForm.GetAttribute("method")
	assert.Equal(t, "POST", modeMethod)
}

// TestE2E_ProgressiveEnhancement_CSRFToken verifies CSRF token presence.
func TestE2E_ProgressiveEnhancement_CSRFToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Verify CSRF token input exists
	csrfInput := page.Locator("input[name='csrf_token']")
	err = csrfInput.WaitFor(playwright.LocatorWaitForOptions{
		State: playwright.WaitForSelectorStateAttached,
	})
	require.NoError(t, err, "CSRF token should be present")

	tokenValue, err := csrfInput.GetAttribute("value")
	require.NoError(t, err)
	assert.NotEmpty(t, tokenValue, "CSRF token should have a value")
}

// TestE2E_ProgressiveEnhancement_HTMXEnhanced verifies HTMX prevents page reload.
func TestE2E_ProgressiveEnhancement_HTMXEnhanced(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Fill and submit
	err = page.Fill("#chat-input-textarea", "Hello")
	require.NoError(t, err)

	initialURL := page.URL()

	err = page.Click("#send-button")
	require.NoError(t, err)

	// URL should stay same (HTMX prevented reload)
	time.Sleep(500 * time.Millisecond)
	currentURL := page.URL()
	assert.True(t, strings.HasPrefix(currentURL, strings.TrimSuffix(initialURL, "?session=")),
		"HTMX should prevent full page reload")

	// User message should appear
	userMsg := page.Locator("text=Hello")
	err = userMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(3000),
	})
	require.NoError(t, err, "User message should appear without page reload")
}

// =============================================================================
// RESPONSIVE LAYOUT TESTS
// =============================================================================

// TestE2E_Responsive_MobileLayout verifies mobile viewport renders correctly.
func TestE2E_Responsive_MobileLayout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	// Mobile viewport
	err = page.SetViewportSize(375, 667)
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Verify input accessible on mobile
	inputVisible, err := page.Locator("#chat-input-textarea").IsVisible()
	require.NoError(t, err)
	assert.True(t, inputVisible, "Chat input should be visible on mobile")

	// Verify submit button accessible
	submitVisible, err := page.Locator("#send-button").IsVisible()
	require.NoError(t, err)
	assert.True(t, submitVisible, "Submit button should be visible on mobile")
}

// TestE2E_Responsive_DesktopLayout verifies desktop viewport renders correctly.
func TestE2E_Responsive_DesktopLayout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	// Desktop viewport
	err = page.SetViewportSize(1280, 720)
	require.NoError(t, err)

	_, err = page.Goto(server.URL+"/genui", playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	require.NoError(t, err)

	// Desktop should show sidebar
	sidebar, err := page.QuerySelector(".lg\\:fixed.lg\\:flex")
	require.NoError(t, err)
	assert.NotNil(t, sidebar, "Desktop should have fixed sidebar")

	// Message list should have correct spacing
	messageList, err := page.QuerySelector("#message-list")
	require.NoError(t, err)

	classAttr, err := messageList.GetAttribute("class")
	require.NoError(t, err)
	assert.Contains(t, classAttr, "space-y-6", "Message list should have space-y-6 spacing")
}
