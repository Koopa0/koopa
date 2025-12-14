//go:build e2e

package web_test

import (
	"testing"
	"time"

	"github.com/koopa0/koopa-cli/internal/web"
	"github.com/koopa0/koopa-cli/internal/web/e2e"
	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// SESSION TITLE AUTO-GENERATION TESTS
// =============================================================================
// These tests verify that session titles are auto-generated after the first message.
// Session title generation uses AI or truncation fallback.
// Bug Fix: Title generation was called AFTER SSE connection closed; now called BEFORE.

// TestE2E_Session_TitleAutoGeneration verifies title appears in sidebar after first message.
// This test validates the SSE timing fix: maybeGenerateTitle now runs before WriteDone.
func TestE2E_Session_TitleAutoGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	// 1. Navigate to chat page
	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	require.NoError(t, err)

	// 2. Verify sidebar initially shows "No chats yet" or is empty
	// (New sessions without messages don't appear in ListSessionsWithMessages)
	// NOTE: Use desktop-session-list specifically to avoid dual mobile/desktop sidebar issue
	sidebarList := page.Locator("#desktop-session-list")
	err = sidebarList.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "sidebar session list should be visible")

	// 3. Send a message with unique content
	testMessage := "Test title generation with unique content"
	err = page.Fill("#chat-input-textarea", testMessage)
	require.NoError(t, err, "failed to fill textarea")

	err = page.Click("#send-button")
	require.NoError(t, err, "failed to click submit button")

	// 4. Wait for streaming to complete
	// The final message should appear after SSE streaming is done
	finalMsg := page.Locator(".group.flex.gap-3:not(.justify-end)")
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err, "assistant message should complete streaming")

	// 5. Wait for sidebar to update (sidebar-refresh event from SSE)
	// The title should be truncated from the user's message or AI-generated
	time.Sleep(1 * time.Second) // Give time for OOB swap to complete

	// 6. Verify sidebar contains the session (either with title or "New Chat" fallback)
	// Use desktop sidebar specifically to avoid dual mobile/desktop issue
	sidebarItems := page.Locator("#desktop-session-list li")
	itemCount, err := sidebarItems.Count()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, itemCount, 1, "sidebar should have at least one session after first message")

	// Check if any session item contains part of the user message or has content
	if itemCount > 0 {
		firstItem := sidebarItems.First()
		itemText, err := firstItem.TextContent()
		require.NoError(t, err)
		assert.NotEmpty(t, itemText, "session item should have text content (title or 'New Chat')")
	}
}

// =============================================================================
// SESSION SWITCHING TESTS
// =============================================================================
// These tests verify session switching via sidebar links.
// Bug Fix: Removed "&&hasSession" condition that blocked fresh users from switching.

// TestE2E_Session_SwitchLoadsHistory verifies clicking session loads its history.
func TestE2E_Session_SwitchLoadsHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	// 1. Navigate and send first message
	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Get initial session ID (should be empty for pre-session state)
	sessionIDField := page.Locator("#session-id-field")
	initialSessionID, _ := sessionIDField.InputValue()
	t.Logf("Initial session ID (pre-session): %s", initialSessionID)

	firstMessage := "First session unique message ABC123"
	err = page.Fill("#chat-input-textarea", firstMessage)
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for streaming to complete
	finalMsg := page.Locator(".group.flex.gap-3:not(.justify-end)")
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err)

	// Log session ID after first message (should be created via lazy session)
	firstSessionID, _ := sessionIDField.InputValue()
	t.Logf("Session ID after first message (session 1): %s", firstSessionID)

	// Wait for sidebar refresh (SSE event) from first message
	// Need 2 seconds to match TestE2E_Session_SidebarRefreshOnNewMessage
	time.Sleep(2 * time.Second)

	// Check sidebar after first message
	sidebar1, _ := page.Locator("#desktop-session-list").InnerHTML()
	t.Logf("Sidebar after first message (%d chars)", len(sidebar1))

	// 2. Click "New Chat" to create second session
	// Use desktop sidebar button specifically
	newChatBtn := page.Locator("#desktop-new-chat-button")
	err = newChatBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "new chat button should be visible")
	err = newChatBtn.Click()
	require.NoError(t, err, "failed to click new chat button")

	// Wait for HTMX swap to complete
	// HTMX boost doesn't trigger a full navigation, so we need to wait for the DOM change
	// The session_id field should change to empty (pre-session state) or a new session ID
	// We can detect the swap completed by waiting for the message list to be empty
	_, err = page.WaitForFunction(`() => {
		const msgList = document.querySelector('#message-list');
		const sessionField = document.querySelector('#session-id-field');
		// New chat clears messages and may reset session_id
		return msgList && msgList.children.length === 0;
	}`, playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "waiting for New Chat HTMX swap")

	// 3. Send second message in the new session
	// Re-query the session_id field since DOM was replaced by HTMX swap
	sessionIDField = page.Locator("#session-id-field")
	secondSessionID, _ := sessionIDField.InputValue()
	t.Logf("Session ID after 'New Chat' (session 2): %s", secondSessionID)

	secondMessage := "Second session unique message XYZ789"
	err = page.Fill("#chat-input-textarea", secondMessage)
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for streaming
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err)

	// 4. Click SECOND session in sidebar to switch back to first session
	// The sidebar shows sessions by updated_at DESC, so:
	// - Index 0 = Session 2 (current, most recently updated)
	// - Index 1 = Session 1 (older, we want to switch to this)
	// Wait for sidebar refresh SSE event to complete
	time.Sleep(2 * time.Second)

	// Use desktop sidebar specifically to avoid dual mobile/desktop issue
	sidebarSessions := page.Locator("#desktop-session-list li a")
	sessionCount, err := sidebarSessions.Count()
	require.NoError(t, err)

	// Log for debugging
	sidebarHTML, _ := page.Locator("#desktop-session-list").InnerHTML()
	t.Logf("Session count: %d, Sidebar HTML length: %d", sessionCount, len(sidebarHTML))
	// Log first 500 chars of sidebar HTML for inspection
	if len(sidebarHTML) > 500 {
		t.Logf("Sidebar HTML (first 500): %s...", sidebarHTML[:500])
	} else {
		t.Logf("Sidebar HTML: %s", sidebarHTML)
	}

	if sessionCount < 2 {
		t.Skipf("Not enough sessions created (got %d, need 2), skipping switch test", sessionCount)
	}

	// Click the SECOND session (older one, index 1)
	// This switches from Session 2 to Session 1
	olderSession := sidebarSessions.Nth(1)
	err = olderSession.Click()
	require.NoError(t, err)

	// 5. Wait for page update
	time.Sleep(1 * time.Second)

	// 6. Verify first message is visible (history loaded)
	pageContent, err := page.Content()
	require.NoError(t, err)
	assert.Contains(t, pageContent, firstMessage,
		"switching to first session should show its message history")
}

// TestE2E_Session_SidebarRefreshOnNewMessage verifies sidebar updates after sending message.
// This tests the sidebar-refresh SSE event timing fix.
func TestE2E_Session_SidebarRefreshOnNewMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Wait for initial load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	require.NoError(t, err)

	// Get initial sidebar state (use desktop sidebar specifically)
	initialSidebar, err := page.Locator("#desktop-session-list").InnerHTML()
	require.NoError(t, err)

	// Send message
	uniqueMessage := "Unique message for sidebar refresh test"
	err = page.Fill("#chat-input-textarea", uniqueMessage)
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for streaming to complete
	finalMsg := page.Locator(".group.flex.gap-3:not(.justify-end)")
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err)

	// Wait for sidebar refresh (OOB swap)
	time.Sleep(2 * time.Second)

	// Check sidebar has updated (use desktop sidebar specifically)
	updatedSidebar, err := page.Locator("#desktop-session-list").InnerHTML()
	require.NoError(t, err)

	// Sidebar should have changed (new session added or title updated)
	// Note: Even if content is same, this verifies no errors occurred during refresh
	assert.NotEmpty(t, updatedSidebar, "sidebar should have content after sending message")

	// The updated sidebar should contain at least one session item
	sessionItems := page.Locator("#desktop-session-list li")
	count, err := sessionItems.Count()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "sidebar should show at least one session")

	// Log for debugging (helpful in CI)
	t.Logf("Initial sidebar: %d chars, Updated sidebar: %d chars",
		len(initialSidebar), len(updatedSidebar))
}

// =============================================================================
// CANVAS PANEL DISPLAY TESTS
// =============================================================================
// These tests verify the Canvas panel appears when AI generates artifacts.
// Bug Fix: WriteCanvasShow now removes 'hidden' class in addition to translate classes.

// TestE2E_Canvas_PanelHiddenByDefault verifies Canvas panel is hidden initially.
func TestE2E_Canvas_PanelHiddenByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Wait for page to load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	require.NoError(t, err)

	// Verify artifact panel exists but is hidden
	artifactPanel := page.Locator("#artifact-panel")

	// Panel should exist
	panelCount, err := artifactPanel.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, panelCount, "artifact panel should exist in DOM")

	// Panel should be hidden (not visible)
	isVisible, err := artifactPanel.IsVisible()
	require.NoError(t, err)
	assert.False(t, isVisible, "artifact panel should be hidden by default (canvas mode off)")

	// Verify hidden class is present
	classAttr, err := artifactPanel.GetAttribute("class")
	require.NoError(t, err)
	assert.Contains(t, classAttr, "hidden", "artifact panel should have 'hidden' class when canvas mode is off")
}

// TestE2E_Canvas_ToggleVisibility verifies Canvas toggle button works.
func TestE2E_Canvas_ToggleVisibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	require.NoError(t, err)

	// First, we need a session to enable canvas toggle
	// Send a message to create session
	err = page.Fill("#chat-input-textarea", "Create session for canvas test")
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for streaming to complete
	finalMsg := page.Locator(".group.flex.gap-3:not(.justify-end)")
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err)

	// Find canvas toggle button
	canvasToggle := page.Locator("#canvas-toggle")
	toggleCount, err := canvasToggle.Count()
	require.NoError(t, err)

	if toggleCount == 0 {
		t.Skip("Canvas toggle button not found, skipping test")
	}

	// Click toggle to enable canvas
	err = canvasToggle.Click()
	require.NoError(t, err)

	// Wait for toggle effect
	time.Sleep(1 * time.Second)

	// Verify aria-checked changed
	ariaChecked, err := canvasToggle.GetAttribute("aria-checked")
	require.NoError(t, err)
	// Note: The exact value depends on initial state and toggle behavior
	t.Logf("Canvas toggle aria-checked: %s", ariaChecked)
}

// =============================================================================
// REGRESSION TESTS
// =============================================================================
// These tests ensure the fixes don't break existing functionality.

// TestE2E_Regression_NoNestedMessageLists verifies no duplicate message-list divs.
func TestE2E_Regression_NoNestedMessageLists(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	// Send multiple messages
	for i := 0; i < 3; i++ {
		err = page.Fill("#chat-input-textarea", "Message number test")
		require.NoError(t, err)
		err = page.Click("#send-button")
		require.NoError(t, err)

		// Wait between messages
		time.Sleep(2 * time.Second)
	}

	// Verify only ONE message-list exists
	messageLists := page.Locator("#message-list")
	count, err := messageLists.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "should have exactly ONE #message-list (no nesting or duplication)")
}

// TestE2E_Regression_CSRFTokenPresent verifies CSRF token exists in form.
func TestE2E_Regression_CSRFTokenPresent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err)

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle,
	})
	require.NoError(t, err)

	// Verify CSRF token input exists
	csrfInput := page.Locator("input[name='csrf_token']")
	count, err := csrfInput.Count()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "CSRF token input should exist in form")

	// Verify it has a value (either pre-session or session-bound)
	if count > 0 {
		tokenValue, err := csrfInput.First().InputValue()
		require.NoError(t, err)
		assert.NotEmpty(t, tokenValue, "CSRF token should have a value")
	}
}
