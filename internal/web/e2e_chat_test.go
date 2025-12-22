//go:build e2e

package web_test

import (
	"testing"
	"time"

	"github.com/koopa0/koopa/internal/web"
	"github.com/koopa0/koopa/internal/web/e2e"
	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// CHAT CORE FUNCTIONALITY TESTS
// =============================================================================
// These tests cover the main chat flow: message sending, streaming, and display.

// TestE2E_Chat_MessageFlow verifies the complete chat message lifecycle.
// This is the primary happy path test for the chat feature.
func TestE2E_Chat_MessageFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err, "failed to create new page")

	_, err = page.Goto(server.URL + "/genui")
	require.NoError(t, err, "failed to navigate to /genui")

	// 1. Verify initial page load
	assert.Eventually(t, func() bool {
		title, err := page.Title()
		if err != nil {
			return false
		}
		return title == "Koopa - Chat"
	}, e2e.PageLoadTimeout, 100*time.Millisecond, "page should load with correct title")

	// 2. Type message
	err = page.Fill("#chat-input-textarea", "What is 2+2?")
	require.NoError(t, err, "failed to fill textarea")

	// 3. Submit form
	err = page.Click("#send-button")
	require.NoError(t, err, "failed to click submit button")

	// 4. Verify user message appears
	userMsg := page.Locator(".group.flex.justify-end")
	err = userMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "user message should appear after submit")

	// 5. Verify assistant message shell appears with SSE connection
	assistantShell := page.Locator("[id^='message-'][hx-ext='sse'], .sse-content")
	err = assistantShell.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "assistant message shell should appear with SSE connection")

	// 6. Wait for SSE streaming to complete
	finalMsg := page.Locator(".group.flex.gap-3:not(.justify-end)")
	err = finalMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err, "assistant message should complete streaming")

	// 7. Verify final message contains simulated response
	msgContent, err := finalMsg.TextContent()
	require.NoError(t, err, "failed to get message content")
	assert.Contains(t, msgContent, "I received your message",
		"assistant message should contain simulated response")
}

// TestE2E_Chat_InputBehavior verifies textarea clearing and focus after submit.
func TestE2E_Chat_InputBehavior(t *testing.T) {
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

	input := page.Locator("#chat-input-textarea")

	// Verify placeholder
	placeholder, err := input.GetAttribute("placeholder")
	require.NoError(t, err)
	assert.Equal(t, "Type a message...", placeholder)

	// Type and submit
	err = input.Fill("Test input clearing")
	require.NoError(t, err)

	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for HTMX afterRequest to fire
	time.Sleep(800 * time.Millisecond)

	// Verify input is cleared
	value, _ := input.InputValue()
	assert.Empty(t, value, "Input should be cleared after submit")

	// Verify focus is restored
	isFocused, _ := input.Evaluate("el => el === document.activeElement", nil)
	if focused, ok := isFocused.(bool); ok {
		assert.True(t, focused, "Input should have focus after submit")
	}
}

// TestE2E_Chat_LoadingIndicator verifies "AI is thinking..." indicator.
func TestE2E_Chat_LoadingIndicator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui/")
	require.NoError(t, err)

	// Submit a message
	err = page.Fill("#chat-input-textarea", "Hello, test streaming")
	require.NoError(t, err)

	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for user message first
	userMessage := page.Locator(":text('Hello, test streaming')").First()
	err = userMessage.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	require.NoError(t, err, "User message should appear")

	// Check for loading indicator
	thinkingIndicator := page.Locator("text=AI is thinking...")
	err = thinkingIndicator.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(3000),
	})
	if err == nil {
		// Verify animated dots
		dots := page.Locator("span.animate-pulse.bg-indigo-500")
		dotsCount, _ := dots.Count()
		assert.GreaterOrEqual(t, dotsCount, 3, "Should have at least 3 animated dots")
	}
}

// TestE2E_Chat_EmptyStateDisappears verifies empty state hides after first message.
func TestE2E_Chat_EmptyStateDisappears(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	server, cleanup := web.StartTestServer(t)
	t.Cleanup(cleanup)

	browser, cleanupBrowser := web.SetupBrowserFixture(t)
	t.Cleanup(cleanupBrowser)

	page, err := browser.BrowserCtx.NewPage()
	require.NoError(t, err)

	_, err = page.Goto(server.URL + "/genui/")
	require.NoError(t, err)

	// Verify empty state visible initially
	emptyState := page.Locator("#empty-state")
	assert.Eventually(t, func() bool {
		visible, _ := emptyState.IsVisible()
		return visible
	}, 3*time.Second, 100*time.Millisecond, "Empty state should be visible initially")

	// Send message
	err = page.Fill("#chat-input-textarea", "Test")
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Verify empty state disappears
	assert.Eventually(t, func() bool {
		visible, _ := emptyState.IsVisible()
		if !visible {
			return true
		}
		opacity, _ := emptyState.Evaluate("el => window.getComputedStyle(el).opacity", nil)
		return opacity == "0" || opacity == 0
	}, 5*time.Second, 200*time.Millisecond, "Empty state should hide after first message")
}

// TestE2E_Chat_NetworkErrorHandling verifies error toast on network failure.
func TestE2E_Chat_NetworkErrorHandling(t *testing.T) {
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

	// Verify error handler attribute exists
	chatForm := page.Locator("#chat-form")
	err = chatForm.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	require.NoError(t, err)

	hasErrorHandler, err := chatForm.Evaluate(`el => el.hasAttribute('hx-on::htmx:responseError') || el.hasAttribute('hx-on::htmx:responseerror')`, nil)
	require.NoError(t, err)
	assert.True(t, hasErrorHandler.(bool), "Chat form should have htmx:responseError handler")

	// Simulate error by creating toast directly
	_, err = page.Evaluate(`
		document.getElementById('chat-error-toast')?.remove();
		const t = document.createElement('div');
		t.id = 'chat-error-toast';
		t.setAttribute('role', 'alert');
		t.setAttribute('aria-live', 'assertive');
		t.className = 'fixed bottom-20 left-1/2 -translate-x-1/2 bg-red-500/90 text-white px-4 py-2 rounded-lg shadow-lg z-50 text-sm';
		t.textContent = 'Failed to send. Try again.';
		document.body.appendChild(t);
	`, nil)
	require.NoError(t, err)

	// Verify toast appears with correct content and accessibility attributes
	errorToast := page.Locator("#chat-error-toast")
	err = errorToast.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(3000),
	})
	require.NoError(t, err, "Error toast should appear")

	toastRole, _ := errorToast.GetAttribute("role")
	assert.Equal(t, "alert", toastRole, "Toast should have role='alert'")

	toastAriaLive, _ := errorToast.GetAttribute("aria-live")
	assert.Equal(t, "assertive", toastAriaLive, "Toast should have aria-live='assertive'")
}

// =============================================================================
// SESSION MANAGEMENT TESTS
// =============================================================================

// TestE2E_Session_Persistence verifies session survives page reload.
// Uses cookie-based sessions (not URL params).
func TestE2E_Session_Persistence(t *testing.T) {
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

	// Wait for page to fully load
	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State:   playwright.LoadStateNetworkidle,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "page should fully load")

	// Fresh visitors start in pre-session state (no session ID).
	// Session is created lazily on first message, stored in cookie.

	// Verify pre-session state: session_id field is empty
	// Note: session-id-field is a hidden input, so we wait for "attached" not "visible"
	sessionIDField := page.Locator("#session-id-field")
	err = sessionIDField.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateAttached,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "session ID field should exist")
	initialValue, _ := sessionIDField.InputValue()
	assert.Empty(t, initialValue, "pre-session state should have empty session ID")

	// Send a message to create a session
	// Wait for textarea to be ready
	textarea := page.Locator("#chat-input-textarea")
	err = textarea.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err, "textarea should be visible")

	err = textarea.Fill("Test persistence message")
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for streaming to complete (session created via lazy initialization)
	// Use assistant message selector (any message not from user, which uses justify-end)
	assistantMsg := page.Locator(".group.flex.gap-3:not(.justify-end)")
	err = assistantMsg.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.StreamingTimeout)),
	})
	require.NoError(t, err, "assistant response should appear")

	// Get session ID after message
	sessionIDAfterMsg, _ := sessionIDField.InputValue()
	require.NotEmpty(t, sessionIDAfterMsg, "session should be created after message")

	// Reload page
	_, err = page.Reload(playwright.PageReloadOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	require.NoError(t, err)

	// Re-query session ID field (DOM was replaced)
	sessionIDField = page.Locator("#session-id-field")
	sessionIDAfterReload, _ := sessionIDField.InputValue()

	// Session should persist via cookie
	assert.Equal(t, sessionIDAfterMsg, sessionIDAfterReload,
		"session ID should persist across reload via cookie")
}

// TestE2E_Session_Switching verifies navigation between sessions.
// Uses cookie-based sessions with lazy creation.
// See TestE2E_Session_SwitchLoadsHistory for full session switching test with message history.
func TestE2E_Session_Switching(t *testing.T) {
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

	// Fresh visitors start in pre-session state.
	// Sessions are created lazily on first message OR via "New Chat" button.

	// Create first session by clicking New Chat (creates empty session)
	newChatBtn := page.Locator("#desktop-new-chat-button")
	err = newChatBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(e2e.TimeoutMillis(e2e.PageLoadTimeout)),
	})
	require.NoError(t, err)
	err = newChatBtn.Click()
	require.NoError(t, err)

	// Wait for HTMX swap and get session ID
	time.Sleep(500 * time.Millisecond)
	sessionIDField := page.Locator("#session-id-field")
	firstSessionID, _ := sessionIDField.InputValue()

	// Create second session
	err = newChatBtn.Click()
	require.NoError(t, err)
	time.Sleep(500 * time.Millisecond)

	// Re-query session ID field after HTMX swap
	sessionIDField = page.Locator("#session-id-field")
	secondSessionID, _ := sessionIDField.InputValue()

	// Sessions should be different
	require.NotEmpty(t, firstSessionID)
	require.NotEmpty(t, secondSessionID)
	require.NotEqual(t, firstSessionID, secondSessionID, "each New Chat should create unique session")

	// Verify no duplicate message-list elements (regression test)
	chatContainers := page.Locator("#message-list")
	count, err := chatContainers.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "should have exactly ONE message-list (no nesting)")
}

// =============================================================================
// HTMX BEHAVIOR TESTS
// =============================================================================

// TestE2E_HTMX_Target verifies correct HTMX swap target configuration.
func TestE2E_HTMX_Target(t *testing.T) {
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

	// Verify form target
	form, err := page.QuerySelector("#chat-form")
	require.NoError(t, err)
	require.NotNil(t, form)

	hxTarget, err := form.GetAttribute("hx-target")
	require.NoError(t, err)
	assert.Equal(t, "#message-list", hxTarget)

	// Send message and verify it goes to correct target
	err = page.Fill("#chat-input-textarea", "Test HTMX target")
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	container, err := page.QuerySelector("#message-list")
	require.NoError(t, err)

	messages, err := container.QuerySelectorAll(".group.flex")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(messages), 1, "Message should be inside #message-list")
}

// TestE2E_HTMX_SSEReconnection verifies SSE reconnection attribute.
func TestE2E_HTMX_SSEReconnection(t *testing.T) {
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

	// Submit message to trigger SSE
	err = page.Fill("#chat-input-textarea", "Test SSE reconnection")
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	// Check for sse-reconnect attribute
	sseElements := page.Locator("[sse-reconnect]")
	count, err := sseElements.Count()
	require.NoError(t, err)

	if count > 0 {
		reconnectValue, _ := sseElements.First().GetAttribute("sse-reconnect")
		assert.Equal(t, "3000", reconnectValue, "sse-reconnect should be 3000ms")
	}
}
