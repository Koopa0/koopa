//go:build e2e

package web_test

import (
	"strings"
	"testing"
	"time"

	"github.com/koopa0/koopa/internal/web"
	"github.com/koopa0/koopa/internal/web/e2e"
	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// UI COMPONENT TESTS
// =============================================================================
// These tests verify individual UI components render and behave correctly.

// TestE2E_Component_SettingsModal verifies the Settings Modal functionality.
func TestE2E_Component_SettingsModal(t *testing.T) {
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

	// Wait for Elements to load
	_, err = page.WaitForFunction("() => !!customElements.get('el-dialog')", playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(10000),
	})
	require.NoError(t, err, "Elements should load")

	t.Run("OpenModal", func(t *testing.T) {
		// Open user menu
		userMenuBtn := page.Locator("button[aria-label='User menu']")
		err = userMenuBtn.WaitFor(playwright.LocatorWaitForOptions{
			State:   playwright.WaitForSelectorStateVisible,
			Timeout: playwright.Float(e2e.TimeoutMillis(e2e.InteractionTimeout)),
		})
		require.NoError(t, err)

		err = userMenuBtn.Click()
		require.NoError(t, err)

		time.Sleep(300 * time.Millisecond)

		// Click settings button
		settingsBtn := page.Locator("button[commandfor='settings']").First()
		err = settingsBtn.Click()
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		// Verify modal is visible
		modal := page.Locator("dialog#settings[open]")
		err = modal.WaitFor(playwright.LocatorWaitForOptions{
			State:   playwright.WaitForSelectorStateVisible,
			Timeout: playwright.Float(e2e.TimeoutMillis(e2e.InteractionTimeout)),
		})
		require.NoError(t, err, "Settings modal should open")

		// Verify theme buttons exist
		lightBtn := page.Locator("button:has-text('Light')")
		visible, _ := lightBtn.IsVisible()
		assert.True(t, visible, "Light theme button should be visible")

		darkBtn := page.Locator("button:has-text('Dark')")
		visible, _ = darkBtn.IsVisible()
		assert.True(t, visible, "Dark theme button should be visible")
	})

	t.Run("CloseModal", func(t *testing.T) {
		cancelBtn := page.Locator("dialog#settings button:has-text('Cancel')")
		err = cancelBtn.Click()
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		modal := page.Locator("dialog#settings[open]")
		count, _ := modal.Count()
		assert.Equal(t, 0, count, "Modal should be closed")
	})
}

// TestE2E_Component_UserMenu verifies the User Menu dropdown.
func TestE2E_Component_UserMenu(t *testing.T) {
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

	t.Run("MenuButtonVisible", func(t *testing.T) {
		userMenuBtn := page.Locator("button[aria-label='User menu']")
		err = userMenuBtn.WaitFor(playwright.LocatorWaitForOptions{
			State:   playwright.WaitForSelectorStateVisible,
			Timeout: playwright.Float(e2e.TimeoutMillis(e2e.InteractionTimeout)),
		})
		require.NoError(t, err, "User menu button should be visible")

		avatar := userMenuBtn.Locator("div.rounded-full")
		visible, _ := avatar.IsVisible()
		assert.True(t, visible, "User avatar should be visible")
	})

	t.Run("OpenMenu", func(t *testing.T) {
		userMenuBtn := page.Locator("button[aria-label='User menu']")
		err = userMenuBtn.Click()
		require.NoError(t, err)

		time.Sleep(300 * time.Millisecond)

		// Verify menu items
		settingsItem := page.Locator("button:has-text('Settings')")
		visible, _ := settingsItem.IsVisible()
		assert.True(t, visible, "Settings menu item should be visible")

		helpItem := page.Locator("button:has-text('Help')")
		visible, _ = helpItem.IsVisible()
		assert.True(t, visible, "Help menu item should be visible")

		logoutItem := page.Locator("button:has-text('Logout')")
		visible, _ = logoutItem.IsVisible()
		assert.True(t, visible, "Logout menu item should be visible")
	})

	t.Run("CloseByClickingOutside", func(t *testing.T) {
		err = page.Click("body", playwright.PageClickOptions{
			Position: &playwright.Position{X: 10, Y: 10},
		})
		require.NoError(t, err)

		time.Sleep(300 * time.Millisecond)

		menu := page.Locator("el-menu[popover]:popover-open")
		count, _ := menu.Count()
		assert.Equal(t, 0, count, "Menu should be closed after clicking outside")
	})
}

// TestE2E_Component_CommandPalette verifies the Command Palette (Cmd+K).
func TestE2E_Component_CommandPalette(t *testing.T) {
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

	// Wait for Elements
	_, err = page.WaitForFunction("() => !!customElements.get('el-command-palette')", playwright.PageWaitForFunctionOptions{
		Timeout: playwright.Float(10000),
	})
	require.NoError(t, err)

	t.Run("OpenViaCmdK", func(t *testing.T) {
		err = page.Keyboard().Press("Meta+K")
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		palette := page.Locator("dialog#command-palette[open]")
		err = palette.WaitFor(playwright.LocatorWaitForOptions{
			State:   playwright.WaitForSelectorStateVisible,
			Timeout: playwright.Float(e2e.TimeoutMillis(e2e.InteractionTimeout)),
		})
		require.NoError(t, err, "Command palette should open with Cmd+K")

		searchInput := palette.Locator("input[type='text']")
		visible, _ := searchInput.IsVisible()
		assert.True(t, visible, "Search input should be visible")
	})

	t.Run("ShowDefaultCommands", func(t *testing.T) {
		openSettings := page.Locator("button:has-text('Open Settings')")
		visible, _ := openSettings.IsVisible()
		assert.True(t, visible, "Open Settings command should be visible")

		newChat := page.Locator("button:has-text('New Chat')")
		visible, _ = newChat.IsVisible()
		assert.True(t, visible, "New Chat command should be visible")
	})

	t.Run("CloseViaEscape", func(t *testing.T) {
		err = page.Keyboard().Press("Escape")
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		palette := page.Locator("dialog#command-palette[open]")
		count, _ := palette.Count()
		assert.Equal(t, 0, count, "Command palette should be closed")
	})

	t.Run("OpenViaButton", func(t *testing.T) {
		searchBtn := page.Locator("button[commandfor='command-palette']")
		err = searchBtn.Click()
		require.NoError(t, err)

		time.Sleep(500 * time.Millisecond)

		palette := page.Locator("dialog#command-palette[open]")
		visible, _ := palette.IsVisible()
		assert.True(t, visible, "Command palette should open via button")

		// Close for cleanup
		_ = page.Keyboard().Press("Escape")
	})
}

// TestE2E_Component_Header verifies the header layout.
func TestE2E_Component_Header(t *testing.T) {
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

	t.Run("HeaderVisible", func(t *testing.T) {
		header := page.Locator("header")
		err = header.WaitFor(playwright.LocatorWaitForOptions{
			State:   playwright.WaitForSelectorStateVisible,
			Timeout: playwright.Float(e2e.TimeoutMillis(e2e.InteractionTimeout)),
		})
		require.NoError(t, err, "Header should be visible")
	})

	t.Run("LogoVisible", func(t *testing.T) {
		logo := page.Locator("h1:has-text('Koopa')")
		visible, _ := logo.IsVisible()
		assert.True(t, visible, "Koopa logo should be visible")
	})

	t.Run("SearchHintOnDesktop", func(t *testing.T) {
		err = page.SetViewportSize(1280, 720)
		require.NoError(t, err)

		time.Sleep(300 * time.Millisecond)

		searchHint := page.Locator("button:has-text('Search...')")
		visible, _ := searchHint.IsVisible()
		assert.True(t, visible, "Search hint should be visible on desktop")

		kbd := searchHint.Locator("kbd:has-text('⌘K')")
		visible, _ = kbd.IsVisible()
		assert.True(t, visible, "Cmd+K badge should be visible")
	})
}

// TestE2E_Component_NewChatButton verifies the New Chat button.
func TestE2E_Component_NewChatButton(t *testing.T) {
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

	// Find desktop New Chat button
	newChatBtn := page.Locator("#desktop-new-chat-button")
	err = newChatBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	require.NoError(t, err, "New Chat button should be visible")

	// Verify href
	href, err := newChatBtn.GetAttribute("href")
	require.NoError(t, err)
	assert.Equal(t, "/genui", href)

	// Verify class
	class, _ := newChatBtn.GetAttribute("class")
	assert.Contains(t, class, "new-chat-button")

	// Verify text
	text, _ := newChatBtn.TextContent()
	assert.Contains(t, strings.TrimSpace(text), "New Chat")
}

// TestE2E_Component_ModeToggle verifies the mode toggle.
func TestE2E_Component_ModeToggle(t *testing.T) {
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

	// Wait for mode toggle
	modeToggle := page.Locator("#mode-toggle")
	err = modeToggle.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(5000),
	})
	require.NoError(t, err)

	// Verify chat button has hx-post
	chatBtn := page.Locator("#mode-toggle button[value='chat']")
	chatHxPost, err := chatBtn.GetAttribute("hx-post")
	require.NoError(t, err)
	assert.Contains(t, chatHxPost, "/genui/mode")
}

// TestE2E_Component_EmptyState verifies empty state logo and styling.
func TestE2E_Component_EmptyState(t *testing.T) {
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

	// Find empty state
	emptyState, err := page.QuerySelector("#empty-state")
	require.NoError(t, err)
	require.NotNil(t, emptyState, "Empty state should be visible on fresh page")

	// Check for logo with indigo styling
	logo, err := emptyState.QuerySelector(".bg-indigo-500\\/10")
	require.NoError(t, err)
	require.NotNil(t, logo, "Empty state should have logo with indigo background")

	// Check for "K" text
	logoText, _ := logo.TextContent()
	assert.Contains(t, logoText, "K")
}

// TestE2E_Component_MessageStyling verifies message bubble styling.
func TestE2E_Component_MessageStyling(t *testing.T) {
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

	// Send message to create bubbles
	err = page.Fill("#chat-input-textarea", "Test message styling")
	require.NoError(t, err)
	err = page.Click("#send-button")
	require.NoError(t, err)

	// Wait for user message
	userBubble, err := page.WaitForSelector(".group.flex.justify-end", playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(3000),
	})
	require.NoError(t, err)
	require.NotNil(t, userBubble)

	// Verify right alignment
	classAttr, _ := userBubble.GetAttribute("class")
	assert.Contains(t, classAttr, "justify-end", "User message should be right-aligned")

	// Verify padding on inner bubble
	innerBubble, _ := userBubble.QuerySelector("[class*='px-4'][class*='py-3']")
	assert.NotNil(t, innerBubble, "Message bubble should have px-4 py-3 padding")

	// Wait for AI message
	aiMessage, err := page.WaitForSelector(".group.flex:not(.justify-end)", playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(5000),
	})
	if err == nil && aiMessage != nil {
		// Check AI avatar
		avatar, _ := aiMessage.QuerySelector(".size-8.rounded-lg")
		assert.NotNil(t, avatar, "AI message should have avatar")
	}
}

// =============================================================================
// CSS / JAVASCRIPT LOADING TESTS
// =============================================================================

// TestE2E_Assets_CSSLoaded verifies Tailwind CSS loads correctly.
func TestE2E_Assets_CSSLoaded(t *testing.T) {
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

	// Check sidebar has background color
	sidebar := page.Locator("#sidebar")
	bgColor, err := sidebar.Evaluate("el => window.getComputedStyle(el).backgroundColor", nil)
	require.NoError(t, err)
	assert.NotEqual(t, "rgba(0, 0, 0, 0)", bgColor, "sidebar should have background color")

	// Verify CSS file loaded
	cssLoaded, err := page.Evaluate(`() => {
		const link = document.querySelector('link[href*="output.css"]');
		return link !== null;
	}`)
	require.NoError(t, err)
	assert.True(t, cssLoaded.(bool), "output.css should be loaded")
}

// TestE2E_Assets_JavaScriptLoaded verifies JavaScript dependencies load.
func TestE2E_Assets_JavaScriptLoaded(t *testing.T) {
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

	// Verify HTMX loaded
	htmxLoaded, err := page.Evaluate(`() => typeof htmx !== 'undefined'`)
	require.NoError(t, err)
	assert.True(t, htmxLoaded.(bool), "HTMX should be loaded")

	// Verify Elements loaded
	elementsLoaded, err := page.Evaluate(`
		async () => {
			for (let i = 0; i < 50; i++) {
				if (customElements.get('el-dialog')) return true;
				await new Promise(resolve => setTimeout(resolve, 100));
			}
			return false;
		}
	`)
	require.NoError(t, err)
	assert.True(t, elementsLoaded.(bool), "@tailwindplus/elements should be loaded")

	// Verify HTMX SSE extension
	sseExtLoaded, err := page.Evaluate(`() => {
		return typeof htmx !== 'undefined' &&
		       typeof htmx.createEventSource === 'function';
	}`)
	require.NoError(t, err)
	assert.True(t, sseExtLoaded.(bool), "HTMX SSE extension should be loaded")
}
