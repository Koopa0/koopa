package component

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTabs_KeyboardNavigation verifies tabs with keyboard navigation.
func TestTabs_KeyboardNavigation(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
		{ID: "security", Label: "Security"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "security",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `aria-selected="true"`) // Security tab active
	assert.Contains(t, html, `@keydown.arrow-left`)  // Arrow key support
	assert.Contains(t, html, `@keydown.arrow-right`)
	assert.Contains(t, html, `@keydown.home`)
	assert.Contains(t, html, `@keydown.end`)
	assert.Contains(t, html, `text-sm font-medium`) // Explicit font size
}

// TestTabs_ARIAAttributes verifies complete ARIA tablist implementation.
func TestTabs_ARIAAttributes(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
		{ID: "security", Label: "Security"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `role="tablist"`)
	assert.Contains(t, html, `aria-label="Settings tabs"`)
	assert.Contains(t, html, `role="tab"`)
	assert.Contains(t, html, `aria-controls="general-panel"`)
	assert.Contains(t, html, `aria-controls="security-panel"`)
}

// TestTabs_HTMXAttributes verifies HTMX integration.
func TestTabs_HTMXAttributes(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `hx-get="/genui/settings/general"`)
	assert.Contains(t, html, `hx-target="#settings-content"`)
	assert.Contains(t, html, `hx-swap="innerHTML"`)
	assert.Contains(t, html, `hx-push-url="/genui/settings?tab=general"`)
}

// TestTabs_ActiveTabStyling verifies active tab visual styling.
func TestTabs_ActiveTabStyling(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
		{ID: "security", Label: "Security"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "border-primary-600") // Active tab border
	assert.Contains(t, html, "text-primary-600")   // Active tab text
	assert.Contains(t, html, "border-transparent") // Inactive tab border
}

// TestTabs_WithIcons verifies tab rendering with icons.
func TestTabs_WithIcons(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General", Icon: "<svg>icon</svg>"},
		{ID: "security", Label: "Security", Icon: ""},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "&lt;svg&gt;icon&lt;/svg&gt;") // Icon escaped (templ auto-escaping)
	assert.Contains(t, html, "General")
	assert.Contains(t, html, "Security")
}

// TestTabs_NoActiveTab verifies rendering with no active tab.
func TestTabs_NoActiveTab(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
		{ID: "security", Label: "Security"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "", // No active tab
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	// Should render without error
	assert.Contains(t, html, "General")
	assert.Contains(t, html, "Security")
}

// TestTabs_SingleTab verifies rendering with single tab.
func TestTabs_SingleTab(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "General")
	assert.Contains(t, html, `aria-selected="true"`)
}

// TestTabs_TouchTargets verifies 44px minimum touch target size.
func TestTabs_TouchTargets(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `min-h-[44px]`) // WCAG 2.1 AA touch target
}

// TestTabs_ResponsiveOverflow verifies horizontal scroll for overflow.
func TestTabs_ResponsiveOverflow(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
		{ID: "security", Label: "Security"},
		{ID: "appearance", Label: "Appearance"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "overflow-x-auto") // Horizontal scroll
	assert.Contains(t, html, "scrollbar-thin")
}

// TestTabs_AlpineJSHelper verifies Alpine.js helper usage.
func TestTabs_AlpineJSHelper(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `x-data="tabsNav()"`) // Alpine.js helper from base.templ
}

// TestTabs_FocusVisibleRings verifies keyboard focus styling.
func TestTabs_FocusVisibleRings(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "focus-visible:outline-none")
	assert.Contains(t, html, "focus-visible:ring-2")
	assert.Contains(t, html, "focus-visible:ring-primary-500")
}

// TestTabs_DarkModeClasses verifies dark mode Tailwind classes.
func TestTabs_DarkModeClasses(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "general",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "dark:border-gray-700")
	assert.Contains(t, html, "dark:text-primary-400")
}

// TestTabs_ThreeTabs verifies the default settings page tabs.
func TestTabs_ThreeTabs(t *testing.T) {
	t.Parallel()
	tabs := []TabItem{
		{ID: "general", Label: "General"},
		{ID: "security", Label: "Security"},
		{ID: "appearance", Label: "Appearance"},
	}

	props := TabsProps{
		Tabs:     tabs,
		ActiveID: "security",
	}

	var buf bytes.Buffer
	err := Tabs(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "General")
	assert.Contains(t, html, "Security")
	assert.Contains(t, html, "Appearance")
	// Only security should be active
	assert.Contains(t, html, `aria-selected="true"`)
}
