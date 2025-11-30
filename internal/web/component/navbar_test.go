package component

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNavbar_RenderCorrectly verifies basic Navbar rendering with valid props.
func TestNavbar_RenderCorrectly(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:    "Koopa",
		ActivePath: "/genui/settings",
		CSRFToken:  "test-token",
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "Koopa")
	assert.Contains(t, html, `aria-current="page"`)          // Settings link active
	assert.Contains(t, html, `action="/genui/logout"`)       // Progressive enhancement form
	assert.Contains(t, html, `min-h-[44px]`)                 // Touch target size
	assert.Contains(t, html, `aria-label="Main navigation"`) // ARIA label
}

// TestNavbar_ChatActive verifies navbar with Chat as active page.
func TestNavbar_ChatActive(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:    "Koopa",
		ActivePath: "/genui",
		CSRFToken:  "test-token",
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `aria-current="page"`) // Chat link should be active
	assert.Contains(t, html, "Chat")
}

// TestNavbar_EmptyCSRFToken verifies rendering with empty CSRF token.
//
// Zero value behavior: CSRFToken == "" is INVALID for logout, but component
// should still render without error.
func TestNavbar_EmptyCSRFToken(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:   "Koopa",
		CSRFToken: "", // Invalid state
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err, "Should render without error even with empty CSRF")

	html := buf.String()
	assert.Contains(t, html, `name="csrf_token" value=""`) // Empty value rendered
}

// TestNavbar_ZeroValueProps verifies rendering with all zero values.
func TestNavbar_ZeroValueProps(t *testing.T) {
	t.Parallel()
	props := NavbarProps{} // All zero values

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err, "Should handle zero values gracefully")

	html := buf.String()
	// Should render basic structure even with empty props
	assert.Contains(t, html, `<nav`)
	assert.Contains(t, html, `aria-label="Main navigation"`)
}

// TestNavbar_EmptyAppName verifies navbar with empty app name.
func TestNavbar_EmptyAppName(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:   "", // Empty app name
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	// Should render structure without crashing
	assert.Contains(t, html, `<nav`)
}

// TestNavbar_NoActiveLink verifies navbar with no active link highlighted.
func TestNavbar_NoActiveLink(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:    "Koopa",
		ActivePath: "", // No active link
		CSRFToken:  "test-token",
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	// No aria-current should be present
	assert.NotContains(t, html, `aria-current="page"`)
}

// TestNavbar_DarkModeClasses verifies dark mode Tailwind classes are present.
func TestNavbar_DarkModeClasses(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:   "Koopa",
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "dark:bg-surface-900")
	assert.Contains(t, html, "dark:border-gray-700")
}

// TestNavbar_HTMXAttributes verifies HTMX attributes are correctly rendered.
func TestNavbar_HTMXAttributes(t *testing.T) {
	t.Parallel()
	props := NavbarProps{
		AppName:   "Koopa",
		CSRFToken: "test-token",
	}

	var buf bytes.Buffer
	err := Navbar(props).Render(context.Background(), &buf)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, `hx-post="/genui/logout"`)
	assert.Contains(t, html, `hx-confirm="Are you sure you want to logout?"`)
}
