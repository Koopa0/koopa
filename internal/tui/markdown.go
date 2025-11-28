package tui

import (
	"strings"

	"github.com/charmbracelet/glamour"
)

// markdownRenderer provides Markdown to styled terminal output conversion.
// Uses glamour with dark theme for consistent appearance.
// Caches the renderer and only recreates when width changes.
type markdownRenderer struct {
	renderer *glamour.TermRenderer
	width    int // Cached width to avoid unnecessary recreation
}

// newMarkdownRenderer creates a renderer with terminal-appropriate styling.
// Returns nil renderer if initialization fails (graceful degradation).
func newMarkdownRenderer(width int) *markdownRenderer {
	if width <= 0 {
		width = 80 // Default terminal width
	}

	r, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(), // Detect light/dark terminal
		glamour.WithWordWrap(width),
	)
	if err != nil {
		// Graceful degradation: return nil, caller will use plain text
		return nil
	}

	return &markdownRenderer{renderer: r, width: width}
}

// UpdateWidth recreates the renderer only if width has actually changed.
// Returns true if renderer was updated, false if unchanged.
func (m *markdownRenderer) UpdateWidth(width int) bool {
	if m == nil || width <= 0 || m.width == width {
		return false
	}

	r, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		// Keep existing renderer on error
		return false
	}

	m.renderer = r
	m.width = width
	return true
}

// Render converts Markdown to styled terminal output.
// Returns original text if rendering fails.
func (m *markdownRenderer) Render(markdown string) string {
	if m == nil || m.renderer == nil {
		return markdown
	}

	rendered, err := m.renderer.Render(markdown)
	if err != nil {
		return markdown
	}

	// Trim trailing newlines added by glamour
	return strings.TrimSuffix(rendered, "\n")
}
