package tui

import (
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

// View implements tea.Model.
// Uses AltScreen with viewport for scrollable message history.
func (m *Model) View() tea.View {
	m.viewBuf.Reset()

	// Viewport (scrollable message area)
	_, _ = m.viewBuf.WriteString(m.viewport.View())
	_, _ = m.viewBuf.WriteString("\n")

	// Separator line above input
	_, _ = m.viewBuf.WriteString(m.renderSeparator())
	_, _ = m.viewBuf.WriteString("\n")

	// Input prompt - always show and always accept input
	// Users can type while LLM is thinking/streaming (better UX)
	_, _ = m.viewBuf.WriteString(m.styles.Prompt.Render("> "))
	_, _ = m.viewBuf.WriteString(m.input.View())
	_, _ = m.viewBuf.WriteString("\n")

	// Separator line below input
	_, _ = m.viewBuf.WriteString(m.renderSeparator())
	_, _ = m.viewBuf.WriteString("\n")

	// Help bar (keyboard shortcuts)
	_, _ = m.viewBuf.WriteString(m.renderStatusBar())

	v := tea.NewView(m.viewBuf.String())
	v.AltScreen = true
	return v
}

// rebuildViewportContent reconstructs the viewport content from messages and state.
// Called when messages, streaming output, or state changes.
func (m *Model) rebuildViewportContent() {
	var b strings.Builder

	// Banner (ASCII art) and tips
	_, _ = b.WriteString(m.styles.RenderBanner())
	_, _ = b.WriteString("\n")
	_, _ = b.WriteString(m.styles.RenderWelcomeTips())
	_, _ = b.WriteString("\n")

	// Messages (already bounded by addMessage)
	for _, msg := range m.messages {
		switch msg.Role {
		case roleUser:
			_, _ = b.WriteString(m.styles.User.Render("You> "))
			_, _ = b.WriteString(msg.Text)
		case roleAssistant:
			_, _ = b.WriteString(m.styles.Assistant.Render("Koopa> "))
			_, _ = b.WriteString(m.markdown.Render(msg.Text))
		case roleSystem:
			_, _ = b.WriteString(m.styles.System.Render(msg.Text))
		case roleError:
			_, _ = b.WriteString(m.styles.Error.Render("Error: " + msg.Text))
		}
		_, _ = b.WriteString("\n\n")
	}

	// Current streaming output
	if m.state == StateStreaming && m.output.Len() > 0 {
		_, _ = b.WriteString(m.styles.Assistant.Render("Koopa> "))
		_, _ = b.WriteString(m.output.String())
		_, _ = b.WriteString("\n\n")
	}

	// Tool status indicator (shown during streaming when a tool is executing)
	if m.state == StateStreaming && m.toolStatus != "" {
		_, _ = b.WriteString(m.spinner.View())
		_, _ = b.WriteString(" ")
		_, _ = b.WriteString(m.styles.System.Render(m.toolStatus))
		_, _ = b.WriteString("\n\n")
	}

	// Thinking indicator
	if m.state == StateThinking {
		_, _ = b.WriteString(m.spinner.View())
		_, _ = b.WriteString(" Thinking...\n\n")
	}

	m.viewport.SetContent(b.String())
}

// renderSeparator returns a horizontal line separator.
func (m *Model) renderSeparator() string {
	width := m.width
	if width <= 0 {
		width = 80 // Default width
	}
	return m.styles.Separator.Render(strings.Repeat("─", width))
}

// renderStatusBar returns state-appropriate keyboard shortcut help.
func (m *Model) renderStatusBar() string {
	var bindings []key.Binding
	switch m.state {
	case StateInput:
		bindings = []key.Binding{
			m.keys.Submit, m.keys.NewLine, m.keys.History,
			m.keys.Cancel, m.keys.Quit, m.keys.ScrollUp,
		}
	case StateThinking, StateStreaming:
		bindings = []key.Binding{
			m.keys.EscCancel, m.keys.Cancel,
			m.keys.ScrollUp, m.keys.ScrollDown,
		}
	}
	return m.help.ShortHelpView(bindings)
}
