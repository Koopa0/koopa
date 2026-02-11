package tui

import (
	"context"
	"errors"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
)

// Update implements tea.Model.
//
//nolint:gocognit,gocyclo // Bubble Tea Update requires type switch on all message types
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.handleKey(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Calculate viewport height: total - input - separators - help
		inputHeight := m.input.Height() + promptLines
		fixedHeight := separatorLines + inputHeight + helpLines
		vpHeight := max(msg.Height-fixedHeight, minViewport)

		m.viewport.SetWidth(msg.Width)
		m.viewport.SetHeight(vpHeight)
		m.input.SetWidth(msg.Width - 4) // Room for "> " prompt
		m.help.SetWidth(msg.Width)
		m.markdown.UpdateWidth(msg.Width)

		// Rebuild viewport content with new dimensions
		m.rebuildViewportContent()
		return m, nil

	case tea.MouseWheelMsg:
		// Forward mouse wheel to viewport for scrolling
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		// Rebuild viewport to update spinner animation during thinking or tool execution
		if m.state == StateThinking || (m.state == StateStreaming && m.toolStatus != "") {
			m.rebuildViewportContent()
		}
		return m, cmd

	case streamStartedMsg:
		m.streamCancel = msg.cancel
		m.streamEventCh = msg.eventCh
		m.state = StateStreaming
		m.rebuildViewportContent()
		m.viewport.GotoBottom()
		return m, listenForStream(msg.eventCh)

	case streamToolMsg:
		m.toolStatus = msg.status
		m.rebuildViewportContent()
		m.viewport.GotoBottom()
		return m, listenForStream(m.streamEventCh)

	case streamTextMsg:
		m.toolStatus = "" // Clear tool status when text arrives
		m.output.WriteString(msg.text)
		m.rebuildViewportContent()
		m.viewport.GotoBottom()
		return m, listenForStream(m.streamEventCh)

	case streamDoneMsg:
		m.state = StateInput
		m.toolStatus = ""

		// Cancel context to release timer resources
		if m.streamCancel != nil {
			m.streamCancel()
			m.streamCancel = nil
		}
		m.streamEventCh = nil

		// Prefer msg.output.Response (complete response from Genkit) over accumulated chunks.
		// This handles models that don't stream or send final content only in Output.
		finalText := msg.output.Response
		if finalText == "" {
			// Fallback to accumulated chunks if Response is empty
			finalText = m.output.String()
		}

		m.addMessage(Message{
			Role: roleAssistant,
			Text: finalText,
		})
		m.output.Reset()
		m.rebuildViewportContent()
		m.viewport.GotoBottom()
		// Re-focus textarea after stream completes
		return m, m.input.Focus()

	case streamErrorMsg:
		m.state = StateInput
		m.toolStatus = ""

		// Cancel context to release timer resources
		if m.streamCancel != nil {
			m.streamCancel()
			m.streamCancel = nil
		}
		m.streamEventCh = nil

		switch {
		case errors.Is(msg.err, context.Canceled):
			m.addMessage(Message{Role: roleSystem, Text: "(Canceled)"})
		case errors.Is(msg.err, context.DeadlineExceeded):
			m.addMessage(Message{Role: roleError, Text: "Query timeout (>5 min). Try a simpler query or break it into steps."})
		default:
			m.addMessage(Message{Role: roleError, Text: msg.err.Error()})
		}
		m.output.Reset()
		m.rebuildViewportContent()
		m.viewport.GotoBottom()
		// Re-focus textarea after error
		return m, m.input.Focus()
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}
