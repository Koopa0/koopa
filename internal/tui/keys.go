package tui

import (
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

// Slash command constants.
const (
	cmdHelp  = "/help"
	cmdClear = "/clear"
	cmdExit  = "/exit"
	cmdQuit  = "/quit"
)

// keyMap holds key bindings for help bar display.
type keyMap struct {
	Submit     key.Binding
	NewLine    key.Binding
	History    key.Binding
	Cancel     key.Binding
	Quit       key.Binding
	ScrollUp   key.Binding
	ScrollDown key.Binding
	EscCancel  key.Binding
}

func newKeyMap() keyMap {
	return keyMap{
		Submit:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "send")),
		NewLine:    key.NewBinding(key.WithKeys("shift+enter"), key.WithHelp("s+enter", "newline")),
		History:    key.NewBinding(key.WithKeys("up", "down"), key.WithHelp("↑/↓", "history")),
		Cancel:     key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "cancel")),
		Quit:       key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("ctrl+d", "exit")),
		ScrollUp:   key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "scroll up")),
		ScrollDown: key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "scroll down")),
		EscCancel:  key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel")),
	}
}

//nolint:gocyclo // Keyboard handler requires branching for all key combinations
func (m *Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	k := msg.Key()

	// Check for Ctrl modifier
	if k.Mod&tea.ModCtrl != 0 {
		switch k.Code {
		case 'c':
			return m.handleCtrlC()
		case 'd':
			cmd := m.cleanup()
			return m, cmd
		}
	}

	// Check special keys
	switch k.Code {
	case tea.KeyEnter:
		if m.state == StateInput {
			// Enter without Shift = submit
			// Shift+Enter = newline (pass through to textarea)
			if k.Mod&tea.ModShift == 0 {
				return m.handleSubmit()
			}
		}

	case tea.KeyUp:
		// Up at first line navigates history, otherwise pass to textarea
		if m.state == StateInput && m.input.Line() == 0 {
			return m.navigateHistory(-1)
		}

	case tea.KeyDown:
		// Down at last line navigates history, otherwise pass to textarea
		if m.state == StateInput && m.input.Line() == m.input.LineCount()-1 {
			return m.navigateHistory(1)
		}

	case tea.KeyEscape:
		if m.state == StateStreaming || m.state == StateThinking {
			m.cancelStream()
			m.state = StateInput
			m.output.Reset()
			return m, nil
		}

	case tea.KeyPgUp:
		m.viewport.PageUp()
		return m, nil

	case tea.KeyPgDown:
		m.viewport.PageDown()
		return m, nil
	}

	// Pass keys to textarea for typing - ALWAYS allow typing even during streaming
	// Better UX: users can prepare next message while LLM responds
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) handleCtrlC() (tea.Model, tea.Cmd) {
	now := time.Now()

	// Double Ctrl+C within 1 second = quit
	if now.Sub(m.lastCtrlC) < time.Second {
		cmd := m.cleanup()
		return m, cmd
	}
	m.lastCtrlC = now

	switch m.state {
	case StateInput:
		m.input.Reset()
		return m, nil

	case StateThinking, StateStreaming:
		m.cancelStream()
		m.state = StateInput
		m.output.Reset()
		m.addMessage(Message{Role: roleSystem, Text: "(Canceled)"})
		return m, nil
	}

	return m, nil
}

func (m *Model) handleSubmit() (tea.Model, tea.Cmd) {
	query := strings.TrimSpace(m.input.Value())
	if query == "" {
		return m, nil
	}

	// Handle slash commands
	if strings.HasPrefix(query, "/") {
		return m.handleSlashCommand(query)
	}

	// Add to history (enforce maxHistory cap)
	m.history = append(m.history, query)
	if len(m.history) > maxHistory {
		// Remove oldest entries to stay within bounds
		m.history = m.history[len(m.history)-maxHistory:]
	}
	m.historyIdx = len(m.history)

	// Add user message
	m.addMessage(Message{Role: roleUser, Text: query})

	// Clear input
	m.input.Reset()

	// Start thinking
	m.state = StateThinking

	return m, tea.Batch(
		m.spinner.Tick,
		m.startStream(query),
	)
}

func (m *Model) handleSlashCommand(cmd string) (tea.Model, tea.Cmd) {
	switch cmd {
	case cmdHelp:
		m.addMessage(Message{
			Role: roleSystem,
			Text: "Commands: " + cmdHelp + ", " + cmdClear + ", " + cmdExit + "\nShortcuts:\n  Enter: send message\n  Shift+Enter: new line\n  Ctrl+C: cancel/clear\n  Ctrl+D: exit\n  Up/Down: history\n  PgUp/PgDn: scroll",
		})
	case cmdClear:
		m.messages = nil
	case cmdExit, cmdQuit:
		cleanupCmd := m.cleanup()
		return m, cleanupCmd
	default:
		m.addMessage(Message{
			Role: roleError,
			Text: "Unknown command: " + cmd,
		})
	}
	m.input.Reset()
	return m, nil
}

func (m *Model) navigateHistory(delta int) (tea.Model, tea.Cmd) {
	if len(m.history) == 0 {
		return m, nil
	}

	m.historyIdx += delta

	if m.historyIdx < 0 {
		m.historyIdx = 0
	}
	if m.historyIdx > len(m.history) {
		m.historyIdx = len(m.history)
	}

	if m.historyIdx == len(m.history) {
		m.input.SetValue("")
	} else {
		m.input.SetValue(m.history[m.historyIdx])
		// Move cursor to end of text
		m.input.CursorEnd()
	}

	return m, nil
}

func (m *Model) cancelStream() {
	if m.streamCancel != nil {
		m.streamCancel()
		m.streamCancel = nil
	}
}

// cleanup cancels any active stream and returns the quit command.
// Waits for goroutine exit with timeout to prevent resource leaks.
func (m *Model) cleanup() tea.Cmd {
	// Cancel main context first - this triggers all goroutines using m.ctx
	if m.ctxCancel != nil {
		m.ctxCancel()
		m.ctxCancel = nil
	}

	// Then cancel stream-specific context (may already be canceled via parent)
	m.cancelStream()
	m.streamEventCh = nil

	return tea.Quit
}
