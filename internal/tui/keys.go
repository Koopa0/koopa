package tui

import (
	"log/slog"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Slash command constants.
const (
	cmdHelp  = "/help"
	cmdClear = "/clear"
	cmdExit  = "/exit"
	cmdQuit  = "/quit"
)

//nolint:gocyclo // Keyboard handler requires branching for all key combinations
func (t *TUI) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.Key()

	// Check for Ctrl modifier
	if key.Mod&tea.ModCtrl != 0 {
		switch key.Code {
		case 'c':
			return t.handleCtrlC()
		case 'd':
			cmd := t.cleanup()
			return t, cmd
		}
	}

	// Check special keys
	switch key.Code {
	case tea.KeyEnter:
		if t.state == StateInput {
			// Enter without Shift = submit
			// Shift+Enter = newline (pass through to textarea)
			if key.Mod&tea.ModShift == 0 {
				return t.handleSubmit()
			}
		}

	case tea.KeyUp:
		// Up at first line navigates history, otherwise pass to textarea
		if t.state == StateInput && t.input.Line() == 0 {
			return t.navigateHistory(-1)
		}

	case tea.KeyDown:
		// Down at last line navigates history, otherwise pass to textarea
		if t.state == StateInput && t.input.Line() == t.input.LineCount()-1 {
			return t.navigateHistory(1)
		}

	case tea.KeyEscape:
		if t.state == StateStreaming || t.state == StateThinking {
			t.cancelStream()
			t.state = StateInput
			t.output.Reset()
			return t, nil
		}
	}

	// Pass keys to textarea for typing - ALWAYS allow typing even during streaming
	// Better UX: users can prepare next message while LLM responds
	var cmd tea.Cmd
	t.input, cmd = t.input.Update(msg)
	return t, cmd
}

func (t *TUI) handleCtrlC() (tea.Model, tea.Cmd) {
	now := time.Now()

	// Double Ctrl+C within 1 second = quit
	if now.Sub(t.lastCtrlC) < time.Second {
		cmd := t.cleanup()
		return t, cmd
	}
	t.lastCtrlC = now

	switch t.state {
	case StateInput:
		t.input.Reset()
		return t, nil

	case StateThinking, StateStreaming:
		t.cancelStream()
		t.state = StateInput
		t.output.Reset()
		t.addMessage(Message{Role: "system", Text: "(Canceled)"})
		return t, nil
	}

	return t, nil
}

func (t *TUI) handleSubmit() (tea.Model, tea.Cmd) {
	query := strings.TrimSpace(t.input.Value())
	if query == "" {
		return t, nil
	}

	// Handle slash commands
	if strings.HasPrefix(query, "/") {
		return t.handleSlashCommand(query)
	}

	// Add to history (enforce maxHistory cap)
	t.history = append(t.history, query)
	if len(t.history) > maxHistory {
		// Remove oldest entries to stay within bounds
		t.history = t.history[len(t.history)-maxHistory:]
	}
	t.historyIdx = len(t.history)

	// Add user message
	t.addMessage(Message{Role: "user", Text: query})

	// Clear input
	t.input.Reset()

	// Start thinking
	t.state = StateThinking

	return t, tea.Batch(
		t.spinner.Tick,
		t.startStream(query),
	)
}

func (t *TUI) handleSlashCommand(cmd string) (tea.Model, tea.Cmd) {
	switch cmd {
	case cmdHelp:
		t.addMessage(Message{
			Role: roleSystem,
			Text: "Commands: " + cmdHelp + ", " + cmdClear + ", " + cmdExit + "\nShortcuts:\n  Enter: send message\n  Shift+Enter: new line\n  Ctrl+C: cancel/clear\n  Ctrl+D: exit\n  Up/Down: history",
		})
	case cmdClear:
		t.messages = nil
	case cmdExit, cmdQuit:
		cleanupCmd := t.cleanup()
		return t, cleanupCmd
	default:
		t.addMessage(Message{
			Role: roleError,
			Text: "Unknown command: " + cmd,
		})
	}
	t.input.Reset()
	return t, nil
}

func (t *TUI) navigateHistory(delta int) (tea.Model, tea.Cmd) {
	if len(t.history) == 0 {
		return t, nil
	}

	t.historyIdx += delta

	if t.historyIdx < 0 {
		t.historyIdx = 0
	}
	if t.historyIdx > len(t.history) {
		t.historyIdx = len(t.history)
	}

	if t.historyIdx == len(t.history) {
		t.input.SetValue("")
	} else {
		t.input.SetValue(t.history[t.historyIdx])
		// Move cursor to end of text
		t.input.CursorEnd()
	}

	return t, nil
}

func (t *TUI) cancelStream() {
	if t.streamCancel != nil {
		t.streamCancel()
		t.streamCancel = nil
	}
}

// cleanup cancels any active stream and returns the quit command.
// Waits for goroutine exit with timeout to prevent resource leaks.
func (t *TUI) cleanup() tea.Cmd {
	// Cancel main context first - this triggers all goroutines using t.ctx
	if t.ctxCancel != nil {
		t.ctxCancel()
		t.ctxCancel = nil
	}

	// Then cancel stream-specific context (may already be canceled via parent)
	t.cancelStream()

	// Wait for goroutine with timeout (increased for network cleanup)
	if t.streamDone != nil {
		select {
		case <-t.streamDone:
			// Goroutine exited cleanly
		case <-time.After(500 * time.Millisecond): // Allow more time for network cleanup
			slog.Error("goroutine leak: stream did not exit after context cancel")
		}
		t.streamDone = nil
	}

	return tea.Quit
}
