// Package tui provides Bubble Tea terminal interface for Koopa.
package tui

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
)

// State represents TUI state machine.
type State int

// TUI state machine states.
const (
	StateInput     State = iota // Awaiting user input
	StateThinking               // Processing request
	StateStreaming              // Streaming response
)

// Memory bounds to prevent unbounded growth.
const (
	maxMessages = 100 // Maximum messages stored
	maxHistory  = 100 // Maximum command history entries
)

// Timeout constants for stream operations and cleanup.
// Centralized here for consistency across the TUI package.
const (
	streamTimeout  = 5 * time.Minute        // Maximum time for a single stream
	cleanupTimeout = 100 * time.Millisecond // Maximum wait for goroutine cleanup
)

// Message role constants for consistent display.
const (
	roleUser      = "user"
	roleAssistant = "assistant"
	roleSystem    = "system"
	roleError     = "error"
)

// Message represents a conversation message for display.
type Message struct {
	Role string // "user", "assistant", "system", "error"
	Text string
}

// TUI is the Bubble Tea model for Koopa terminal interface.
type TUI struct {
	// Input (textarea for multi-line support, Shift+Enter for newline)
	input      textarea.Model
	history    []string
	historyIdx int

	// State
	state     State
	lastCtrlC time.Time

	// Output
	spinner  spinner.Model
	output   strings.Builder
	viewBuf  strings.Builder // Reusable buffer for View() to reduce allocations
	messages []Message

	// Stream management
	// Note: No sync.WaitGroup - Bubble Tea's event loop provides synchronization.
	// Channel closure signals goroutine completion.
	streamCancel context.CancelFunc
	streamTextCh <-chan string
	streamDoneCh <-chan chat.Output
	streamErrCh  <-chan error
	streamDone   chan struct{} // Signals goroutine exit for cleanup

	// Dependencies (direct, no interface)
	chatFlow  *chat.Flow
	sessionID string
	ctx       context.Context
	ctxCancel context.CancelFunc // For canceling all operations on exit

	// Dimensions
	width  int
	height int

	// Styles
	styles Styles

	// Markdown rendering (nil = graceful degradation to plain text)
	markdown *markdownRenderer
}

// addMessage appends a message and enforces maxMessages bound.
func (t *TUI) addMessage(msg Message) {
	t.messages = append(t.messages, msg)
	if len(t.messages) > maxMessages {
		// Remove oldest messages to stay within bounds
		t.messages = t.messages[len(t.messages)-maxMessages:]
	}
}

// New creates a TUI model for chat interaction.
// Panics if flow or ctx are nil - these are programmer errors that
// should be caught during development, not runtime.
//
// IMPORTANT: ctx MUST be the same context passed to tea.WithContext()
// to ensure consistent cancellation behavior.
func New(ctx context.Context, flow *chat.Flow, sessionID string) *TUI {
	if flow == nil {
		panic("tui.New: flow is required")
	}
	if ctx == nil {
		panic("tui.New: ctx is required")
	}

	// Create cancellable context for cleanup on exit
	ctx, cancel := context.WithCancel(ctx)

	// Create textarea for multi-line input
	// Enter submits, Shift+Enter adds newline (default behavior)
	ta := textarea.New()
	ta.Placeholder = "Ask anything..."
	ta.SetHeight(1)  // Single line by default
	ta.SetWidth(120) // Wide enough for long text, updated on WindowSizeMsg
	ta.MaxWidth = 0  // No max width limit
	ta.ShowLineNumbers = false

	// Clean, minimal styling like Claude Code / Gemini CLI
	// No background colors, just simple text
	cleanStyle := textarea.StyleState{
		Base:        lipgloss.NewStyle(),
		Text:        lipgloss.NewStyle(),
		Placeholder: lipgloss.NewStyle().Foreground(lipgloss.Color("240")), // Gray placeholder
		Prompt:      lipgloss.NewStyle(),
	}
	ta.SetStyles(textarea.Styles{
		Focused: cleanStyle,
		Blurred: cleanStyle,
	})
	ta.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.Dot

	return &TUI{
		chatFlow:  flow,
		sessionID: sessionID,
		ctx:       ctx,
		ctxCancel: cancel,
		input:     ta,
		spinner:   sp,
		styles:    DefaultStyles(),
		history:   make([]string, 0, maxHistory),
		markdown:  newMarkdownRenderer(80),
		width:     80, // Default width until WindowSizeMsg arrives
	}
}

// Init implements tea.Model.
func (t *TUI) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		t.spinner.Tick,
		t.input.Focus(), // Ensure textarea is focused on startup
	)
}

// Update implements tea.Model.
//
//nolint:gocognit,gocyclo // Bubble Tea Update requires type switch on all message types
func (t *TUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return t.handleKey(msg)

	case tea.WindowSizeMsg:
		t.width = msg.Width
		t.height = msg.Height
		// Update textarea width (leave room for prompt "> ")
		t.input.SetWidth(msg.Width - 4)
		// Update markdown renderer only if width actually changed
		t.markdown.UpdateWidth(msg.Width)
		return t, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		t.spinner, cmd = t.spinner.Update(msg)
		return t, cmd

	case streamStartedMsg:
		t.streamCancel = msg.cancel
		t.streamTextCh = msg.textCh
		t.streamDoneCh = msg.doneCh
		t.streamErrCh = msg.errCh
		t.streamDone = msg.done
		t.state = StateStreaming
		return t, listenForStream(msg.textCh, msg.doneCh, msg.errCh)

	case streamTextMsg:
		t.output.WriteString(msg.text)
		return t, listenForStream(t.streamTextCh, t.streamDoneCh, t.streamErrCh)

	case streamDoneMsg:
		t.state = StateInput

		// Cancel context to release timer resources BEFORE clearing reference
		if t.streamCancel != nil {
			t.streamCancel()
			t.streamCancel = nil
		}

		// Wait for goroutine to fully exit before proceeding
		if t.streamDone != nil {
			select {
			case <-t.streamDone:
				// Goroutine exited cleanly
			case <-time.After(cleanupTimeout):
				slog.Warn("stream goroutine did not exit after Done")
			}
			t.streamDone = nil
		}

		// Prefer msg.output.Response (complete response from Genkit) over accumulated chunks.
		// This handles models that don't stream or send final content only in Output.
		finalText := msg.output.Response
		if finalText == "" {
			// Fallback to accumulated chunks if Response is empty
			finalText = t.output.String()
		}

		t.addMessage(Message{
			Role: roleAssistant,
			Text: finalText,
		})
		t.output.Reset()
		// Re-focus textarea after stream completes
		return t, t.input.Focus()

	case streamErrorMsg:
		t.state = StateInput

		// Cancel context to release timer resources BEFORE clearing reference
		if t.streamCancel != nil {
			t.streamCancel()
			t.streamCancel = nil
		}

		// Wait for goroutine to fully exit before proceeding
		if t.streamDone != nil {
			select {
			case <-t.streamDone:
				// Goroutine exited cleanly
			case <-time.After(cleanupTimeout):
				slog.Warn("stream goroutine did not exit after error")
			}
			t.streamDone = nil
		}

		switch {
		case errors.Is(msg.err, context.Canceled):
			t.addMessage(Message{Role: roleSystem, Text: "(Canceled)"})
		case errors.Is(msg.err, context.DeadlineExceeded):
			t.addMessage(Message{Role: roleError, Text: "Query timeout (>5 min). Try a simpler query or break it into steps."})
		default:
			t.addMessage(Message{Role: roleError, Text: msg.err.Error()})
		}
		t.output.Reset()
		// Re-focus textarea after error
		return t, t.input.Focus()
	}

	var cmd tea.Cmd
	t.input, cmd = t.input.Update(msg)
	return t, cmd
}

// View implements tea.Model.
// Renders inline (no AltScreen).
func (t *TUI) View() tea.View {
	// Reuse builder to reduce allocations (reset at end of each call)
	t.viewBuf.Reset()

	// Banner (ASCII art) and tips - always show
	_, _ = t.viewBuf.WriteString(t.styles.RenderBanner())
	_, _ = t.viewBuf.WriteString("\n")
	_, _ = t.viewBuf.WriteString(t.styles.RenderWelcomeTips())
	_, _ = t.viewBuf.WriteString("\n")

	// Messages (already bounded by addMessage)
	for _, msg := range t.messages {
		switch msg.Role {
		case roleUser:
			_, _ = t.viewBuf.WriteString(t.styles.User.Render("You> "))
			_, _ = t.viewBuf.WriteString(msg.Text)
		case roleAssistant:
			_, _ = t.viewBuf.WriteString(t.styles.Assistant.Render("Koopa> "))
			// Render markdown for assistant messages
			_, _ = t.viewBuf.WriteString(t.markdown.Render(msg.Text))
		case roleSystem:
			_, _ = t.viewBuf.WriteString(t.styles.System.Render(msg.Text))
		case roleError:
			_, _ = t.viewBuf.WriteString(t.styles.Error.Render("Error: " + msg.Text))
		}
		_, _ = t.viewBuf.WriteString("\n\n")
	}

	// Current streaming output
	if t.state == StateStreaming && t.output.Len() > 0 {
		_, _ = t.viewBuf.WriteString(t.styles.Assistant.Render("Koopa> "))
		_, _ = t.viewBuf.WriteString(t.output.String())
		_, _ = t.viewBuf.WriteString("\n\n")
	}

	// Thinking indicator
	if t.state == StateThinking {
		_, _ = t.viewBuf.WriteString(t.spinner.View())
		_, _ = t.viewBuf.WriteString(" Thinking...\n\n")
	}

	// Separator line above input (like Claude Code / Gemini CLI)
	_, _ = t.viewBuf.WriteString(t.renderSeparator())
	_, _ = t.viewBuf.WriteString("\n")

	// Input prompt - always show and always accept input
	// Users can type while LLM is thinking/streaming (better UX)
	_, _ = t.viewBuf.WriteString(t.styles.Prompt.Render("> "))
	_, _ = t.viewBuf.WriteString(t.input.View())
	_, _ = t.viewBuf.WriteString("\n")

	// Separator line below input
	_, _ = t.viewBuf.WriteString(t.renderSeparator())
	_, _ = t.viewBuf.WriteString("\n")

	// Status bar
	_, _ = t.viewBuf.WriteString(t.renderStatusBar())

	// Inline rendering (no AltScreen)
	return tea.NewView(t.viewBuf.String())
}

// renderSeparator returns a horizontal line separator.
func (t *TUI) renderSeparator() string {
	width := t.width
	if width <= 0 {
		width = 80 // Default width
	}
	return t.styles.Separator.Render(strings.Repeat("─", width))
}

func (t *TUI) renderStatusBar() string {
	var help string
	switch t.state {
	case StateInput:
		help = "Enter: send | Shift+Enter: newline | Up/Down: history | Ctrl+C: clear | Ctrl+D: exit"
	case StateThinking, StateStreaming:
		help = "Esc: cancel | Ctrl+C x2: force exit"
	}
	return t.styles.StatusBar.Render(help)
}
