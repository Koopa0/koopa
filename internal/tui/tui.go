// Package tui provides Bubble Tea terminal interface for Koopa.
package tui

import (
	"context"
	"errors"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/koopa0/koopa/internal/agent/chat"
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

// Timeout constants for stream operations.
const streamTimeout = 5 * time.Minute // Maximum time for a single stream

// Message role constants for consistent display.
const (
	roleUser      = "user"
	roleAssistant = "assistant"
	roleSystem    = "system"
	roleError     = "error"
)

// Layout constants for viewport height calculation.
const (
	separatorLines = 2 // Two separator lines (above and below input)
	helpLines      = 1 // Help bar height
	promptLines    = 1 // Prompt prefix line
	minViewport    = 3 // Minimum viewport height
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

	// Scrollable message viewport
	viewport viewport.Model

	// Help bar for keyboard shortcuts
	help help.Model
	keys keyMap

	// Stream management
	// Note: No sync.WaitGroup - Bubble Tea's event loop provides synchronization.
	// Single union channel with discriminated events simplifies select logic.
	streamCancel  context.CancelFunc
	streamEventCh <-chan streamEvent

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
// Returns error if required dependencies are nil.
//
// IMPORTANT: ctx MUST be the same context passed to tea.WithContext()
// to ensure consistent cancellation behavior.
func New(ctx context.Context, flow *chat.Flow, sessionID string) (*TUI, error) {
	if flow == nil {
		return nil, errors.New("tui.New: flow is required")
	}
	if ctx == nil {
		return nil, errors.New("tui.New: ctx is required")
	}
	if sessionID == "" {
		return nil, errors.New("tui.New: session ID is required")
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

	// Create viewport for scrollable message history.
	// Disable built-in keyboard handling — we route keys explicitly
	// in handleKey to avoid conflicts with textarea/history navigation.
	vp := viewport.New(viewport.WithWidth(80), viewport.WithHeight(20))
	vp.MouseWheelEnabled = true
	vp.SoftWrap = true
	vp.KeyMap = viewport.KeyMap{} // Disable default key bindings

	h := help.New()

	return &TUI{
		chatFlow:  flow,
		sessionID: sessionID,
		ctx:       ctx,
		ctxCancel: cancel,
		input:     ta,
		spinner:   sp,
		viewport:  vp,
		help:      h,
		keys:      newKeyMap(),
		styles:    DefaultStyles(),
		history:   make([]string, 0, maxHistory),
		markdown:  newMarkdownRenderer(80),
		width:     80, // Default width until WindowSizeMsg arrives
	}, nil
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

		// Calculate viewport height: total - input - separators - help
		inputHeight := t.input.Height() + promptLines
		fixedHeight := separatorLines + inputHeight + helpLines
		vpHeight := max(msg.Height-fixedHeight, minViewport)

		t.viewport.SetWidth(msg.Width)
		t.viewport.SetHeight(vpHeight)
		t.input.SetWidth(msg.Width - 4) // Room for "> " prompt
		t.help.SetWidth(msg.Width)
		t.markdown.UpdateWidth(msg.Width)

		// Rebuild viewport content with new dimensions
		t.rebuildViewportContent()
		return t, nil

	case tea.MouseWheelMsg:
		// Forward mouse wheel to viewport for scrolling
		var cmd tea.Cmd
		t.viewport, cmd = t.viewport.Update(msg)
		return t, cmd

	case spinner.TickMsg:
		var cmd tea.Cmd
		t.spinner, cmd = t.spinner.Update(msg)
		// Rebuild viewport to update spinner animation
		if t.state == StateThinking {
			t.rebuildViewportContent()
		}
		return t, cmd

	case streamStartedMsg:
		t.streamCancel = msg.cancel
		t.streamEventCh = msg.eventCh
		t.state = StateStreaming
		t.rebuildViewportContent()
		t.viewport.GotoBottom()
		return t, listenForStream(msg.eventCh)

	case streamTextMsg:
		t.output.WriteString(msg.text)
		t.rebuildViewportContent()
		t.viewport.GotoBottom()
		return t, listenForStream(t.streamEventCh)

	case streamDoneMsg:
		t.state = StateInput

		// Cancel context to release timer resources
		if t.streamCancel != nil {
			t.streamCancel()
			t.streamCancel = nil
		}
		t.streamEventCh = nil

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
		t.rebuildViewportContent()
		t.viewport.GotoBottom()
		// Re-focus textarea after stream completes
		return t, t.input.Focus()

	case streamErrorMsg:
		t.state = StateInput

		// Cancel context to release timer resources
		if t.streamCancel != nil {
			t.streamCancel()
			t.streamCancel = nil
		}
		t.streamEventCh = nil

		switch {
		case errors.Is(msg.err, context.Canceled):
			t.addMessage(Message{Role: roleSystem, Text: "(Canceled)"})
		case errors.Is(msg.err, context.DeadlineExceeded):
			t.addMessage(Message{Role: roleError, Text: "Query timeout (>5 min). Try a simpler query or break it into steps."})
		default:
			t.addMessage(Message{Role: roleError, Text: msg.err.Error()})
		}
		t.output.Reset()
		t.rebuildViewportContent()
		t.viewport.GotoBottom()
		// Re-focus textarea after error
		return t, t.input.Focus()
	}

	var cmd tea.Cmd
	t.input, cmd = t.input.Update(msg)
	return t, cmd
}

// View implements tea.Model.
// Uses AltScreen with viewport for scrollable message history.
func (t *TUI) View() tea.View {
	t.viewBuf.Reset()

	// Viewport (scrollable message area)
	_, _ = t.viewBuf.WriteString(t.viewport.View())
	_, _ = t.viewBuf.WriteString("\n")

	// Separator line above input
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

	// Help bar (keyboard shortcuts)
	_, _ = t.viewBuf.WriteString(t.renderStatusBar())

	v := tea.NewView(t.viewBuf.String())
	v.AltScreen = true
	return v
}

// rebuildViewportContent reconstructs the viewport content from messages and state.
// Called when messages, streaming output, or state changes.
func (t *TUI) rebuildViewportContent() {
	var b strings.Builder

	// Banner (ASCII art) and tips
	_, _ = b.WriteString(t.styles.RenderBanner())
	_, _ = b.WriteString("\n")
	_, _ = b.WriteString(t.styles.RenderWelcomeTips())
	_, _ = b.WriteString("\n")

	// Messages (already bounded by addMessage)
	for _, msg := range t.messages {
		switch msg.Role {
		case roleUser:
			_, _ = b.WriteString(t.styles.User.Render("You> "))
			_, _ = b.WriteString(msg.Text)
		case roleAssistant:
			_, _ = b.WriteString(t.styles.Assistant.Render("Koopa> "))
			_, _ = b.WriteString(t.markdown.Render(msg.Text))
		case roleSystem:
			_, _ = b.WriteString(t.styles.System.Render(msg.Text))
		case roleError:
			_, _ = b.WriteString(t.styles.Error.Render("Error: " + msg.Text))
		}
		_, _ = b.WriteString("\n\n")
	}

	// Current streaming output
	if t.state == StateStreaming && t.output.Len() > 0 {
		_, _ = b.WriteString(t.styles.Assistant.Render("Koopa> "))
		_, _ = b.WriteString(t.output.String())
		_, _ = b.WriteString("\n\n")
	}

	// Thinking indicator
	if t.state == StateThinking {
		_, _ = b.WriteString(t.spinner.View())
		_, _ = b.WriteString(" Thinking...\n\n")
	}

	t.viewport.SetContent(b.String())
}

// renderSeparator returns a horizontal line separator.
func (t *TUI) renderSeparator() string {
	width := t.width
	if width <= 0 {
		width = 80 // Default width
	}
	return t.styles.Separator.Render(strings.Repeat("─", width))
}

// renderStatusBar returns state-appropriate keyboard shortcut help.
func (t *TUI) renderStatusBar() string {
	var bindings []key.Binding
	switch t.state {
	case StateInput:
		bindings = []key.Binding{
			t.keys.Submit, t.keys.NewLine, t.keys.History,
			t.keys.Cancel, t.keys.Quit, t.keys.ScrollUp,
		}
	case StateThinking, StateStreaming:
		bindings = []key.Binding{
			t.keys.EscCancel, t.keys.Cancel,
			t.keys.ScrollUp, t.keys.ScrollDown,
		}
	}
	return t.help.ShortHelpView(bindings)
}
