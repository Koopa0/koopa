// Package tui provides Bubble Tea terminal interface for Koopa.
package tui

import (
	"context"
	"errors"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/google/uuid"
	"github.com/koopa0/koopa/internal/chat"
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

// Model is the Bubble Tea model for Koopa terminal interface.
type Model struct {
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
	toolStatus    string // Current tool status (e.g., "搜尋網路..."), empty when idle

	// Dependencies (direct, no interface)
	chatFlow  *chat.Flow
	sessionID uuid.UUID
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
func (m *Model) addMessage(msg Message) {
	m.messages = append(m.messages, msg)
	if len(m.messages) > maxMessages {
		// Remove oldest messages to stay within bounds
		m.messages = m.messages[len(m.messages)-maxMessages:]
	}
}

// New creates a Model for chat interaction.
// Returns error if required dependencies are nil.
//
// IMPORTANT: ctx MUST be the same context passed to tea.WithContext()
// to ensure consistent cancellation behavior.
func New(ctx context.Context, flow *chat.Flow, sessionID uuid.UUID) (*Model, error) {
	if flow == nil {
		return nil, errors.New("tui.New: flow is required")
	}
	if ctx == nil {
		return nil, errors.New("tui.New: ctx is required")
	}
	if sessionID == uuid.Nil {
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

	return &Model{
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
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		m.spinner.Tick,
		m.input.Focus(), // Ensure textarea is focused on startup
	)
}
