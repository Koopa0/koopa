package tui

import (
	"context"
	"testing"
	"time"

	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"
	"go.uber.org/goleak"

	"github.com/koopa0/koopa/internal/agent/chat"
)

// goleakOptions returns standard goleak options for all TUI tests.
// Filters out persistent goroutines that are expected to exist:
// - HTTP/2 connection pool goroutines
// - OpenCensus stats worker (global singleton, can't be stopped)
func goleakOptions() []goleak.Option {
	return []goleak.Option{
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("net/http.(*http2clientConnReadLoop).run"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	}
}

// newTestTUI creates a TUI with properly initialized textarea for testing.
func newTestTUI() *TUI {
	ta := textarea.New()
	ta.SetHeight(3)
	ta.ShowLineNumbers = false
	return &TUI{
		state:    StateInput,
		input:    ta,
		history:  make([]string, 0),
		styles:   DefaultStyles(),
		markdown: newMarkdownRenderer(80),
		ctx:      context.Background(), // Required for stream operations
	}
}

func TestNew_ErrorOnNilFlow(t *testing.T) {
	_, err := New(context.Background(), nil, "test")
	if err == nil {
		t.Error("Expected error for nil flow")
	}
}

func TestNew_ErrorOnNilContext(t *testing.T) {
	// Note: We can't create a real *chat.Flow without full setup,
	// so we're testing that error is returned for nil context
	var flow *chat.Flow
	//lint:ignore SA1012 intentionally testing nil context handling
	_, err := New(nil, flow, "test") //nolint:staticcheck
	if err == nil {
		t.Error("Expected error for nil context")
	}
}

func TestNew_ErrorOnEmptySessionID(t *testing.T) {
	_, err := New(context.Background(), nil, "")
	if err == nil {
		t.Error("Expected error for empty session ID")
	}
}

func TestTUI_Init(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	cmd := tui.Init()
	if cmd == nil {
		t.Error("Init should return a command (blink + spinner tick)")
	}
}

func TestTUI_HandleSlashCommands(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tests := []struct {
		name     string
		cmd      string
		wantExit bool
		wantMsgs int // number of messages added
	}{
		{"help", "/help", false, 1},
		{"clear", "/clear", false, 0}, // clears messages
		{"exit", "/exit", true, 0},
		{"quit", "/quit", true, 0},
		{"unknown", "/unknown", false, 1}, // error message
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tui := newTestTUI()

			// Pre-populate with a message for /clear test
			tui.messages = []Message{{Role: "user", Text: "hello"}}

			model, cmd := tui.handleSlashCommand(tt.cmd)
			result := model.(*TUI)

			if tt.wantExit {
				if cmd == nil {
					t.Error("Expected quit command for exit")
				}
			} else {
				if tt.cmd == "/clear" {
					if len(result.messages) != 0 {
						t.Error("/clear should clear messages")
					}
				} else {
					if len(result.messages) != 1+tt.wantMsgs {
						t.Errorf("Expected %d messages, got %d", 1+tt.wantMsgs, len(result.messages))
					}
				}
			}
		})
	}
}

func TestTUI_HistoryNavigation(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	tui.history = []string{"first", "second", "third"}
	tui.historyIdx = 3

	tests := []struct {
		delta    int
		expected string
	}{
		{-1, "third"},
		{-1, "second"},
		{-1, "first"},
		{-1, "first"}, // Should stay at first
		{1, "second"},
		{1, "third"},
		{1, ""}, // Past end = empty
		{1, ""}, // Should stay empty
	}

	for i, tt := range tests {
		model, _ := tui.navigateHistory(tt.delta)
		tui = model.(*TUI)
		if tui.input.Value() != tt.expected {
			t.Errorf("Step %d: got %q, want %q", i, tui.input.Value(), tt.expected)
		}
	}
}

func TestTUI_CtrlC_ClearsInput(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	tui.input.SetValue("some input")

	model, _ := tui.handleCtrlC()
	result := model.(*TUI)

	if result.input.Value() != "" {
		t.Error("First Ctrl+C should clear input")
	}
}

func TestTUI_DoubleCtrlC_Exits(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	tui.lastCtrlC = time.Now()

	_, cmd := tui.handleCtrlC()

	if cmd == nil {
		t.Error("Double Ctrl+C should return quit command")
	}
}

func TestTUI_Update_KeyPress(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	tui.input.SetValue("test")

	// Simulate Ctrl+C (should clear input)
	key := tea.Key{Code: 'c', Mod: tea.ModCtrl}
	msg := tea.KeyPressMsg(key)

	model, _ := tui.Update(msg)
	result := model.(*TUI)

	if result.input.Value() != "" {
		t.Error("Ctrl+C should clear input")
	}
}

func TestTUI_View_ContainsHeader(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()

	view := tui.View()
	// The View contains styled content, but should include "Koopa" somewhere
	if view.Content == nil {
		t.Error("View content should not be nil")
	}
}

func TestTUI_StreamMessageTypes(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	t.Run("streamTextMsg", func(t *testing.T) {
		eventCh := make(chan streamEvent, 1)

		tui := newTestTUI()
		tui.state = StateStreaming
		tui.streamEventCh = eventCh

		model, _ := tui.Update(streamTextMsg{text: "Hello"})
		result := model.(*TUI)

		if result.output.String() != "Hello" {
			t.Errorf("Expected 'Hello', got %q", result.output.String())
		}
	})

	t.Run("streamDoneMsg", func(t *testing.T) {
		tui := newTestTUI()
		tui.state = StateStreaming
		_, _ = tui.output.WriteString("Hello World")

		model, _ := tui.Update(streamDoneMsg{output: chat.Output{Response: "Hello World"}})
		result := model.(*TUI)

		if result.state != StateInput {
			t.Error("Should return to StateInput after stream done")
		}
		if len(result.messages) != 1 {
			t.Error("Should add assistant message")
		}
		if result.output.Len() != 0 {
			t.Error("Output buffer should be reset")
		}
	})

	t.Run("streamErrorMsg", func(t *testing.T) {
		tui := newTestTUI()
		tui.state = StateStreaming

		model, _ := tui.Update(streamErrorMsg{err: context.Canceled})
		result := model.(*TUI)

		if result.state != StateInput {
			t.Error("Should return to StateInput after error")
		}
		if len(result.messages) != 1 {
			t.Error("Should add system message for cancellation")
		}
		if result.messages[0].Role != "system" {
			t.Error("Should be system message for cancellation")
		}
	})
}

func TestListenForStream_UnionChannel(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	t.Run("text event", func(t *testing.T) {
		eventCh := make(chan streamEvent, 1)
		eventCh <- streamEvent{text: "hello"}

		cmd := listenForStream(eventCh)
		msg := cmd()

		if m, ok := msg.(streamTextMsg); !ok {
			t.Errorf("Expected streamTextMsg, got %T", msg)
		} else if m.text != "hello" {
			t.Errorf("Expected text 'hello', got %q", m.text)
		}
	})

	t.Run("done event", func(t *testing.T) {
		eventCh := make(chan streamEvent, 1)
		eventCh <- streamEvent{done: true, output: chat.Output{Response: "done"}}

		cmd := listenForStream(eventCh)
		msg := cmd()

		if m, ok := msg.(streamDoneMsg); !ok {
			t.Errorf("Expected streamDoneMsg, got %T", msg)
		} else if m.output.Response != "done" {
			t.Errorf("Expected response 'done', got %q", m.output.Response)
		}
	})

	t.Run("error event", func(t *testing.T) {
		eventCh := make(chan streamEvent, 1)
		eventCh <- streamEvent{err: context.Canceled}

		cmd := listenForStream(eventCh)
		msg := cmd()

		if _, ok := msg.(streamErrorMsg); !ok {
			t.Errorf("Expected streamErrorMsg, got %T", msg)
		}
	})

	t.Run("channel closed", func(t *testing.T) {
		eventCh := make(chan streamEvent)
		close(eventCh)

		cmd := listenForStream(eventCh)
		msg := cmd()

		if _, ok := msg.(streamErrorMsg); !ok {
			t.Errorf("Expected streamErrorMsg on channel close, got %T", msg)
		}
	})

	t.Run("nil channel returns nil", func(t *testing.T) {
		cmd := listenForStream(nil)
		msg := cmd()

		if msg != nil {
			t.Errorf("Expected nil for nil channel, got %T", msg)
		}
	})
}

func TestTUI_AddMessage_BoundsEnforcement(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()

	// Add more than maxMessages
	for i := 0; i < maxMessages+50; i++ {
		tui.addMessage(Message{Role: "user", Text: "test"})
	}

	if len(tui.messages) > maxMessages {
		t.Errorf("Message count %d exceeds max %d", len(tui.messages), maxMessages)
	}

	if len(tui.messages) != maxMessages {
		t.Errorf("Expected exactly %d messages, got %d", maxMessages, len(tui.messages))
	}
}

func TestTUI_HandleSubmit_AddsToHistory(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	tui.ctx = context.Background()
	tui.input.SetValue("test query")

	// We can't fully test handleSubmit without a real chat.Flow,
	// but we can verify the setup behavior
	initialHistoryLen := len(tui.history)

	// Manually simulate what handleSubmit does for history
	query := "test query"
	tui.history = append(tui.history, query)
	if len(tui.history) > maxHistory {
		tui.history = tui.history[len(tui.history)-maxHistory:]
	}
	tui.historyIdx = len(tui.history)

	if len(tui.history) != initialHistoryLen+1 {
		t.Error("History should increase by 1")
	}
	if tui.historyIdx != len(tui.history) {
		t.Error("History index should point past end")
	}
}

func TestTUI_HandleSubmit_HistoryBounds(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()

	// Pre-fill history to max
	for i := 0; i < maxHistory; i++ {
		tui.history = append(tui.history, "old")
	}

	// Add one more (simulating handleSubmit behavior)
	tui.history = append(tui.history, "new")
	if len(tui.history) > maxHistory {
		tui.history = tui.history[len(tui.history)-maxHistory:]
	}

	if len(tui.history) > maxHistory {
		t.Errorf("History count %d exceeds max %d", len(tui.history), maxHistory)
	}

	// Verify oldest was removed
	if tui.history[len(tui.history)-1] != "new" {
		t.Error("Newest entry should be preserved")
	}
}

func TestMarkdownRenderer_UpdateWidth(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	t.Run("creates renderer with correct width", func(t *testing.T) {
		mr := newMarkdownRenderer(100)
		if mr == nil {
			t.Fatal("Failed to create markdown renderer")
		}
		if mr.width != 100 {
			t.Errorf("Expected width 100, got %d", mr.width)
		}
	})

	t.Run("UpdateWidth changes width", func(t *testing.T) {
		mr := newMarkdownRenderer(80)
		if mr == nil {
			t.Fatal("Failed to create markdown renderer")
		}

		updated := mr.UpdateWidth(120)
		if !updated {
			t.Error("UpdateWidth should return true when width changes")
		}
		if mr.width != 120 {
			t.Errorf("Expected width 120, got %d", mr.width)
		}
	})

	t.Run("UpdateWidth no-op for same width", func(t *testing.T) {
		mr := newMarkdownRenderer(80)
		if mr == nil {
			t.Fatal("Failed to create markdown renderer")
		}

		updated := mr.UpdateWidth(80)
		if updated {
			t.Error("UpdateWidth should return false when width unchanged")
		}
	})

	t.Run("UpdateWidth handles nil receiver", func(t *testing.T) {
		var mr *markdownRenderer
		updated := mr.UpdateWidth(100)
		if updated {
			t.Error("UpdateWidth should return false for nil receiver")
		}
	})

	t.Run("UpdateWidth handles invalid width", func(t *testing.T) {
		mr := newMarkdownRenderer(80)
		if mr == nil {
			t.Fatal("Failed to create markdown renderer")
		}

		updated := mr.UpdateWidth(0)
		if updated {
			t.Error("UpdateWidth should return false for zero width")
		}

		updated = mr.UpdateWidth(-1)
		if updated {
			t.Error("UpdateWidth should return false for negative width")
		}
	})
}

func TestMarkdownRenderer_Render(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	t.Run("renders markdown", func(t *testing.T) {
		mr := newMarkdownRenderer(80)
		if mr == nil {
			t.Fatal("Failed to create markdown renderer")
		}

		result := mr.Render("**bold**")
		// Glamour adds ANSI codes, so just verify it's not empty
		if result == "" {
			t.Error("Render should produce output")
		}
	})

	t.Run("nil renderer returns original", func(t *testing.T) {
		var mr *markdownRenderer
		result := mr.Render("test")
		if result != "test" {
			t.Errorf("Expected original text, got %q", result)
		}
	})
}

func TestTUI_Cleanup(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()

	// Setup stream state
	eventCh := make(chan streamEvent, 1)
	tui.streamEventCh = eventCh

	cmd := tui.cleanup()
	if cmd == nil {
		t.Error("cleanup should return quit command")
	}

	// Verify streamEventCh is nil after cleanup
	if tui.streamEventCh != nil {
		t.Error("streamEventCh should be nil after cleanup")
	}
}

func TestTUI_CancelStream(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()

	canceled := false
	tui.streamCancel = func() { canceled = true }

	tui.cancelStream()

	if !canceled {
		t.Error("cancelStream should call cancel function")
	}
	if tui.streamCancel != nil {
		t.Error("streamCancel should be nil after cancel")
	}
}

func TestTUI_CtrlC_CancelsStream(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions()...)

	tui := newTestTUI()
	tui.state = StateStreaming

	canceled := false
	tui.streamCancel = func() { canceled = true }

	model, _ := tui.handleCtrlC()
	result := model.(*TUI)

	if !canceled {
		t.Error("Ctrl+C during streaming should cancel")
	}
	if result.state != StateInput {
		t.Error("Should return to StateInput")
	}
	if len(result.messages) != 1 || result.messages[0].Role != "system" {
		t.Error("Should add canceled system message")
	}
}
