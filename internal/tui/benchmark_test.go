package tui

import (
	"context"
	"strings"
	"testing"

	"charm.land/bubbles/v2/textarea"
	tea "charm.land/bubbletea/v2"

	"github.com/koopa0/koopa/internal/chat"
)

// newBenchmarkModel creates a Model for benchmarking with minimal setup.
func newBenchmarkModel() *Model {
	ta := textarea.New()
	ta.SetHeight(3)
	ta.ShowLineNumbers = false
	return &Model{
		state:    StateInput,
		input:    ta,
		history:  make([]string, 0, maxHistory),
		messages: make([]Message, 0, maxMessages),
		styles:   DefaultStyles(),
		markdown: newMarkdownRenderer(80),
		width:    80,
		height:   24,
		ctx:      context.Background(),
	}
}

// BenchmarkTUI_View measures View rendering performance.
func BenchmarkTUI_View(b *testing.B) {
	b.Run("empty", func(b *testing.B) {
		tui := newBenchmarkModel()
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})

	b.Run("10_messages", func(b *testing.B) {
		tui := newBenchmarkModel()
		for i := 0; i < 10; i++ {
			tui.addMessage(Message{Role: "user", Text: "Hello, this is a test message"})
			tui.addMessage(Message{Role: "assistant", Text: "This is a response with some content"})
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})

	b.Run("50_messages", func(b *testing.B) {
		tui := newBenchmarkModel()
		for i := 0; i < 50; i++ {
			tui.addMessage(Message{Role: "user", Text: "Hello, this is a test message"})
			tui.addMessage(Message{Role: "assistant", Text: "This is a response with some content"})
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})

	b.Run("max_messages", func(b *testing.B) {
		tui := newBenchmarkModel()
		for i := 0; i < maxMessages; i++ {
			tui.addMessage(Message{Role: "user", Text: "Hello, this is a test message with some longer content to simulate real usage"})
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})

	b.Run("streaming_state", func(b *testing.B) {
		tui := newBenchmarkModel()
		tui.state = StateStreaming
		tui.output.WriteString("This is streaming output that is being written in real-time...")
		for i := 0; i < 10; i++ {
			tui.addMessage(Message{Role: "user", Text: "Hello"})
			tui.addMessage(Message{Role: "assistant", Text: "Response"})
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})

	b.Run("thinking_state", func(b *testing.B) {
		tui := newBenchmarkModel()
		tui.state = StateThinking
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})

	b.Run("large_messages", func(b *testing.B) {
		tui := newBenchmarkModel()
		largeText := strings.Repeat("This is a large message with lots of content. ", 100)
		for i := 0; i < 20; i++ {
			tui.addMessage(Message{Role: "assistant", Text: largeText})
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = tui.View()
		}
	})
}

// BenchmarkTUI_AddMessage measures message addition performance.
func BenchmarkTUI_AddMessage(b *testing.B) {
	b.Run("single", func(b *testing.B) {
		tui := newBenchmarkModel()
		msg := Message{Role: "user", Text: "Hello"}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			tui.messages = tui.messages[:0] // Reset to avoid bounds trimming
			tui.addMessage(msg)
		}
	})

	b.Run("with_bounds_check", func(b *testing.B) {
		tui := newBenchmarkModel()
		// Pre-fill to near capacity
		for i := 0; i < maxMessages-1; i++ {
			tui.messages = append(tui.messages, Message{Role: "user", Text: "test"})
		}
		msg := Message{Role: "user", Text: "Hello"}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			tui.addMessage(msg)
			// Remove one to stay near capacity
			if len(tui.messages) > maxMessages-1 {
				tui.messages = tui.messages[1:]
			}
		}
	})

	b.Run("at_capacity", func(b *testing.B) {
		tui := newBenchmarkModel()
		// Fill to capacity
		for i := 0; i < maxMessages; i++ {
			tui.messages = append(tui.messages, Message{Role: "user", Text: "test"})
		}
		msg := Message{Role: "user", Text: "Hello"}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			tui.addMessage(msg)
		}
	})
}

// BenchmarkTUI_Update measures Update loop performance.
func BenchmarkTUI_Update(b *testing.B) {
	b.Run("key_press", func(b *testing.B) {
		tui := newBenchmarkModel()
		key := tea.Key{Code: 'a'}
		msg := tea.KeyPressMsg(key)
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			model, _ := tui.Update(msg)
			tui = model.(*Model)
		}
	})

	b.Run("window_resize", func(b *testing.B) {
		tui := newBenchmarkModel()
		msg := tea.WindowSizeMsg{Width: 120, Height: 40}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			model, _ := tui.Update(msg)
			tui = model.(*Model)
		}
	})

	b.Run("stream_text_msg", func(b *testing.B) {
		tui := newBenchmarkModel()
		tui.state = StateStreaming
		eventCh := make(chan streamEvent, 1)
		tui.streamEventCh = eventCh

		msg := streamTextMsg{text: "Hello "}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			model, _ := tui.Update(msg)
			tui = model.(*Model)
			tui.output.Reset() // Reset to avoid unbounded growth
		}
	})
}

// BenchmarkTUI_NavigateHistory measures history navigation performance.
func BenchmarkTUI_NavigateHistory(b *testing.B) {
	b.Run("small_history", func(b *testing.B) {
		tui := newBenchmarkModel()
		tui.history = []string{"one", "two", "three"}
		tui.historyIdx = 1
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			model, _ := tui.navigateHistory(-1)
			tui = model.(*Model)
			if tui.historyIdx == 0 {
				tui.historyIdx = len(tui.history)
			}
		}
	})

	b.Run("large_history", func(b *testing.B) {
		tui := newBenchmarkModel()
		for i := 0; i < maxHistory; i++ {
			tui.history = append(tui.history, "history entry "+string(rune('a'+i%26)))
		}
		tui.historyIdx = maxHistory / 2
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			model, _ := tui.navigateHistory(-1)
			tui = model.(*Model)
			if tui.historyIdx == 0 {
				tui.historyIdx = len(tui.history)
			}
		}
	})
}

// BenchmarkMarkdownRenderer measures markdown rendering performance.
func BenchmarkMarkdownRenderer(b *testing.B) {
	b.Run("short_text", func(b *testing.B) {
		mr := newMarkdownRenderer(80)
		text := "Hello **world**!"
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = mr.Render(text)
		}
	})

	b.Run("code_block", func(b *testing.B) {
		mr := newMarkdownRenderer(80)
		text := "```go\nfunc main() {\n\tfmt.Println(\"Hello\")\n}\n```"
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = mr.Render(text)
		}
	})

	b.Run("long_text", func(b *testing.B) {
		mr := newMarkdownRenderer(80)
		text := strings.Repeat("This is a paragraph with **bold** and *italic* text. ", 50)
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = mr.Render(text)
		}
	})

	b.Run("complex_markdown", func(b *testing.B) {
		mr := newMarkdownRenderer(80)
		text := `# Heading 1

This is a paragraph with **bold** and *italic* text.

## Heading 2

- List item 1
- List item 2
- List item 3

` + "```go\nfunc main() {\n\tfmt.Println(\"Hello\")\n}\n```" + `

> This is a blockquote

[Link](http://example.com)
`
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = mr.Render(text)
		}
	})

	b.Run("update_width", func(b *testing.B) {
		mr := newMarkdownRenderer(80)
		widths := []int{80, 120, 40, 100, 60}
		b.ResetTimer()
		b.ReportAllocs()
		for i := range b.N {
			mr.UpdateWidth(widths[i%len(widths)])
		}
	})
}

// BenchmarkListenForStream measures stream listening performance.
func BenchmarkListenForStream(b *testing.B) {
	b.Run("text_event", func(b *testing.B) {
		eventCh := make(chan streamEvent, 1)

		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			eventCh <- streamEvent{text: "Hello"}
			cmd := listenForStream(eventCh)
			_ = cmd()
		}
	})

	b.Run("done_event", func(b *testing.B) {
		eventCh := make(chan streamEvent, 1)

		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			eventCh <- streamEvent{done: true, output: chat.Output{Response: "done"}}
			cmd := listenForStream(eventCh)
			_ = cmd()
		}
	})

	b.Run("nil_channel", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			cmd := listenForStream(nil)
			_ = cmd()
		}
	})
}

// BenchmarkStyles measures style rendering performance.
func BenchmarkStyles(b *testing.B) {
	b.Run("render_banner", func(b *testing.B) {
		styles := DefaultStyles()
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = styles.RenderBanner()
		}
	})

	b.Run("render_welcome_tips", func(b *testing.B) {
		styles := DefaultStyles()
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = styles.RenderWelcomeTips()
		}
	})

	b.Run("default_styles", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = DefaultStyles()
		}
	})
}

// BenchmarkTUI_HandleSlashCommand measures slash command handling performance.
func BenchmarkTUI_HandleSlashCommand(b *testing.B) {
	b.Run("help", func(b *testing.B) {
		tui := newBenchmarkModel()
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			tui.messages = tui.messages[:0] // Reset messages
			model, _ := tui.handleSlashCommand("/help")
			tui = model.(*Model)
		}
	})

	b.Run("clear", func(b *testing.B) {
		tui := newBenchmarkModel()
		for i := 0; i < 10; i++ {
			tui.addMessage(Message{Role: "user", Text: "test"})
		}
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			tui.messages = []Message{{Role: "user", Text: "test"}}
			model, _ := tui.handleSlashCommand("/clear")
			tui = model.(*Model)
		}
	})

	b.Run("unknown", func(b *testing.B) {
		tui := newBenchmarkModel()
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			tui.messages = tui.messages[:0]
			model, _ := tui.handleSlashCommand("/unknown")
			tui = model.(*Model)
		}
	})
}
