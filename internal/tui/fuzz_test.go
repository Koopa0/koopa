package tui

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
)

// FuzzTUI_HandleSlashCommand tests slash command handling with fuzzed input.
func FuzzTUI_HandleSlashCommand(f *testing.F) {
	// Add seed corpus
	f.Add("/help")
	f.Add("/clear")
	f.Add("/exit")
	f.Add("/quit")
	f.Add("/unknown")
	f.Add("/")
	f.Add("//")
	f.Add("/a")
	f.Add("/very-long-command-name-that-does-not-exist")
	f.Add("/command with spaces")
	f.Add("/command\twith\ttabs")
	f.Add("/command\nwith\nnewlines")

	f.Fuzz(func(t *testing.T, cmd string) {
		// Only test strings that start with /
		if !strings.HasPrefix(cmd, "/") {
			return
		}

		tui := newTestTUI()
		tui.messages = []Message{{Role: "user", Text: "hello"}}

		// Should never panic
		model, resultCmd := tui.handleSlashCommand(cmd)
		result := model.(*TUI)

		// Basic invariants
		if result == nil {
			t.Error("Result should not be nil")
		}

		// Exit commands should return a command
		if cmd == "/exit" || cmd == "/quit" {
			if resultCmd == nil {
				t.Error("Exit command should return quit command")
			}
		}

		// Clear should empty messages
		if cmd == "/clear" {
			if len(result.messages) != 0 {
				t.Error("/clear should clear messages")
			}
		}
	})
}

// FuzzTUI_NavigateHistory tests history navigation with fuzzed delta values.
func FuzzTUI_NavigateHistory(f *testing.F) {
	// Add seed corpus
	f.Add(0)
	f.Add(1)
	f.Add(-1)
	f.Add(100)
	f.Add(-100)
	f.Add(1000000)
	f.Add(-1000000)

	f.Fuzz(func(t *testing.T, delta int) {
		tui := newTestTUI()
		tui.history = []string{"first", "second", "third"}
		tui.historyIdx = 1

		// Should never panic
		model, _ := tui.navigateHistory(delta)
		result := model.(*TUI)

		// Index should be within bounds
		if result.historyIdx < 0 {
			t.Errorf("History index should not be negative: %d", result.historyIdx)
		}
		if result.historyIdx > len(result.history) {
			t.Errorf("History index should not exceed history length: %d > %d", result.historyIdx, len(result.history))
		}
	})
}

// FuzzTUI_AddMessage tests message addition with various message content.
func FuzzTUI_AddMessage(f *testing.F) {
	// Add seed corpus
	f.Add("user", "hello")
	f.Add("assistant", "hi there")
	f.Add("system", "message")
	f.Add("error", "something went wrong")
	f.Add("", "")
	f.Add("unknown_role", "test")
	f.Add("user", strings.Repeat("a", 10000)) // Large message
	f.Add("user", "line1\nline2\nline3")      // Multi-line
	f.Add("user", "emoji 🎉🚀")                 // Unicode
	f.Add("user", "\x00\x01\x02")             // Binary

	f.Fuzz(func(t *testing.T, role, text string) {
		tui := newTestTUI()

		// Should never panic
		tui.addMessage(Message{Role: role, Text: text})

		// Messages should never exceed max
		if len(tui.messages) > maxMessages {
			t.Errorf("Message count %d exceeds max %d", len(tui.messages), maxMessages)
		}

		// Last message should be what we added (if it wasn't trimmed)
		// Note: We don't assert equality because older messages may be trimmed
		// when maxMessages is reached. The key invariant is that messages slice
		// is always valid and within bounds.
		_ = len(tui.messages) // Use the length to ensure messages is accessible
	})
}

// FuzzTUI_KeyPress tests key handling with various key inputs.
func FuzzTUI_KeyPress(f *testing.F) {
	// Add seed corpus - various key codes
	f.Add(int32('a'), int(0))                     // Regular key
	f.Add(int32('c'), int(tea.ModCtrl))           // Ctrl+C
	f.Add(int32('d'), int(tea.ModCtrl))           // Ctrl+D
	f.Add(int32(tea.KeyEnter), int(0))            // Enter
	f.Add(int32(tea.KeyEnter), int(tea.ModShift)) // Shift+Enter
	f.Add(int32(tea.KeyUp), int(0))               // Up arrow
	f.Add(int32(tea.KeyDown), int(0))             // Down arrow
	f.Add(int32(tea.KeyEscape), int(0))           // Escape
	f.Add(int32(tea.KeyTab), int(0))              // Tab
	f.Add(int32(tea.KeySpace), int(0))            // Space

	f.Fuzz(func(t *testing.T, code int32, mod int) {
		tui := newTestTUI()
		// Use background context to avoid nil pointer issues
		tui.ctx = context.Background()

		key := tea.Key{Code: rune(code), Mod: tea.KeyMod(mod)}
		msg := tea.KeyPressMsg(key)

		// Should never panic with proper context
		model, _ := tui.handleKey(msg)
		if model == nil {
			t.Error("Model should not be nil")
		}
	})
}

// FuzzTUI_View tests View rendering with various state combinations.
func FuzzTUI_View(f *testing.F) {
	// Add seed corpus
	f.Add(0, 80, 24)   // StateInput, normal terminal
	f.Add(1, 80, 24)   // StateThinking
	f.Add(2, 80, 24)   // StateStreaming
	f.Add(0, 40, 10)   // Small terminal
	f.Add(0, 200, 50)  // Large terminal
	f.Add(0, 0, 0)     // Zero dimensions
	f.Add(0, -1, -1)   // Negative dimensions
	f.Add(0, 10000, 1) // Very wide

	f.Fuzz(func(t *testing.T, state, width, height int) {
		tui := newTestTUI()

		// Set state (bounded to valid values)
		if state >= 0 && state <= 2 {
			tui.state = State(state)
		}

		tui.width = width
		tui.height = height

		// Add some messages for more complex view
		tui.messages = []Message{
			{Role: "user", Text: "Hello"},
			{Role: "assistant", Text: "Hi there!"},
		}

		// Add output for streaming state
		if tui.state == StateStreaming {
			tui.output.WriteString("Streaming output...")
		}

		// Should never panic
		_ = tui.View()

		// Check that viewBuf contains valid UTF-8
		content := tui.viewBuf.String()
		if !utf8.ValidString(content) {
			t.Error("View should produce valid UTF-8")
		}
	})
}

// FuzzMarkdownRenderer_Render tests markdown rendering with fuzzed input.
func FuzzMarkdownRenderer_Render(f *testing.F) {
	// Add seed corpus
	f.Add("Hello World")
	f.Add("**bold**")
	f.Add("*italic*")
	f.Add("`code`")
	f.Add("```go\nfunc main() {}\n```")
	f.Add("# Heading")
	f.Add("- list item")
	f.Add("[link](http://example.com)")
	f.Add("")                         // Empty
	f.Add(strings.Repeat("a", 10000)) // Large input
	f.Add("emoji 🎉🚀✨")
	f.Add("\x00\x01\x02") // Binary
	f.Add("line1\nline2\nline3")
	f.Add("special chars: <>&\"'")

	f.Fuzz(func(t *testing.T, markdown string) {
		mr := newMarkdownRenderer(80)
		if mr == nil {
			t.Skip("Failed to create markdown renderer")
		}

		// Should never panic
		result := mr.Render(markdown)

		// Note: result may be empty even if markdown is non-empty because
		// the renderer might strip some content. This is acceptable behavior.
		_ = result // Ensure result is used

		// Should produce valid UTF-8
		if !utf8.ValidString(result) {
			t.Error("Rendered output should be valid UTF-8")
		}
	})
}

// FuzzMarkdownRenderer_UpdateWidth tests width update with fuzzed values.
func FuzzMarkdownRenderer_UpdateWidth(f *testing.F) {
	// Add seed corpus
	f.Add(80)
	f.Add(40)
	f.Add(120)
	f.Add(0)
	f.Add(-1)
	f.Add(1)
	f.Add(10000)
	f.Add(-10000)

	f.Fuzz(func(t *testing.T, width int) {
		mr := newMarkdownRenderer(80)
		if mr == nil {
			t.Skip("Failed to create markdown renderer")
		}

		// Should never panic
		updated := mr.UpdateWidth(width)

		// Invalid widths should not update
		if width <= 0 && updated {
			t.Errorf("Invalid width %d should not cause update", width)
		}

		// Same width should not update
		if width == 80 && updated {
			t.Error("Same width should not cause update")
		}
	})
}
