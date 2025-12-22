//go:build integration

package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/koopa0/koopa/internal/agent/chat"
)

func TestMain(m *testing.M) {
	// Filter out persistent goroutines:
	// - HTTP/2 connection goroutines from Google AI client
	// - OpenCensus stats worker (global singleton, can't be stopped)
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("net/http.(*http2clientConnReadLoop).run"),
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)
}

// createTestSession creates a session in the database and returns its ID and cleanup function.
func createTestSession(t *testing.T, setup *chatFlowSetup) (string, func()) {
	t.Helper()
	sess, err := setup.SessionStore.CreateSession(setup.Ctx, "test-session", "gemini-2.0-flash", "")
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}
	cleanup := func() {
		// Use background context for cleanup since test context may be canceled
		_ = setup.SessionStore.DeleteSession(context.Background(), sess.ID)
	}
	return sess.ID.String(), cleanup
}

func TestTUI_Integration_StartStream_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	setup, cleanup := setupChatFlow(t)
	defer cleanup()

	sessionID, sessionCleanup := createTestSession(t, setup)
	defer sessionCleanup()
	tui := New(setup.Ctx, setup.Flow, sessionID)

	// Start a stream with a simple query
	cmd := tui.startStream("Say hello in exactly 3 words")
	msg := cmd()

	startedMsg, ok := msg.(streamStartedMsg)
	if !ok {
		t.Fatalf("Expected streamStartedMsg, got %T", msg)
	}

	// Verify channels are initialized
	if startedMsg.textCh == nil {
		t.Error("textCh should not be nil")
	}
	if startedMsg.doneCh == nil {
		t.Error("doneCh should not be nil")
	}
	if startedMsg.errCh == nil {
		t.Error("errCh should not be nil")
	}
	if startedMsg.cancel == nil {
		t.Error("cancel should not be nil")
	}
	if startedMsg.done == nil {
		t.Error("done channel should not be nil")
	}

	// Collect stream output
	var chunks []string
	var finalOutput chat.Output
	var streamErr error

	// Listen for stream messages with timeout
	timeout := time.After(30 * time.Second)

streamLoop:
	for {
		select {
		case <-timeout:
			t.Fatal("Stream timed out")
		default:
			cmd := listenForStream(startedMsg.textCh, startedMsg.doneCh, startedMsg.errCh)
			msg := cmd()

			switch m := msg.(type) {
			case streamTextMsg:
				chunks = append(chunks, m.text)
			case streamDoneMsg:
				finalOutput = m.output
				break streamLoop
			case streamErrorMsg:
				streamErr = m.err
				break streamLoop
			case nil:
				break streamLoop
			}
		}
	}

	if streamErr != nil {
		t.Fatalf("Stream error: %v", streamErr)
	}

	// Verify we got some output
	if len(chunks) == 0 {
		t.Error("Expected at least one text chunk")
	}

	// Verify final output has content
	if finalOutput.Response == "" {
		t.Error("Expected non-empty response")
	}

	t.Logf("Received %d chunks, final response length: %d", len(chunks), len(finalOutput.Response))

	// Wait for goroutine cleanup
	select {
	case <-startedMsg.done:
		// Goroutine exited cleanly
	case <-time.After(5 * time.Second):
		t.Error("Goroutine did not exit within timeout")
	}
}

func TestTUI_Integration_StartStream_Cancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	setup, cleanup := setupChatFlow(t)
	defer cleanup()

	sessionID, sessionCleanup := createTestSession(t, setup)
	defer sessionCleanup()
	tui := New(setup.Ctx, setup.Flow, sessionID)

	// Start a stream with a long query
	cmd := tui.startStream("Write a very long story about a turtle. Make it at least 500 words.")
	msg := cmd()

	startedMsg, ok := msg.(streamStartedMsg)
	if !ok {
		t.Fatalf("Expected streamStartedMsg, got %T", msg)
	}

	// Wait for at least one chunk, then cancel
	chunksReceived := 0
	canceled := false
	timeout := time.After(30 * time.Second)

cancelLoop:
	for {
		select {
		case <-timeout:
			t.Fatal("Test timed out")
		default:
			cmd := listenForStream(startedMsg.textCh, startedMsg.doneCh, startedMsg.errCh)
			msg := cmd()

			switch msg.(type) {
			case streamTextMsg:
				chunksReceived++
				if chunksReceived >= 2 && !canceled {
					// Cancel after receiving some chunks
					startedMsg.cancel()
					canceled = true
				}
			case streamDoneMsg:
				t.Logf("Stream completed with %d chunks before cancellation took effect", chunksReceived)
				break cancelLoop
			case streamErrorMsg:
				t.Logf("Stream canceled after %d chunks", chunksReceived)
				break cancelLoop
			case nil:
				break cancelLoop
			}

			if chunksReceived > 100 {
				t.Fatal("Received too many chunks, cancellation may have failed")
			}
		}
	}

	// Wait for goroutine cleanup
	select {
	case <-startedMsg.done:
		// Goroutine exited cleanly
	case <-time.After(5 * time.Second):
		t.Error("Goroutine did not exit within timeout after cancellation")
	}
}

func TestTUI_Integration_HandleSubmit_StateTransition(t *testing.T) {
	// This test verifies handleSubmit properly transitions state and returns commands.
	// It doesn't test the full E2E flow (which is tested in StartStream tests).
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	setup, cleanup := setupChatFlow(t)
	defer cleanup()

	sessionID, sessionCleanup := createTestSession(t, setup)
	defer sessionCleanup()
	tui := New(setup.Ctx, setup.Flow, sessionID)

	// Set input value
	tui.input.SetValue("What is 2+2?")

	// Call handleSubmit
	model, cmd := tui.handleSubmit()
	result := model.(*TUI)

	// Verify state changed to thinking
	if result.state != StateThinking {
		t.Errorf("Expected StateThinking, got %v", result.state)
	}

	// Verify input was cleared
	if result.input.Value() != "" {
		t.Error("Input should be cleared after submit")
	}

	// Verify user message was added
	if len(result.messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(result.messages))
	}
	if result.messages[0].Role != "user" {
		t.Errorf("Expected user role, got %s", result.messages[0].Role)
	}

	// Verify history was updated
	if len(result.history) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(result.history))
	}

	// Verify command was returned (batch command for spinner + stream)
	if cmd == nil {
		t.Fatal("Expected command from handleSubmit")
	}

	// Cancel to cleanup
	result.cancelStream()
}

func TestTUI_Integration_ChannelLifecycle(t *testing.T) {
	// This test verifies channel behavior without API calls

	t.Run("normal completion", func(t *testing.T) {
		textCh := make(chan string, 10)
		doneCh := make(chan chat.Output, 1)

		// Pre-fill channels before starting to read (no goroutine needed)
		textCh <- "Hello"
		textCh <- " World"
		doneCh <- chat.Output{Response: "Hello World"}

		var chunks []string
		var finalOutput chat.Output

		// Read all text chunks first
		for {
			select {
			case text, ok := <-textCh:
				if !ok {
					goto checkDone
				}
				chunks = append(chunks, text)
			default:
				goto checkDone
			}
		}

	checkDone:
		// Now check for done
		select {
		case output := <-doneCh:
			finalOutput = output
		default:
			t.Error("Expected done message")
		}

		if len(chunks) != 2 {
			t.Errorf("Expected 2 chunks, got %d", len(chunks))
		}
		if finalOutput.Response != "Hello World" {
			t.Errorf("Expected 'Hello World', got %q", finalOutput.Response)
		}
	})

	t.Run("error before completion", func(t *testing.T) {
		textCh := make(chan string, 10)
		errCh := make(chan error, 1)

		// Pre-fill channels
		textCh <- "Partial"
		errCh <- context.Canceled

		var gotError bool
		var chunks []string

		// Read text chunks
		for {
			select {
			case text, ok := <-textCh:
				if !ok {
					goto checkErr
				}
				chunks = append(chunks, text)
			default:
				goto checkErr
			}
		}

	checkErr:
		// Check for error
		select {
		case err := <-errCh:
			gotError = true
			if err != context.Canceled {
				t.Errorf("Expected context.Canceled, got %v", err)
			}
		default:
			t.Error("Expected error message")
		}

		if !gotError {
			t.Error("Expected to receive error")
		}
		if len(chunks) != 1 {
			t.Errorf("Expected 1 chunk, got %d", len(chunks))
		}
	})

	t.Run("all channels closed without value", func(t *testing.T) {
		textCh := make(chan string)
		doneCh := make(chan chat.Output, 1)
		errCh := make(chan error, 1)

		close(textCh)
		close(doneCh)
		close(errCh)

		cmd := listenForStream(textCh, doneCh, errCh)
		msg := cmd()

		if msg != nil {
			t.Errorf("Expected nil for all closed channels, got %T", msg)
		}
	})
}

func TestTUI_Integration_ViewDuringStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	setup, cleanup := setupChatFlow(t)
	defer cleanup()

	sessionID, sessionCleanup := createTestSession(t, setup)
	defer sessionCleanup()
	tui := New(setup.Ctx, setup.Flow, sessionID)

	// Start streaming
	tui.input.SetValue("Tell me about Go programming")
	model, cmd := tui.handleSubmit()
	tui = model.(*TUI)

	// Call View during different states and verify no panic
	_ = tui.View()
	content := tui.viewBuf.String()
	if content == "" {
		t.Error("View content should not be empty during thinking")
	}
	if !strings.Contains(content, "Thinking") {
		t.Error("View should show thinking indicator")
	}

	// Process a few messages to get into streaming state
	for i := 0; i < 5 && cmd != nil; i++ {
		msg := cmd()
		if msg == nil {
			break
		}
		model, cmd = tui.Update(msg)
		tui = model.(*TUI)

		// View should work in any state
		_ = tui.View()
		viewContent := tui.viewBuf.String()
		if viewContent == "" {
			t.Errorf("View content should not be empty at iteration %d", i)
		}
	}

	// Cancel to clean up
	tui.cancelStream()
}
