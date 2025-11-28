package tui

import (
	"context"
	"fmt"
	"log/slog"

	tea "charm.land/bubbletea/v2"

	"github.com/koopa0/koopa-cli/internal/agent/chat"
)

// streamBufferSize is sized for ~1.5s burst at 60 FPS refresh rate.
// This prevents backpressure during UI render delays while keeping
// memory bounded (100 strings ≈ 10KB typical).
const streamBufferSize = 100

// Stream message types
type streamStartedMsg struct {
	textCh <-chan string
	doneCh <-chan chat.Output
	errCh  <-chan error
	cancel context.CancelFunc
	done   chan struct{} // Signals goroutine exit
}

type streamTextMsg struct {
	text string
}

type streamDoneMsg struct {
	output chat.Output
}

type streamErrorMsg struct {
	err error
}

// startStream creates a command that initiates streaming.
// Directly uses *chat.Flow - no adapter needed.
//
// Goroutine lifecycle: The spawned goroutine exits when:
//  1. Stream completes normally (Done=true)
//  2. Context is cancelled (cancel() called)
//  3. Error occurs
//
// Channel closure signals completion - no WaitGroup needed.
func (t *TUI) startStream(query string) tea.Cmd {
	return func() tea.Msg {
		textCh := make(chan string, streamBufferSize)
		doneCh := make(chan chat.Output, 1)
		errCh := make(chan error, 1)
		done := make(chan struct{})

		// Create context with timeout to prevent indefinite hangs
		ctx, cancel := context.WithTimeout(t.ctx, streamTimeout)

		go func() {
			// Ensure timer resources are released on all exit paths
			defer cancel()
			// Panic recovery to prevent TUI lockup
			defer func() {
				if r := recover(); r != nil {
					slog.Error("stream panic recovered", "panic", r)
					select {
					case errCh <- fmt.Errorf("stream panic: %v", r):
					default:
					}
				}
			}()

			// Signal goroutine exit for cleanup
			defer close(done)

			// Channel closure signals goroutine completion
			defer close(textCh)
			defer close(doneCh)
			defer close(errCh)

			var chunkCount int

			// Directly use chat.Flow's iterator (Go 1.23+ range-over-func)
			// Genkit's StreamingFlowValue has: {Stream.Text, Output, Done}
			for streamValue, err := range t.chatFlow.Stream(ctx, chat.Input{
				Query:     query,
				SessionID: t.sessionID,
			}) {
				if err != nil {
					select {
					case errCh <- fmt.Errorf("chunk %d: %w", chunkCount, err):
					case <-ctx.Done():
					}
					return // Error sent, exit immediately
				}

				if streamValue.Done {
					select {
					case doneCh <- streamValue.Output:
					case <-ctx.Done():
					}
					return // Completion sent, exit immediately
				}

				if streamValue.Stream.Text != "" {
					chunkCount++
					select {
					case textCh <- streamValue.Stream.Text:
					case <-ctx.Done():
						return
					}
				}
			}

			// CRITICAL: Guarantee completion signal if iterator exits without Done
			// This happens when: context cancelled, zero chunks, or early termination
			// If we reach here, the iterator exited without sending Done or error
			{
				err := ctx.Err()
				if err == nil {
					// Iterator exited without error and without Done - unexpected
					err = fmt.Errorf("stream ended unexpectedly without completion")
					slog.Warn("stream iterator exited without completion signal")
				}
				select {
				case errCh <- err:
				default:
					// Channel full - should not happen with buffered channel
				}
			}
		}()

		return streamStartedMsg{
			textCh: textCh,
			doneCh: doneCh,
			errCh:  errCh,
			cancel: cancel,
			done:   done,
		}
	}
}

// listenForStream creates a command to wait for next stream message.
// Handles channel closure correctly by checking ok values.
//
// Design: When textCh closes, we block on doneCh/errCh to get the final result.
// The goroutine always sends to doneCh OR errCh before exiting, so this is safe.
func listenForStream(textCh <-chan string, doneCh <-chan chat.Output, errCh <-chan error) tea.Cmd {
	return func() tea.Msg {
		// Nil channel check - if channels are nil, stream has ended
		if textCh == nil && doneCh == nil && errCh == nil {
			return nil
		}

		select {
		case text, ok := <-textCh:
			if !ok {
				// textCh closed - block on doneCh/errCh for final result
				// Goroutine guarantees one of these will receive a value
				select {
				case output, ok := <-doneCh:
					if ok {
						return streamDoneMsg{output: output}
					}
				case err, ok := <-errCh:
					if ok {
						return streamErrorMsg{err: err}
					}
				}
				// Both channels closed without values - protocol violation
				// Return error to prevent UI deadlock
				return streamErrorMsg{err: fmt.Errorf("stream ended without completion signal")}
			}
			return streamTextMsg{text: text}

		case output, ok := <-doneCh:
			if ok {
				return streamDoneMsg{output: output}
			}
			// doneCh closed without value - wait for errCh
			select {
			case err, ok := <-errCh:
				if ok {
					return streamErrorMsg{err: err}
				}
			default:
			}
			return streamErrorMsg{err: fmt.Errorf("stream completed without result")}

		case err, ok := <-errCh:
			if ok {
				return streamErrorMsg{err: err}
			}
			// errCh closed without value - wait for doneCh
			select {
			case output, ok := <-doneCh:
				if ok {
					return streamDoneMsg{output: output}
				}
			default:
			}
			return streamErrorMsg{err: fmt.Errorf("stream error channel closed unexpectedly")}
		}
	}
}
