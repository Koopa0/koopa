package tui

import (
	"context"
	"fmt"
	"log/slog"

	tea "charm.land/bubbletea/v2"

	"github.com/koopa0/koopa/internal/chat"
	"github.com/koopa0/koopa/internal/tools"
)

// streamBufferSize is sized for ~1.5s burst at 60 FPS refresh rate.
// This prevents backpressure during UI render delays while keeping
// memory bounded (100 strings ≈ 10KB typical).
const streamBufferSize = 100

// streamEvent is a discriminated union for all stream events.
// Using a single channel with union type simplifies select logic
// and eliminates complex multi-channel closure handling.
type streamEvent struct {
	// Exactly one of these fields is set per event
	text       string      // Text chunk (when non-empty)
	output     chat.Output // Final output (when done is true)
	err        error       // Error (when non-nil)
	done       bool        // True when stream completed successfully
	toolStatus string      // Tool status message (when non-empty, e.g. "搜尋網路中...")
}

// Stream message types for Bubble Tea
type streamStartedMsg struct {
	eventCh <-chan streamEvent
	cancel  context.CancelFunc
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

type streamToolMsg struct {
	status string
}

// tuiToolEmitter implements tools.Emitter for the TUI.
// Sends tool status through the stream event channel so Bubble Tea
// can display tool execution progress (e.g., "搜尋網路中...").
type tuiToolEmitter struct {
	eventCh chan<- streamEvent
}

func (e *tuiToolEmitter) OnToolStart(name string) {
	display := toolDisplayName(name)
	select {
	case e.eventCh <- streamEvent{toolStatus: display + "..."}:
	default: // best-effort: don't block if channel is full
	}
}

func (e *tuiToolEmitter) OnToolComplete(_ string) {
	select {
	case e.eventCh <- streamEvent{toolStatus: ""}:
	default:
	}
}

func (e *tuiToolEmitter) OnToolError(_ string) {
	select {
	case e.eventCh <- streamEvent{toolStatus: ""}:
	default:
	}
}

// Compile-time interface verification.
var _ tools.Emitter = (*tuiToolEmitter)(nil)

// startStream creates a command that initiates streaming.
// Directly uses *chat.Flow - no adapter needed.
//
// Goroutine lifecycle: The spawned goroutine exits when:
//  1. Stream completes normally (Done=true)
//  2. Context is canceled (cancel() called)
//  3. Error occurs
//
// Channel closure signals completion - no WaitGroup needed.
func (m *Model) startStream(query string) tea.Cmd {
	return func() tea.Msg {
		eventCh := make(chan streamEvent, streamBufferSize)

		// Create context with timeout to prevent indefinite hangs
		ctx, cancel := context.WithTimeout(m.ctx, streamTimeout)

		// Inject tool event emitter so tool status is shown in TUI
		ctx = tools.ContextWithEmitter(ctx, &tuiToolEmitter{eventCh: eventCh})

		go func() {
			// Ensure timer resources are released on all exit paths
			defer cancel()
			// Channel closure signals goroutine completion
			defer close(eventCh)

			// Panic recovery to prevent TUI lockup
			defer func() {
				if r := recover(); r != nil {
					slog.Error("stream panic recovered", "panic", r)
					select {
					case eventCh <- streamEvent{err: fmt.Errorf("stream panic: %v", r)}:
					default:
					}
				}
			}()

			var chunkCount int

			// Directly use chat.Flow's iterator (Go 1.23+ range-over-func)
			// Genkit's StreamingFlowValue has: {Stream.Text, Output, Done}
			for streamValue, err := range m.chatFlow.Stream(ctx, chat.Input{
				Query:     query,
				SessionID: m.sessionID.String(),
			}) {
				if err != nil {
					select {
					case eventCh <- streamEvent{err: fmt.Errorf("chunk %d: %w", chunkCount, err)}:
					case <-ctx.Done():
					}
					return
				}

				if streamValue.Done {
					select {
					case eventCh <- streamEvent{done: true, output: streamValue.Output}:
					case <-ctx.Done():
					}
					return
				}

				if streamValue.Stream.Text != "" {
					chunkCount++
					select {
					case eventCh <- streamEvent{text: streamValue.Stream.Text}:
					case <-ctx.Done():
						return
					}
				}
			}

			// CRITICAL: Guarantee completion signal if iterator exits without Done
			// This happens when: context canceled, zero chunks, or early termination
			err := ctx.Err()
			if err == nil {
				err = fmt.Errorf("stream ended unexpectedly without completion")
				slog.Warn("stream iterator exited without completion signal")
			}
			select {
			case eventCh <- streamEvent{err: err}:
			default:
			}
		}()

		return streamStartedMsg{
			eventCh: eventCh,
			cancel:  cancel,
		}
	}
}

// listenForStream creates a command to wait for next stream event.
// Uses single union channel - no complex multi-channel select needed.
// Empty events (all fields zero) are skipped via loop instead of recursion
// to prevent stack overflow under pathological conditions.
func listenForStream(eventCh <-chan streamEvent) tea.Cmd {
	return func() tea.Msg {
		if eventCh == nil {
			return nil
		}

		for {
			event, ok := <-eventCh
			if !ok {
				// Channel closed - stream ended
				return streamErrorMsg{err: fmt.Errorf("stream ended without completion signal")}
			}

			// Discriminated union dispatch
			switch {
			case event.err != nil:
				return streamErrorMsg{err: event.err}
			case event.done:
				return streamDoneMsg{output: event.output}
			case event.toolStatus != "":
				return streamToolMsg{status: event.toolStatus}
			case event.text != "":
				return streamTextMsg{text: event.text}
			default:
				// Empty event - loop instead of recursing
				continue
			}
		}
	}
}
