package testutil

import (
	"bufio"
	"strings"
	"testing"
)

// SSEEvent represents a parsed Server-Sent Event.
type SSEEvent struct {
	Type string // event: value
	Data string // data: value (multi-line joined with \n)
}

// ParseSSEEvents parses SSE event stream into structured events.
//
// Handles W3C SSE spec correctly:
//   - Multiple "data:" lines are joined with newline
//   - Empty line terminates an event
//   - data: before event: is allowed (defaults to "message" event type per W3C spec)
//   - Comments starting with ":" are ignored
//
// Example:
//
//	events := testutil.ParseSSEEvents(t, responseBody)
//	require.Len(t, events, 3)
//	assert.Equal(t, "chunk", events[0].Type)
func ParseSSEEvents(t *testing.T, body string) []SSEEvent {
	t.Helper()

	var events []SSEEvent
	scanner := bufio.NewScanner(strings.NewReader(body))

	var currentEvent SSEEvent
	var dataLines []string
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "event: "):
			if currentEvent.Type != "" && len(dataLines) > 0 {
				t.Fatalf("SSE parse error at line %d: new event before previous event terminated (got %q)", lineNum, line)
			}
			currentEvent.Type = strings.TrimPrefix(line, "event: ")

		case strings.HasPrefix(line, "data: "):
			// SSE spec: data before event is allowed (defaults to "message" event type)
			if currentEvent.Type == "" {
				currentEvent.Type = "message" // W3C SSE spec default
			}
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))

		case line == "":
			if currentEvent.Type != "" && len(dataLines) > 0 {
				// SSE spec: multiple data lines joined with \n
				currentEvent.Data = strings.Join(dataLines, "\n")
				events = append(events, currentEvent)
				currentEvent = SSEEvent{}
				dataLines = nil
			} else if currentEvent.Type != "" {
				// Event with no data - still valid per SSE spec
				events = append(events, currentEvent)
				currentEvent = SSEEvent{}
				dataLines = nil
			}

		default:
			// SSE allows comments starting with ":"
			if !strings.HasPrefix(line, ":") && line != "" {
				t.Fatalf("SSE parse error at line %d: unexpected SSE line: %q", lineNum, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("SSE scan error: %v", err)
	}

	if currentEvent.Type != "" {
		t.Fatalf("SSE stream ended without terminating event %q (missing empty line)", currentEvent.Type)
	}

	return events
}

// FindEvent finds an event by type in the parsed events.
// Returns nil if not found.
func FindEvent(events []SSEEvent, eventType string) *SSEEvent {
	for i := range events {
		if events[i].Type == eventType {
			return &events[i]
		}
	}
	return nil
}

// FindAllEvents finds all events of a given type.
func FindAllEvents(events []SSEEvent, eventType string) []SSEEvent {
	var found []SSEEvent
	for _, e := range events {
		if e.Type == eventType {
			found = append(found, e)
		}
	}
	return found
}
