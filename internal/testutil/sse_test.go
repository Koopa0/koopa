package testutil

import (
	"testing"
)

func TestParseSSEEvents_Basic(t *testing.T) {
	body := `event: chunk
data: Hello

event: done
data: Final

`
	events := ParseSSEEvents(t, body)

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Type != "chunk" {
		t.Errorf("expected first event type 'chunk', got %q", events[0].Type)
	}
	if events[0].Data != "Hello" {
		t.Errorf("expected first event data 'Hello', got %q", events[0].Data)
	}

	if events[1].Type != "done" {
		t.Errorf("expected second event type 'done', got %q", events[1].Type)
	}
	if events[1].Data != "Final" {
		t.Errorf("expected second event data 'Final', got %q", events[1].Data)
	}
}

func TestParseSSEEvents_MultilineData(t *testing.T) {
	body := `event: chunk
data: Line1
data: Line2
data: Line3

`
	events := ParseSSEEvents(t, body)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	expected := "Line1\nLine2\nLine3"
	if events[0].Data != expected {
		t.Errorf("expected data %q, got %q", expected, events[0].Data)
	}
}

func TestParseSSEEvents_DataBeforeEvent(t *testing.T) {
	// W3C SSE spec: data before event defaults to "message" event type
	body := `data: HelloWorld

`
	events := ParseSSEEvents(t, body)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Type != "message" {
		t.Errorf("expected event type 'message' (W3C default), got %q", events[0].Type)
	}
	if events[0].Data != "HelloWorld" {
		t.Errorf("expected data 'HelloWorld', got %q", events[0].Data)
	}
}

func TestParseSSEEvents_Comments(t *testing.T) {
	body := `event: chunk
: this is a comment
data: Hello

`
	events := ParseSSEEvents(t, body)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Data != "Hello" {
		t.Errorf("expected data 'Hello', got %q", events[0].Data)
	}
}

func TestParseSSEEvents_HTMLContent(t *testing.T) {
	body := `event: chunk
data: <div id="msg-content-123" hx-swap-oob="innerHTML">Hello</div>

`
	events := ParseSSEEvents(t, body)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	expected := `<div id="msg-content-123" hx-swap-oob="innerHTML">Hello</div>`
	if events[0].Data != expected {
		t.Errorf("expected data %q, got %q", expected, events[0].Data)
	}
}

func TestFindEvent(t *testing.T) {
	events := []SSEEvent{
		{Type: "chunk", Data: "data1"},
		{Type: "chunk", Data: "data2"},
		{Type: "done", Data: "final"},
	}

	// Find existing event
	found := FindEvent(events, "done")
	if found == nil {
		t.Fatal("expected to find 'done' event")
	}
	if found.Data != "final" {
		t.Errorf("expected data 'final', got %q", found.Data)
	}

	// Find non-existing event
	notFound := FindEvent(events, "error")
	if notFound != nil {
		t.Error("expected nil for non-existing event")
	}
}

func TestFindAllEvents(t *testing.T) {
	events := []SSEEvent{
		{Type: "chunk", Data: "data1"},
		{Type: "chunk", Data: "data2"},
		{Type: "done", Data: "final"},
	}

	chunks := FindAllEvents(events, "chunk")
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunk events, got %d", len(chunks))
	}

	done := FindAllEvents(events, "done")
	if len(done) != 1 {
		t.Fatalf("expected 1 done event, got %d", len(done))
	}

	errors := FindAllEvents(events, "error")
	if len(errors) != 0 {
		t.Fatalf("expected 0 error events, got %d", len(errors))
	}
}

// TestParseSSEEvents_IncompleteStream tests lenient mode handling of truncated streams
func TestParseSSEEvents_IncompleteStream(t *testing.T) {
	// Stream without trailing empty line - should still parse the event
	body := `event: chunk
data: Hello`

	events := ParseSSEEvents(t, body)

	if len(events) != 1 {
		t.Fatalf("expected 1 event from incomplete stream, got %d", len(events))
	}

	if events[0].Type != "chunk" {
		t.Errorf("expected event type 'chunk', got %q", events[0].Type)
	}
	if events[0].Data != "Hello" {
		t.Errorf("expected data 'Hello', got %q", events[0].Data)
	}
}

// TestParseSSEEvents_IncompleteStreamMultipleEvents tests partial stream with complete and incomplete events
func TestParseSSEEvents_IncompleteStreamMultipleEvents(t *testing.T) {
	// First event complete, second event missing trailing newline
	body := `event: chunk
data: First

event: chunk
data: Second`

	events := ParseSSEEvents(t, body)

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Data != "First" {
		t.Errorf("expected first data 'First', got %q", events[0].Data)
	}
	if events[1].Data != "Second" {
		t.Errorf("expected second data 'Second', got %q", events[1].Data)
	}
}

// TestParseSSEEvents_EventOnlyNoData tests event type without data (allowed per SSE spec)
func TestParseSSEEvents_EventOnlyNoData(t *testing.T) {
	body := `event: ping

`
	events := ParseSSEEvents(t, body)

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Type != "ping" {
		t.Errorf("expected event type 'ping', got %q", events[0].Type)
	}
	if events[0].Data != "" {
		t.Errorf("expected empty data, got %q", events[0].Data)
	}
}

// TestParseSSEEvents_EmptyInput tests that empty input returns no events
func TestParseSSEEvents_EmptyInput(t *testing.T) {
	events := ParseSSEEvents(t, "")

	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty input, got %d", len(events))
	}
}

// TestParseSSEEvents_CommentsOnly tests that comment-only stream returns no events
func TestParseSSEEvents_CommentsOnly(t *testing.T) {
	body := `: this is a comment
: another comment
`
	events := ParseSSEEvents(t, body)

	if len(events) != 0 {
		t.Fatalf("expected 0 events for comments-only stream, got %d", len(events))
	}
}

// TestParseSSEEvents_EmptyLinesOnly tests that empty lines are ignored
func TestParseSSEEvents_EmptyLinesOnly(t *testing.T) {
	body := `


`
	events := ParseSSEEvents(t, body)

	if len(events) != 0 {
		t.Fatalf("expected 0 events for empty-lines-only stream, got %d", len(events))
	}
}

func TestDiscardLogger(t *testing.T) {
	logger := DiscardLogger()
	if logger == nil {
		t.Fatal("DiscardLogger should not return nil")
	}

	// Should not panic when logging
	logger.Info("test message")
	logger.Error("error message")
}
