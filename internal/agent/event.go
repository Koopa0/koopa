package agent

// EventType represents the type of agent event.
type EventType int

// Event type constants
const (
	// EventTypeText represents a text chunk event
	EventTypeText EventType = iota
	// EventTypeThought represents a thought event
	EventTypeThought
	// EventTypeInterrupt represents an interrupt event
	EventTypeInterrupt
	// EventTypeError represents an error event
	EventTypeError
	// EventTypeComplete represents a completion event
	EventTypeComplete
)

// Event is the event emitted by Agent.Execute() through the event channel.
type Event struct {
	Type       EventType
	TextChunk  string
	Thought    string
	Interrupt  *InterruptEvent
	Error      error
	IsComplete bool
	Metadata   map[string]any
}
