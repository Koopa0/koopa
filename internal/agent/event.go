package agent

// EventType represents the type of agent event.
type EventType int

const (
	EventTypeText EventType = iota
	EventTypeThought
	EventTypeInterrupt
	EventTypeError
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
