// Package ai defines AI processing flows for the content pipeline.
// Each flow uses Genkit Go for LLM interaction, tracing, and structured output.
// The exec.Runner dispatches jobs to flows via the Flow interface.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	genkitai "github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/core"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed/entry"
	"github.com/koopa0/blog-backend/internal/project"
)

// ErrContentBlocked indicates the model refused to generate due to safety or policy filters.
// This is a permanent failure — retrying will not help.
var ErrContentBlocked = errors.New("content blocked by model safety filter")

// CheckFinishReason returns ErrContentBlocked if the model response was blocked
// by safety filters. FinishReasonLength (MaxOutputTokens hit) is intentionally
// NOT treated as an error — many flows use small token limits by design
// (e.g. excerpt generation). Notification truncation is prevented by setting
// adequate MaxOutputTokens (2048) in those flows.
// Exported for use by sub-packages.
func CheckFinishReason(resp *genkitai.ModelResponse) error {
	if resp == nil {
		return nil
	}
	switch resp.FinishReason {
	case genkitai.FinishReasonBlocked:
		return fmt.Errorf("%w: %s", ErrContentBlocked, resp.FinishMessage)
	case genkitai.FinishReasonOther:
		return fmt.Errorf("%w: unexpected finish reason: %s", ErrContentBlocked, resp.FinishMessage)
	default:
		return nil
	}
}

// GenkitFlow is a type alias for a Genkit flow that takes and returns raw JSON.
// Every concrete flow stores one of these, created via genkit.DefineFlow in its constructor.
// Exported for use by sub-packages.
type GenkitFlow = core.Flow[json.RawMessage, json.RawMessage, struct{}]

// CollectedReader reads collected items by ID.
type CollectedReader interface {
	Item(ctx context.Context, id uuid.UUID) (*entry.Item, error)
}

// PublishedContentLister lists published contents in a date range.
type PublishedContentLister interface {
	PublishedByDateRange(ctx context.Context, start, end time.Time) ([]content.Content, error)
}

// RecentCollectedLister lists recently collected data in a date range.
type RecentCollectedLister interface {
	RecentCollectedData(ctx context.Context, start, end time.Time, limit int32) ([]entry.Item, error)
}

// ActiveProjectLister lists active projects.
type ActiveProjectLister interface {
	ActiveProjects(ctx context.Context) ([]project.Project, error)
}

// Sender sends a text notification.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// Flow executes a named AI processing pipeline.
// Each concrete flow struct implements this interface directly,
// handling its own JSON marshaling (same pattern as http.Handler).
type Flow interface {
	Name() string
	Run(ctx context.Context, input json.RawMessage) (json.RawMessage, error)
}

// Registry maps flow names to Flow implementations.
type Registry struct {
	flows map[string]Flow
}

// NewRegistry returns a Registry with the given flows.
func NewRegistry(flows ...Flow) *Registry {
	r := &Registry{flows: make(map[string]Flow, len(flows))}
	for _, f := range flows {
		r.flows[f.Name()] = f
	}
	return r
}

// Flow returns the flow for the given name, or nil if not found.
func (r *Registry) Flow(name string) Flow {
	return r.flows[name]
}

// mockFlow implements Flow with canned responses for MOCK_MODE.
type mockFlow struct {
	name   string
	output any
}

// Name returns the flow name for registry lookup.
func (m *mockFlow) Name() string { return m.name }

// Run returns the canned output as JSON.
func (m *mockFlow) Run(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(m.output)
}
