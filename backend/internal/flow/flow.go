// Package flow defines AI processing flows for the content pipeline.
// Each flow uses Genkit Go for LLM interaction, tracing, and structured output.
// The flowrun.Runner dispatches jobs to flows via the Flow interface.
package flow

import (
	"context"
	"encoding/json"

	"github.com/firebase/genkit/go/core"
	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/collected"
)

// genkitFlow is a type alias for a Genkit flow that takes and returns raw JSON.
// Every concrete flow stores one of these, created via genkit.DefineFlow in its constructor.
type genkitFlow = core.Flow[json.RawMessage, json.RawMessage, struct{}]

// BudgetChecker checks whether token usage is within budget.
type BudgetChecker interface {
	Check(tokens int64) error
	Add(tokens int64)
}

// CollectedReader reads collected data by ID.
type CollectedReader interface {
	CollectedDataByID(ctx context.Context, id uuid.UUID) (*collected.CollectedData, error)
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
