// Package search composes the admin global search endpoint. The package
// itself does not own any storage — it defines a narrow Source interface
// that every searchable domain implements, and merges their results at
// the handler boundary. Adding a new entity to the /search result set is
// done by writing a new Source adapter and wiring it in cmd/app.
package search

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// Kind labels the origin entity of a Result so the wire consumer can
// route clicks and render the right badge. Values mirror the table /
// primary-slug vocabulary of each source.
type Kind string

const (
	KindContent    Kind = "content"
	KindNote       Kind = "note"
	KindBookmark   Kind = "bookmark"
	KindHypothesis Kind = "hypothesis"
	KindConcept    Kind = "concept"
	KindTask       Kind = "task"
	KindGoal       Kind = "goal"
	KindTodo       Kind = "todo"
	KindProject    Kind = "project"
)

// Result is a single hit surfaced by any Source. Score is a 0..1
// relevance number when the source can produce one (e.g. pg FTS rank);
// sources without a native score use 0 and order-of-return is preserved.
type Result struct {
	Type    Kind      `json:"type"`
	ID      uuid.UUID `json:"id"`
	Slug    string    `json:"slug,omitempty"`
	Title   string    `json:"title"`
	Excerpt string    `json:"excerpt,omitempty"`
	Score   float64   `json:"score"`
}

// Response wraps the flat result list. The envelope exists so the shape
// can widen (per-kind facets, total counts) without a breaking rename.
type Response struct {
	Results []Result `json:"results"`
}

// Source runs a lexical / semantic search over a single entity kind and
// returns matches in rank order (highest first). Implementations live
// in each domain package and are injected into the handler at wiring
// time — search has no import of any feature package.
type Source interface {
	// Kind returns the Kind tag stamped on every Result emitted by
	// this source.
	Kind() Kind

	// Search runs the query against the underlying store and returns
	// up to limit rows. A zero-result query MUST return an empty slice,
	// never nil, so the handler's merge step does not need nil guards.
	Search(ctx context.Context, query string, limit int) ([]Result, error)
}

// maxLimit caps the total number of rows returned to the client, no
// matter how many sources contribute. Individual sources are fed
// limit/N so no single kind dominates the envelope.
const maxLimit = 50

// LimitPerSource splits the client-requested limit across n sources so
// the response is balanced. Returns at least 1 per source when n > 0.
func LimitPerSource(total, n int) int {
	if n <= 0 || total <= 0 {
		return 0
	}
	per := total / n
	if per < 1 {
		return 1
	}
	return per
}

// HandlerFunc is the net/http adapter the router mounts. The search
// handler lives alongside these helpers in handler.go.
var _ http.Handler = http.HandlerFunc(nil)
