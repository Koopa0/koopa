// agent_note.go holds the write_agent_note and query_agent_notes MCP
// tools. These operate on the internal/agent/note Zettelkasten-adjacent
// runtime log — plans, context snapshots, reflections — NOT on
// Zettelkasten notes (those live on internal/note and are managed by
// create_note / update_note / update_note_maturity in note.go).
//
// Vocabulary split (.claude/rules/mcp-decision-policy.md §4):
//   - agent_note = runtime narrative log (this file)
//   - note       = long-term knowledge artifact (note.go)
//
// A bare "note" in code review or a handler is ambiguous — always
// qualify.

package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
)

// queryAgentNotesDefaultWindow is the default lookback for query_agent_notes
// when the caller doesn't supply `since`. Ninety days covers the
// practitioner's typical "recent reflections" horizon without pulling
// lifetime notes on every call.
const queryAgentNotesDefaultWindow = 90 * 24 * time.Hour

// derefString returns *p or "" when p is nil. Used in log lines so nil
// *string fields print as empty instead of a memory address.
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// queryAgentNotesDefaultLimit / queryAgentNotesMaxLimit bound the result
// slice. Ninety days of notes at normal write cadence fits well inside
// the default; the hard cap prevents an accidental unbounded dump if the
// caller passes a pathological value.
const queryAgentNotesDefaultLimit = 50
const queryAgentNotesMaxLimit = 200

// WriteAgentNoteInput is the input for the write_agent_note tool.
type WriteAgentNoteInput struct {
	Kind     string         `json:"kind" jsonschema:"required" jsonschema_description:"Entry kind: plan, context, or reflection"`
	Content  string         `json:"content" jsonschema:"required" jsonschema_description:"Agent note content (markdown)"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema_description:"Per-kind structured metadata. plan: {reasoning}. context/reflection: freeform."`
}

// WriteAgentNoteOutput is the output of the write_agent_note tool.
type WriteAgentNoteOutput struct {
	Entry agentnote.Note `json:"entry"`
}

func (s *Server) writeAgentNote(ctx context.Context, _ *mcp.CallToolRequest, input WriteAgentNoteInput) (*mcp.CallToolResult, WriteAgentNoteOutput, error) {
	if input.Content == "" {
		return nil, WriteAgentNoteOutput{}, fmt.Errorf("content is required")
	}

	kind := agentnote.Kind(input.Kind)
	switch kind {
	case agentnote.KindPlan, agentnote.KindContext, agentnote.KindReflection:
	default:
		return nil, WriteAgentNoteOutput{}, fmt.Errorf("invalid kind %q (valid: plan, context, reflection)", input.Kind)
	}

	entry, err := s.agentNotes.Create(ctx, &agentnote.CreateParams{
		Kind:      kind,
		CreatedBy: s.callerIdentity(ctx),
		Content:   input.Content,
		Metadata:  input.Metadata,
		EntryDate: s.today(),
	})
	if err != nil {
		return nil, WriteAgentNoteOutput{}, fmt.Errorf("creating agent note: %w", err)
	}

	s.logger.Info("write_agent_note", "kind", kind, "id", entry.ID)
	return nil, WriteAgentNoteOutput{Entry: *entry}, nil
}

// QueryAgentNotesInput is the input for query_agent_notes. Every filter is
// optional. Missing date bounds resolve to [now-90d, today]; missing kind
// / author return all rows in the window. Limit bounds at 200 regardless
// of caller input. When query is non-empty the server filters by FTS
// predicate; in both paths rows come back ordered by entry_date DESC then
// created_at DESC (FTS path uses ts_rank as a final same-day tiebreaker).
type QueryAgentNotesInput struct {
	Query  *string `json:"query,omitempty"  jsonschema_description:"Full-text search over content. Uses websearch_to_tsquery syntax — quotes, AND/OR/NOT. When set, the FTS predicate filters matches; rows still come back ordered by entry_date DESC with ts_rank as same-day tiebreaker (the 'what did I most recently write about X' model)."`
	Kind   *string `json:"kind,omitempty"   jsonschema_description:"Filter by kind: plan, context, reflection"`
	Since  *string `json:"since,omitempty"  jsonschema_description:"YYYY-MM-DD inclusive. Default: 90 days ago."`
	Until  *string `json:"until,omitempty"  jsonschema_description:"YYYY-MM-DD inclusive. Default: today."`
	Author *string `json:"author,omitempty" jsonschema_description:"Agent name filter (learning-studio, hq, koopa0-dev, ...)"`
	Limit  FlexInt `json:"limit,omitempty"  jsonschema_description:"Max results, 1..200. Default 50."`
}

// QueryAgentNotesOutput ships the matched rows newest-first. Truncated is
// true when the underlying store returned more rows than limit; callers
// can narrow the window or bump limit to see the tail.
type QueryAgentNotesOutput struct {
	Notes     []agentnote.Note `json:"notes"`
	Total     int              `json:"total"`
	Truncated bool             `json:"truncated,omitempty"`
}

// parseDateOr parses an optional YYYY-MM-DD date, returning fallback when
// p is nil or empty. Errors propagate to the caller with label (e.g.
// "since"/"until") for contextual messages.
func parseDateOr(p *string, fallback time.Time, label string) (time.Time, error) {
	if p == nil || *p == "" {
		return fallback, nil
	}
	t, err := time.Parse(time.DateOnly, *p)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s: %w", label, err)
	}
	return t, nil
}

func (s *Server) queryAgentNotes(ctx context.Context, _ *mcp.CallToolRequest, input QueryAgentNotesInput) (*mcp.CallToolResult, QueryAgentNotesOutput, error) {
	today := s.today()

	since, err := parseDateOr(input.Since, today.Add(-queryAgentNotesDefaultWindow), "since")
	if err != nil {
		return nil, QueryAgentNotesOutput{}, err
	}
	until, err := parseDateOr(input.Until, today, "until")
	if err != nil {
		return nil, QueryAgentNotesOutput{}, err
	}
	if since.After(until) {
		return nil, QueryAgentNotesOutput{}, fmt.Errorf("since (%s) must not be after until (%s)", since.Format(time.DateOnly), until.Format(time.DateOnly))
	}

	var kindFilter *agentnote.Kind
	if input.Kind != nil && *input.Kind != "" {
		k := agentnote.Kind(*input.Kind)
		switch k {
		case agentnote.KindPlan, agentnote.KindContext, agentnote.KindReflection:
			kindFilter = &k
		default:
			return nil, QueryAgentNotesOutput{}, fmt.Errorf("invalid kind %q (valid: plan, context, reflection)", *input.Kind)
		}
	}

	var authorFilter *string
	if input.Author != nil && *input.Author != "" {
		v := *input.Author
		authorFilter = &v
	}

	limit := clamp(int(input.Limit), 1, queryAgentNotesMaxLimit, queryAgentNotesDefaultLimit)

	// Query param switches between chronological listing and full-text
	// search. Both paths respect the same filters (kind, author, date
	// window); only the ordering and row-selection predicate differ.
	var notes []agentnote.Note
	if input.Query != nil && *input.Query != "" {
		// Search returns up to limit rows already ranked — no over-fetch
		// needed, so truncated stays false unless the store has more than
		// limit matches (LIMIT is applied in SQL).
		notes, err = s.agentNotes.Search(ctx, *input.Query, since, until, kindFilter, authorFilter, limit)
	} else {
		notes, err = s.agentNotes.NotesInRange(ctx, since, until, kindFilter, authorFilter)
	}
	if err != nil {
		return nil, QueryAgentNotesOutput{}, fmt.Errorf("querying agent notes: %w", err)
	}

	truncated := len(notes) > limit
	if truncated {
		notes = notes[:limit]
	}

	s.logger.Info("query_agent_notes",
		"query", derefString(input.Query),
		"since", since.Format(time.DateOnly), "until", until.Format(time.DateOnly),
		"kind", derefString(input.Kind), "author", derefString(input.Author),
		"limit", limit, "returned", len(notes), "truncated", truncated)

	return nil, QueryAgentNotesOutput{
		Notes:     notes,
		Total:     len(notes),
		Truncated: truncated,
	}, nil
}
