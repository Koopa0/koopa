package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/todo"
)

// --- session_delta ---

// SessionDeltaInput is the input for the session_delta tool.
type SessionDeltaInput struct {
	Since *string `json:"since,omitempty" jsonschema_description:"ISO date YYYY-MM-DD to look back from (default: yesterday-midnight in the server's timezone, Asia/Taipei)"`
}

// SessionDeltaOutput is the output of the session_delta tool.
type SessionDeltaOutput struct {
	Since          string                 `json:"since"`
	TodosCreated   []todo.CreatedDetail   `json:"todos_created"`
	TodosCompleted []todo.CompletedDetail `json:"todos_completed"`
	AgentNotes     []agentnote.Note       `json:"agent_notes"`
	SessionCount   int                    `json:"session_count"`
}

func (s *Server) sessionDelta(ctx context.Context, _ *mcp.CallToolRequest, input SessionDeltaInput) (*mcp.CallToolResult, SessionDeltaOutput, error) {
	// Default window is calendar-day aligned in the server's timezone:
	// since=yesterday-midnight (TPE), until=today-midnight (TPE). This
	// matches an agent's "since yesterday" mental model and pairs with
	// the date-typed AgentNotesByDateRange query so an end_session
	// reflection note created today cannot fall outside the range
	// purely because of UTC truncation in the implicit
	// timestamptz→date coercion. Explicit ISO `since` still overrides.
	today := s.today()
	since := today.AddDate(0, 0, -1)
	until := today
	if input.Since != nil && *input.Since != "" {
		t, err := time.Parse(time.DateOnly, *input.Since)
		if err != nil {
			return nil, SessionDeltaOutput{}, fmt.Errorf("invalid since date: %w", err)
		}
		since = t
	}

	created, err := s.todos.ItemsCreatedSince(ctx, since)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying created todo items: %w", err)
	}

	completed, err := s.todos.CompletedItemsDetailSince(ctx, since)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying completed todo items: %w", err)
	}

	notes, err := s.agentNotes.NotesInRange(ctx, since, until, nil, nil)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying agent notes: %w", err)
	}

	sessions, err := s.learn.RecentSessions(ctx, nil, since, 100)
	if err != nil {
		return nil, SessionDeltaOutput{}, fmt.Errorf("querying learning sessions: %w", err)
	}

	return nil, newSessionDeltaOutput(
		since.Format(time.DateOnly),
		created,
		completed,
		notes,
		len(sessions),
	), nil
}

// newSessionDeltaOutput is the canonical builder for SessionDeltaOutput.
// It normalizes nil slices to empty slices so the response satisfies the
// JSON-api invariant that lists encode as `[]` not `null`, regardless of
// upstream store nil behavior.
//
// SessionDeltaOutput has no custom MarshalJSON (cf. LearningDashboardOutput
// which uses ensureSlice), so a direct struct literal with nil slice fields
// would emit `null` for those fields — a wire-contract violation since
// clients iterate them unconditionally.
//
// The sessionDelta handler MUST construct SessionDeltaOutput through this
// builder, never via a direct struct literal. The regression guard is
// TestNewSessionDeltaOutput_NilSlicesBecomeEmptyArrays, which exercises
// this function directly. Mirrors the defensive initialization pattern in
// morningContext (morning.go:132-145).
func newSessionDeltaOutput(
	since string,
	created []todo.CreatedDetail,
	completed []todo.CompletedDetail,
	notes []agentnote.Note,
	sessionCount int,
) SessionDeltaOutput {
	if created == nil {
		created = []todo.CreatedDetail{}
	}
	if completed == nil {
		completed = []todo.CompletedDetail{}
	}
	if notes == nil {
		notes = []agentnote.Note{}
	}
	return SessionDeltaOutput{
		Since:          since,
		TodosCreated:   created,
		TodosCompleted: completed,
		AgentNotes:     notes,
		SessionCount:   sessionCount,
	}
}
