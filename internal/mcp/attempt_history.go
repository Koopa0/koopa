package mcp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning"
)

// attempt_history is the read-side counterpart to record_attempt. It exists
// to make the Improvement Verification Loop executable in real sessions:
// when the user revisits a problem, the coach needs to know "how did this
// go last time?" — outcome, stuck_at, approach, and any 8-step metadata.
//
// Three entry points (exactly one required):
//
//   - target   — by title + domain. Looks up the learning target via
//     find-by-domain-and-title (NOT find-or-create — this is a read tool;
//     creating targets here would silently pollute the catalog). Backs the
//     core "this problem last time" query.
//   - concept  — by concept slug. Returns attempts that produced an
//     observation about that concept, plus the matched observation's
//     signal/category/severity/detail so the caller can see WHY each
//     attempt is in the result set.
//   - session  — by session UUID. Returns attempts for a specific past
//     session in chronological order. Solves the "what did I do yesterday"
//     review use case that end_session's one-shot response cannot.
//
// Returning empty lists with resolved=false is the design for "not found":
// "the user has never attempted this problem" is a legal answer to
// improvement verification, not an error.

// AttemptHistoryInput is the request shape for the attempt_history tool.
// Exactly one of {target, concept_slug, session_id} must be provided.
type AttemptHistoryInput struct {
	Target      *AttemptHistoryTargetRef `json:"target,omitempty" jsonschema_description:"Look up by learning target (title+domain). Mutually exclusive with concept_slug and session_id."`
	ConceptSlug *string                  `json:"concept_slug,omitempty" jsonschema_description:"Look up by concept slug. Returns attempts that explicitly observed this concept, with the matched observation attached. Mutually exclusive with target and session_id."`
	SessionID   *string                  `json:"session_id,omitempty" jsonschema_description:"Look up all attempts within a specific past session, oldest first. Mutually exclusive with target and concept_slug."`
	Domain      *string                  `json:"domain,omitempty" jsonschema_description:"Domain for concept_slug lookup (defaults to 'leetcode'). Ignored for target (which carries its own domain) and session_id."`
	MaxResults  FlexInt                  `json:"max_results,omitempty" jsonschema_description:"Max attempts to return (default 10, max 100). Ignored for session_id which always returns the full session."`
}

// AttemptHistoryTargetRef identifies a learning target by title + domain.
// External ID is accepted as a hint but the lookup primarily matches by
// (domain, title) which is the find-or-create key used everywhere else.
type AttemptHistoryTargetRef struct {
	Title  string  `json:"title" jsonschema:"required" jsonschema_description:"Learning target title (case-sensitive match)"`
	Domain *string `json:"domain,omitempty" jsonschema_description:"Target domain (defaults to 'leetcode'). Same domain semantics as record_attempt.target.domain."`
}

// AttemptHistoryOutput is the response shape. attempts is always non-nil
// (empty slice on no-results) so callers can iterate without nil checks.
// resolved=false signals "lookup target did not exist" — distinct from
// "target exists but has no attempts yet" (resolved=true, empty attempts).
type AttemptHistoryOutput struct {
	Mode     string             `json:"mode"`             // "target", "concept", or "session"
	Resolved bool               `json:"resolved"`         // true if lookup target exists
	Reason   string             `json:"reason,omitempty"` // populated when resolved=false
	Attempts []learning.Attempt `json:"attempts"`
	Total    int                `json:"total"`
}

func (s *Server) attemptHistory(ctx context.Context, _ *mcp.CallToolRequest, input AttemptHistoryInput) (*mcp.CallToolResult, AttemptHistoryOutput, error) {
	// Enforce exactly-one entry point. Three booleans + a sum is the most
	// readable way to express "oneof" in Go without reflection.
	provided := 0
	if input.Target != nil {
		provided++
	}
	if input.ConceptSlug != nil && *input.ConceptSlug != "" {
		provided++
	}
	if input.SessionID != nil && *input.SessionID != "" {
		provided++
	}
	if provided == 0 {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: one of target, concept_slug, session_id is required")
	}
	if provided > 1 {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: target, concept_slug, session_id are mutually exclusive")
	}

	limit := int32(clamp(int(input.MaxResults), 1, 100, 10)) //nolint:gosec // G115: clamped to 1..100

	switch {
	case input.Target != nil:
		return s.attemptHistoryByTarget(ctx, input.Target, limit)
	case input.ConceptSlug != nil:
		domain := "leetcode"
		if input.Domain != nil && *input.Domain != "" {
			domain = *input.Domain
		}
		return s.attemptHistoryByConcept(ctx, domain, *input.ConceptSlug, limit)
	default:
		return s.attemptHistoryBySession(ctx, *input.SessionID)
	}
}

func (s *Server) attemptHistoryByTarget(ctx context.Context, ref *AttemptHistoryTargetRef, limit int32) (*mcp.CallToolResult, AttemptHistoryOutput, error) {
	if ref.Title == "" {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: target.title is required")
	}
	domain := "leetcode"
	if ref.Domain != nil && *ref.Domain != "" {
		domain = *ref.Domain
	}

	itemID, err := s.learn.FindTarget(ctx, domain, ref.Title)
	if err != nil {
		// Not-found is a legal answer for improvement verification: the user
		// has never attempted this problem. Surface as resolved=false rather
		// than as an error so the caller can branch cleanly.
		return nil, AttemptHistoryOutput{
			Mode:     "target",
			Resolved: false,
			Reason:   fmt.Sprintf("no target found in domain %q with title %q", domain, ref.Title),
			Attempts: []learning.Attempt{},
		}, nil
	}

	attempts, err := s.learn.AttemptsByLearningTarget(ctx, itemID, limit)
	if err != nil {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: %w", err)
	}
	if attempts == nil {
		attempts = []learning.Attempt{}
	}
	return nil, AttemptHistoryOutput{
		Mode:     "target",
		Resolved: true,
		Attempts: attempts,
		Total:    len(attempts),
	}, nil
}

func (s *Server) attemptHistoryByConcept(ctx context.Context, domain, slug string, limit int32) (*mcp.CallToolResult, AttemptHistoryOutput, error) {
	concept, err := s.learn.ConceptBySlug(ctx, domain, slug)
	if err != nil {
		return nil, AttemptHistoryOutput{
			Mode:     "concept",
			Resolved: false,
			Reason:   fmt.Sprintf("no concept found in domain %q with slug %q", domain, slug),
			Attempts: []learning.Attempt{},
		}, nil
	}

	attempts, err := s.learn.AttemptsByConcept(ctx, concept.ID, limit)
	if err != nil {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: %w", err)
	}
	if attempts == nil {
		attempts = []learning.Attempt{}
	}
	return nil, AttemptHistoryOutput{
		Mode:     "concept",
		Resolved: true,
		Attempts: attempts,
		Total:    len(attempts),
	}, nil
}

func (s *Server) attemptHistoryBySession(ctx context.Context, sessionIDStr string) (*mcp.CallToolResult, AttemptHistoryOutput, error) {
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: invalid session_id: %w", err)
	}

	attempts, err := s.learn.AttemptsBySession(ctx, sessionID)
	if err != nil {
		return nil, AttemptHistoryOutput{}, fmt.Errorf("attempt_history: %w", err)
	}
	if attempts == nil {
		attempts = []learning.Attempt{}
	}
	// Sessions are validated by existence — empty result on a real session
	// (never had attempts recorded) returns resolved=true with an empty list.
	// We can't distinguish "session never existed" from "session had zero
	// attempts" with the current store API; both yield empty. Adding a
	// sessions.exists check for this edge case is not worth the round-trip.
	return nil, AttemptHistoryOutput{
		Mode:     "session",
		Resolved: true,
		Attempts: attempts,
		Total:    len(attempts),
	}, nil
}
