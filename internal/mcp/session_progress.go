package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning"
)

// --- session_progress ---
//
// In-session aggregate for the currently-active learning session. Coach
// invokes between attempts to make interleaving / retrieval-practice
// decisions. Scope is ACTIVE-session only — when no session is active,
// returns {active: false} with a LastEndedSessionID pointer so the caller
// can pivot to attempt_history(session_id=...) without a second round-trip.
//
// Distinct from session_delta (24h pan-feature activity snapshot) per
// .claude/rules/mcp-decision-policy.md §10: the two tools share neither
// the same entity nor the same workflow contract.

// SessionProgressInput is intentionally empty — the tool answers one
// question, scoped by the server's view of the active session.
type SessionProgressInput struct{}

// SessionProgressOutput reports aggregate state of the currently-active
// learning session. Caller MUST branch on Active first.
//
// JSON contract: on Active=true, every aggregate field is emitted even
// if zero/empty — distributions serialize as `[]` and counts as `0`.
// `omitempty` is DELIBERATELY absent from active-path fields because
// encoding/json's omitempty rule drops zero-length slices and int64(0),
// which would leave a JS consumer with `undefined` for legitimate zero
// states. On Active=false, these fields still serialize (as null / 0 /
// empty-string / empty-slice) but the caller ignores them per the Active
// discriminator.
//
// Why SessionID and StartedAt are pointers: Go's uuid.UUID zero value is
// the all-zeros UUID and time.Time zero value is 0001-01-01; pointers
// emit them as JSON null on Active=false rather than leaking sentinel
// zeros. The three Reason / LastEndedSession* fields DO carry omitempty
// because they are branch-specific affordances, not active-path data.
type SessionProgressOutput struct {
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"` // populated iff !Active

	// LastEndedSession affordance — populated iff !Active AND a previous
	// session exists. Caller can hand this to attempt_history(session_id)
	// for past-session review. This is NOT a fallback: zero aggregate
	// fields are returned for that session by this tool.
	LastEndedSessionID *uuid.UUID `json:"last_ended_session_id,omitempty"`
	LastEndedAt        *time.Time `json:"last_ended_at,omitempty"`

	// Active-path identity + timing. Populated iff Active=true; always
	// emitted to JSON regardless (null / "" / 0 on the inactive path).
	SessionID      *uuid.UUID `json:"session_id"`
	Domain         string     `json:"domain"`
	Mode           string     `json:"mode"`
	StartedAt      *time.Time `json:"started_at"`
	ElapsedSeconds int64      `json:"elapsed_seconds"`
	ElapsedDisplay string     `json:"elapsed_display"` // e.g. "42m", matches end_session

	// Aggregate counts + distributions. Populated iff Active=true.
	AttemptCount int64 `json:"attempt_count"`

	// ParadigmDistribution always emits both "problem_solving" and
	// "immersive" entries when Active (count=0 if absent), so dashboard
	// consumers see a stable shape. For most sessions this is a 0/N
	// split (pure LC or pure Japanese) — do NOT read the mixing ratio
	// as a pedagogical signal. See tool description.
	ParadigmDistribution []SessionProgressParadigm `json:"paradigm_distribution"`

	// ConceptSlugDistribution: per-concept rollup. Sort: observation_count
	// DESC, slug ASC. Empty slice (not nil) when Active with no observations.
	// Kind is carried for display; see HERMES W-10 re: kind semantic.
	ConceptSlugDistribution []SessionProgressConcept `json:"concept_slug_distribution"`

	// ObservationCategoryDistribution: (signal_type, category) rollup.
	// Sort: signal_type in [weakness, improvement, mastery] order, then
	// count DESC, then category ASC. Empty slice (not nil) when Active
	// with no observations.
	ObservationCategoryDistribution []SessionProgressCategory `json:"observation_category_distribution"`
}

// SessionProgressParadigm is one entry of the paradigm distribution. Both
// "problem_solving" and "immersive" are always emitted on the active path.
type SessionProgressParadigm struct {
	Paradigm     string `json:"paradigm"`
	Count        int64  `json:"count"`
	TotalMinutes int64  `json:"total_minutes"`
}

// SessionProgressConcept is one row of the concept distribution.
type SessionProgressConcept struct {
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

// SessionProgressCategory is one row of the observation category
// distribution.
type SessionProgressCategory struct {
	SignalType string `json:"signal_type"`
	Category   string `json:"category"`
	Count      int64  `json:"count"`
}

// sessionProgress resolves the active session and aggregates its in-session
// state. TOCTOU note: ActiveSession + SessionProgress are two round-trips;
// a concurrent end_session between them would produce {Active: true} for a
// session that ended microseconds ago. Single-user / single-session scale
// makes this operationally inert. Treat the response as near-real-time,
// not transactional.
func (s *Server) sessionProgress(ctx context.Context, _ *mcp.CallToolRequest, _ SessionProgressInput) (*mcp.CallToolResult, SessionProgressOutput, error) {
	session, err := s.learn.ActiveSession(ctx)
	if err != nil {
		if errors.Is(err, learning.ErrNoActive) {
			return s.sessionProgressInactive(ctx)
		}
		return nil, SessionProgressOutput{}, fmt.Errorf("resolving active session: %w", err)
	}

	agg, err := s.learn.SessionProgress(ctx, session.ID)
	if err != nil {
		return nil, SessionProgressOutput{}, fmt.Errorf("querying session progress: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(session.StartedAt)

	sessionID := session.ID
	startedAt := session.StartedAt
	out := SessionProgressOutput{
		Active:         true,
		SessionID:      &sessionID,
		Domain:         session.Domain,
		Mode:           string(session.Mode),
		StartedAt:      &startedAt,
		ElapsedSeconds: int64(elapsed.Seconds()),
		ElapsedDisplay: formatElapsed(elapsed),
		AttemptCount:   agg.Stats.AttemptCount,
		ParadigmDistribution: []SessionProgressParadigm{
			{Paradigm: string(learning.ParadigmProblemSolving), Count: agg.Stats.ProblemSolvingCount, TotalMinutes: agg.Stats.ProblemSolvingMinutes},
			{Paradigm: string(learning.ParadigmImmersive), Count: agg.Stats.ImmersiveCount, TotalMinutes: agg.Stats.ImmersiveMinutes},
		},
		ConceptSlugDistribution:         slugDistFromStore(agg.ConceptDist),
		ObservationCategoryDistribution: categoryDistFromStore(agg.CategoryDist),
	}

	s.logger.Info("session_progress",
		"session_id", session.ID,
		"attempt_count", agg.Stats.AttemptCount,
		"elapsed_seconds", out.ElapsedSeconds,
		"concept_count", len(out.ConceptSlugDistribution),
		"category_count", len(out.ObservationCategoryDistribution),
	)

	return nil, out, nil
}

// sessionProgressInactive builds the {active: false} response, including
// the LastEndedSession affordance when a prior session exists.
func (s *Server) sessionProgressInactive(ctx context.Context) (*mcp.CallToolResult, SessionProgressOutput, error) {
	out := SessionProgressOutput{
		Active: false,
		Reason: "no active session",
	}

	last, err := s.learn.LastEndedSession(ctx)
	switch {
	case err == nil:
		id := last.ID
		out.LastEndedSessionID = &id
		if last.EndedAt != nil {
			endedAt := *last.EndedAt
			out.LastEndedAt = &endedAt
		}
	case errors.Is(err, learning.ErrNotFound):
		// no prior session on record — fine, leave affordance fields nil
	default:
		return nil, SessionProgressOutput{}, fmt.Errorf("resolving last ended session: %w", err)
	}

	return nil, out, nil
}

func slugDistFromStore(rows []learning.SessionProgressConceptCount) []SessionProgressConcept {
	out := make([]SessionProgressConcept, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = SessionProgressConcept{
			Slug:  r.Slug,
			Name:  r.Name,
			Kind:  r.Kind,
			Count: r.ObservationCount,
		}
	}
	return out
}

func categoryDistFromStore(rows []learning.SessionProgressCategoryCount) []SessionProgressCategory {
	out := make([]SessionProgressCategory, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = SessionProgressCategory{
			SignalType: r.SignalType,
			Category:   r.Category,
			Count:      r.ObservationCount,
		}
	}
	return out
}

// formatElapsed renders a duration in the coach-facing "42m" shape that
// end_session uses. Sub-minute durations collapse to "0m" so freshly-started
// sessions don't emit "0s" or empty strings. Over-minute rounds to the
// nearest minute and strips time.Duration.String's trailing "0s" artifact.
func formatElapsed(d time.Duration) string {
	if d < time.Minute {
		return "0m"
	}
	return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
}
