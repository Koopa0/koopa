// Copyright 2026 Koopa. All rights reserved.

// learning_read is the read-only learning-analytics multiplexer. It subsumes
// four former standalone tools behind a single `view` discriminator:
//
//   - overview          ← the learning_dashboard overview view (recent sessions
//     list). The other dashboard views (mastery / weaknesses / timeline /
//     variations) are deliberately NOT exposed here — they remain HTTP-admin-
//     only. learning_read rejects them at its boundary.
//   - next_target       ← recommend_next_target (session-scoped recommender).
//   - attempts          ← attempt_history (target / concept / session sub-modes).
//   - session_progress  ← session_progress (in-session aggregate).
//
// The tool is READ-ONLY forever: every view dispatches to a builder that only
// reads from the learning store. No view mutates state.
//
// Per-view input/output types are REUSED from the former standalone tools
// (LearningDashboardInput/Output, RecommendNextTargetInput/Output,
// AttemptHistoryInput/Output, SessionProgressInput/Output) so the wire shapes
// stay byte-for-byte identical to the tools learning_read replaced — the only
// addition is the top-level `view` tag.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/learning"
)

// learning_read view discriminator values. These mirror the FieldEnums
// declared in ops.LearningRead() — keep both in sync.
const (
	learningReadOverview        = "overview"
	learningReadNextTarget      = "next_target"
	learningReadAttempts        = "attempts"
	learningReadSessionProgress = "session_progress"
)

// LearningReadInput is the request shape for the learning_read multiplexer.
// View selects which read to perform; the remaining fields are the UNION of
// what the four views need. Each view ignores fields outside its own set.
//
// The per-view field groupings:
//
//   - overview          : Domain, WindowDays, ConfidenceFilter
//   - next_target       : SessionID, Domain, Count, ExcludePatterns
//   - attempts          : Target, ConceptSlug, SessionID, Domain, MaxResults,
//     IncludeObservations
//   - session_progress  : (none)
type LearningReadInput struct {
	As   string `json:"as,omitempty" jsonschema_description:"Caller agent identity (e.g. learning-studio). Set by project instructions."`
	View string `json:"view" jsonschema:"required" jsonschema_description:"Which read to perform: overview (recent learning sessions), next_target (in-session next-problem recommendation), attempts (attempt history by target/concept/session), session_progress (in-session aggregate for the active session)."`

	// overview fields.
	Domain           *string `json:"domain,omitempty" jsonschema_description:"Filter by domain. Used by overview, next_target, and attempts (concept_slug lookup default 'leetcode')."`
	WindowDays       FlexInt `json:"window_days,omitempty" jsonschema_description:"overview only: lookback window in days. Default 30, range 1..365."`
	ConfidenceFilter *string `json:"confidence_filter,omitempty" jsonschema_description:"overview only: 'high' (default) or 'all'. Currently inert for overview (sessions are not confidence-filtered) but accepted for forward-compatibility."`

	// next_target fields.
	Count           FlexInt  `json:"count,omitempty" jsonschema_description:"next_target only: number of candidates to return, 1..10. Default 3."`
	ExcludePatterns []string `json:"exclude_patterns,omitempty" jsonschema_description:"next_target only: explicit patterns to reject from candidates in addition to auto-detected recent patterns."`

	// attempts fields.
	Target              *AttemptHistoryTargetRef `json:"target,omitempty" jsonschema_description:"attempts only: look up by learning target (title+domain). Mutually exclusive with concept_slug and (attempts) session_id."`
	ConceptSlug         *string                  `json:"concept_slug,omitempty" jsonschema_description:"attempts only: look up by concept slug. Mutually exclusive with target and session_id."`
	MaxResults          FlexInt                  `json:"max_results,omitempty" jsonschema_description:"attempts only: max attempts to return (default 10, max 100). Ignored for session_id which returns the full session."`
	IncludeObservations *bool                    `json:"include_observations,omitempty" jsonschema_description:"attempts only: whether to populate observations[] on each attempt. Default true."`

	// SessionID is shared between next_target (the active session being scoped)
	// and attempts (the past session to list). session_progress takes no input.
	SessionID *string `json:"session_id,omitempty" jsonschema_description:"next_target: the active session UUID to scope the recommendation to (required for next_target). attempts: a past session UUID to list, oldest first (one of target/concept_slug/session_id)."`
}

// LearningReadOutput is the response envelope for learning_read. Exactly one
// of the per-view payload pointers is populated, matching View. The custom
// MarshalJSON flattens the active payload and prepends the `view` tag so a
// learning_read response looks like the old tool's response plus a `view`
// field — mirroring LearningDashboardOutput.MarshalJSON's flatten approach.
type LearningReadOutput struct {
	View string `json:"view"`

	Overview        *LearningDashboardOutput   `json:"-"`
	NextTarget      *RecommendNextTargetOutput `json:"-"`
	Attempts        *AttemptHistoryOutput      `json:"-"`
	SessionProgress *SessionProgressOutput     `json:"-"`
}

// MarshalJSON emits {"view": <view>, ...<active payload fields flattened>}.
// The active payload is marshaled (honoring its own custom MarshalJSON and
// omitempty tags), decoded into a map, and the `view` key is overlaid so the
// envelope's view tag wins. This keeps each view's wire shape identical to its
// former standalone tool plus the `view` tag.
//
// overview's payload already carries a `view` field (always "overview" from
// dashboardOverview); overlaying the envelope's View — also "overview" — is a
// no-op, so the result is consistent.
func (o LearningReadOutput) MarshalJSON() ([]byte, error) {
	var payload any
	switch {
	case o.Overview != nil:
		payload = o.Overview
	case o.NextTarget != nil:
		payload = o.NextTarget
	case o.Attempts != nil:
		payload = o.Attempts
	case o.SessionProgress != nil:
		payload = o.SessionProgress
	default:
		// No payload (should not happen — learningRead always populates one
		// on the success path). Emit just the view tag rather than failing.
		return json.Marshal(map[string]any{"view": o.View})
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling learning_read %s payload: %w", o.View, err)
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("flattening learning_read %s payload: %w", o.View, err)
	}
	viewTag, err := json.Marshal(o.View)
	if err != nil {
		return nil, fmt.Errorf("marshaling learning_read view tag: %w", err)
	}
	fields["view"] = viewTag
	return json.Marshal(fields)
}

// learningRead dispatches a read-only learning query by view. It validates the
// discriminator, then delegates to the same builders the former standalone
// tools used, populating the matching LearningReadOutput payload pointer.
//
//nolint:gocritic // hugeParam: input passed by value per addTool[I,O] generic contract
func (s *Server) learningRead(ctx context.Context, _ *mcp.CallToolRequest, input LearningReadInput) (*mcp.CallToolResult, LearningReadOutput, error) {
	switch input.View {
	case learningReadOverview:
		out, err := s.buildLearningOverview(ctx, LearningDashboardInput{
			Domain:           input.Domain,
			WindowDays:       input.WindowDays,
			ConfidenceFilter: input.ConfidenceFilter,
		})
		if err != nil {
			return nil, LearningReadOutput{}, err
		}
		return nil, LearningReadOutput{View: input.View, Overview: &out}, nil

	case learningReadNextTarget:
		sessionID := ""
		if input.SessionID != nil {
			sessionID = *input.SessionID
		}
		out, err := s.buildRecommendNextTarget(ctx, RecommendNextTargetInput{
			SessionID:       sessionID,
			Domain:          input.Domain,
			Count:           input.Count,
			ExcludePatterns: input.ExcludePatterns,
		})
		if err != nil {
			return nil, LearningReadOutput{}, err
		}
		return nil, LearningReadOutput{View: input.View, NextTarget: &out}, nil

	case learningReadAttempts:
		out, err := s.buildAttemptHistory(ctx, AttemptHistoryInput{
			Target:              input.Target,
			ConceptSlug:         input.ConceptSlug,
			SessionID:           input.SessionID,
			Domain:              input.Domain,
			MaxResults:          input.MaxResults,
			IncludeObservations: input.IncludeObservations,
		})
		if err != nil {
			return nil, LearningReadOutput{}, err
		}
		return nil, LearningReadOutput{View: input.View, Attempts: &out}, nil

	case learningReadSessionProgress:
		out, err := s.buildSessionProgress(ctx)
		if err != nil {
			return nil, LearningReadOutput{}, err
		}
		return nil, LearningReadOutput{View: input.View, SessionProgress: &out}, nil

	default:
		return nil, LearningReadOutput{}, fmt.Errorf("%w: unknown view %q (valid: overview, next_target, attempts, session_progress)", learning.ErrInvalidInput, input.View)
	}
}
