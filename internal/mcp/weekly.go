package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/weekly"
)

// --- weekly_summary ---
//
// Delegates to internal/weekly.Compute, which is the single source of
// truth for weekly review aggregation. The mastery rows and the
// self_audit block are appended here because they are
// learning/audit projections that live outside the weekly package's
// responsibility.

// selfAuditConceptRepetitionThreshold is the minimum number of distinct
// attempts on a single concept within the week before the concept is
// reported as "repeated". 3 is the conservative anti-pattern signal
// from the learning-studio audit memo §E.3 — most authors agree that
// three same-concept attempts inside one week is the lower edge of
// "should have interleaved by now". The threshold lives in code (not
// input) so the metric stays stable across calls; raising it later
// would change which concepts appear without forcing every consumer
// to update.
const selfAuditConceptRepetitionThreshold = 3

// WeeklySummaryInput is the input for the weekly_summary tool.
type WeeklySummaryInput struct {
	WeekOf *string `json:"week_of,omitempty" jsonschema_description:"Monday of the target week YYYY-MM-DD (default: current week)"`
}

// WeeklySummaryOutput is the output of the weekly_summary tool.
//
// SelfAudit is a P0 verification block for the Phase 2 audit fixes
// (CF-04 skip-reason audit, CF-06 solved_after_solution mapping,
// CF-02 fail-closed default caller). It is always emitted as a value
// (never nil) so cowork agents iterating the response do not have to
// nil-check; empty slices inside are `[]`, never `null`.
//
// recommendation_acceptance_rate is intentionally NOT included — it
// requires new tracking infrastructure (per-call recommendation_id
// persistence + attempt linkage) that is out of P0 scope. See
// docs/audit-prompts/reports/learning-studio-audit-decisions.md §E.4
// for the deferral rationale.
type WeeklySummaryOutput struct {
	Review    weekly.Review `json:"review"`
	Mastery   []MasteryRow  `json:"mastery"`
	SelfAudit SelfAudit     `json:"self_audit"`
}

// SelfAudit is the P0 self-audit metric block surfaced by
// weekly_summary. All four metrics derive from existing tables; no
// new tracking infrastructure was added for this block.
//
// Empty / zero state is the honest default: a brand-new week where no
// MCP write has happened yet emits {0, 0.0, 0, 0, [], 0, []} — there
// is no special "no data" sentinel because zero IS the answer.
type SelfAudit struct {
	// ForceTrueCount: number of force-mode plan-entry completions
	// (reason starts with "manual override:") in the window. Should
	// stay near 0 in healthy operation — force is the audited escape
	// hatch per mcp-decision-policy §13, not a routine path.
	ForceTrueCount int64 `json:"force_true_count"`

	// SolvedAfterSolutionRate is solved_after_solution_count divided by
	// attempt_count. Range [0.0, 1.0]. 0.0 when denominator is 0
	// (vacuous truth: no problem_solving attempts means no
	// solution-exposure either).
	SolvedAfterSolutionRate float64 `json:"solved_after_solution_rate"`

	// SolvedAfterSolutionCount is the numerator of the rate above.
	// Surfaced separately so the magnitude is legible — a 0.5 rate at
	// 2 attempts means very different things than at 200.
	SolvedAfterSolutionCount int64 `json:"solved_after_solution_count"`

	// AttemptCount is the denominator of the rate above:
	// problem_solving paradigm attempts in the window. Paradigm-scoped
	// because solved_after_solution is a problem_solving-only outcome
	// (chk_learning_attempts_paradigm_outcome). Mixing in immersive
	// attempts would dilute the rate artificially.
	AttemptCount int64 `json:"attempt_count"`

	// SameConceptRepeatedWithinWeek lists concepts touched by
	// >= selfAuditConceptRepetitionThreshold distinct attempts. Counting
	// unit is distinct attempts (NOT observations) so a single attempt
	// with several observations on one concept does not artificially
	// trip the threshold.
	SameConceptRepeatedWithinWeek []learning.RepeatedConcept `json:"same_concept_repeated_within_week"`

	// SkippedCount is the total number of plan entries that transitioned
	// to status='skipped' in the window. Equals the sum of all counts
	// in SkipReasonPrefixHistogram (server-computed for legibility).
	SkippedCount int64 `json:"skipped_count"`

	// SkipReasonPrefixHistogram is the per-prefix breakdown of
	// SkippedCount. The prefix is the substring before the first ':'
	// in the skip reason; entries without a colon resolve to
	// "unclassified". CF-04 now requires non-blank skip reasons, so a
	// healthy histogram should rarely contain "unclassified" rows
	// (only pre-CF-04 historical data or future divergence).
	SkipReasonPrefixHistogram []activity.SkipReasonPrefix `json:"skip_reason_prefix_histogram"`
}

func (s *Server) weeklySummary(ctx context.Context, _ *mcp.CallToolRequest, input WeeklySummaryInput) (*mcp.CallToolResult, WeeklySummaryOutput, error) {
	now := time.Now().In(s.loc)
	weekStart := weekly.MondayOf(now)
	if input.WeekOf != nil && *input.WeekOf != "" {
		t, err := time.Parse(time.DateOnly, *input.WeekOf)
		if err != nil {
			return nil, WeeklySummaryOutput{}, fmt.Errorf("invalid week_of date: %w", err)
		}
		weekStart = weekly.MondayOf(t.In(s.loc))
	}

	review, err := weekly.Compute(ctx, s.todos, s.agentNotes, s.learn, weekStart)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("computing weekly review: %w", err)
	}

	// Snapshot mastery as of end-of-week. Without the upper bound a
	// historical week_of=2026-W17 query would return mastery counts
	// that include observations made in W18, W19, …, NOW — i.e. the
	// "weekly" snapshot would silently morph into a current snapshot.
	// Codex flagged this in the Phase 2 audit as a real correctness
	// regression on retrospective queries.
	weekEnd := weekStart.AddDate(0, 0, 7)
	masteryRaw, err := s.learn.ConceptMastery(ctx, nil, weekStart, &weekEnd, "high")
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("querying concept mastery: %w", err)
	}

	selfAudit, err := s.computeSelfAudit(ctx, weekStart, weekEnd)
	if err != nil {
		return nil, WeeklySummaryOutput{}, fmt.Errorf("computing self_audit: %w", err)
	}

	return nil, WeeklySummaryOutput{
		Review:    review,
		Mastery:   toMasteryRows(masteryRaw),
		SelfAudit: selfAudit,
	}, nil
}

// computeSelfAudit orchestrates the four P0 self-audit queries and
// shapes the result into the wire-facing SelfAudit struct. Returns a
// zero-valued SelfAudit (with []-initialized slices) on a quiet week
// — never nil slices, per the json-api rule.
//
// Window is [weekStart, weekEnd) in s.loc, exactly matching the
// review and mastery snapshots so the three blocks tell a coherent
// story for the same calendar week.
func (s *Server) computeSelfAudit(ctx context.Context, weekStart, weekEnd time.Time) (SelfAudit, error) {
	forceCount, err := s.activity.LearningPlanForceCount(ctx, weekStart, weekEnd)
	if err != nil {
		return SelfAudit{}, fmt.Errorf("querying force-true count: %w", err)
	}

	outcomeRate, err := s.learn.SelfAuditOutcomeRate(ctx, weekStart, weekEnd)
	if err != nil {
		return SelfAudit{}, fmt.Errorf("querying solved-after-solution rate: %w", err)
	}

	repeated, err := s.learn.SelfAuditRepeatedConcepts(ctx, weekStart, weekEnd, selfAuditConceptRepetitionThreshold)
	if err != nil {
		return SelfAudit{}, fmt.Errorf("querying repeated concepts: %w", err)
	}
	if repeated == nil {
		repeated = []learning.RepeatedConcept{}
	}

	skipHist, err := s.activity.LearningPlanSkippedHistogram(ctx, weekStart, weekEnd)
	if err != nil {
		return SelfAudit{}, fmt.Errorf("querying skip-reason histogram: %w", err)
	}
	if skipHist == nil {
		skipHist = []activity.SkipReasonPrefix{}
	}

	// SkippedCount is server-computed from the histogram so the
	// caller does not have to fold over the slice to know the total.
	// One SQL roundtrip saved over a separate :one count query.
	var skipped int64
	for _, b := range skipHist {
		skipped += b.Count
	}

	// SolvedAfterSolutionRate: 0.0 when the denominator is 0 (no
	// problem_solving attempts → vacuous rate). Otherwise float
	// division. The denominator is bigint in SQL; the conversion to
	// float64 is lossless for the magnitudes we care about (a week's
	// worth of attempts is in the hundreds at most).
	var rate float64
	if outcomeRate.ProblemSolvingAttemptCount > 0 {
		rate = float64(outcomeRate.SolvedAfterSolutionCount) / float64(outcomeRate.ProblemSolvingAttemptCount)
	}

	return SelfAudit{
		ForceTrueCount:                forceCount,
		SolvedAfterSolutionRate:       rate,
		SolvedAfterSolutionCount:      outcomeRate.SolvedAfterSolutionCount,
		AttemptCount:                  outcomeRate.ProblemSolvingAttemptCount,
		SameConceptRepeatedWithinWeek: repeated,
		SkippedCount:                  skipped,
		SkipReasonPrefixHistogram:     skipHist,
	}, nil
}
