// Copyright 2026 Koopa. All rights reserved.

// learning.go holds the learning-session lifecycle MCP tools:
// start_session, record_attempt, end_session, learning_dashboard.
// Supporting tools with narrower scope live in siblings:
//
//   - attempt_history.go   — attempt_history
//   - recommend_next.go    — recommend_next_target
//   - plan.go              — manage_plan multiplexer
//
// The session lifecycle rule (.claude/rules/mcp-decision-policy.md §12):
// only one learning_sessions row may have ended_at IS NULL at a time.
// start_session enforces this and will auto-end an abandoned zombie
// session (>12h idle) so the next start succeeds without manual
// cleanup.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/learning/fsrs"
)

// --- start_session ---

type StartSessionInput struct {
	Domain          string  `json:"domain" jsonschema:"required" jsonschema_description:"Learning domain (e.g. leetcode, japanese, system-design)"`
	Mode            string  `json:"mode" jsonschema:"required" jsonschema_description:"Session mode: retrieval, practice, mixed, review, reading"`
	DailyPlanItemID *string `json:"daily_plan_item_id,omitempty" jsonschema_description:"Optional UUID linking to daily plan"`
}

type StartSessionOutput struct {
	Session learning.Session `json:"session"`
	// ZombieEnded is a prior session that was auto-ended because it had
	// no activity in >12h. Surfaced so the caller knows a stale session
	// was reclaimed and can audit the transition. Nil when no zombie
	// was present.
	ZombieEnded *learning.Session `json:"zombie_ended,omitempty"`
}

func (s *Server) startSession(ctx context.Context, _ *mcp.CallToolRequest, input StartSessionInput) (*mcp.CallToolResult, StartSessionOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "start_session"); err != nil {
		return nil, StartSessionOutput{}, err
	}
	if input.Domain == "" {
		return nil, StartSessionOutput{}, fmt.Errorf("domain is required")
	}

	mode := learning.Mode(input.Mode)
	switch mode {
	case learning.ModeRetrieval, learning.ModePractice, learning.ModeMixed,
		learning.ModeReview, learning.ModeReading:
		// valid
	default:
		return nil, StartSessionOutput{}, fmt.Errorf("invalid mode %q", input.Mode)
	}

	var planItemID *uuid.UUID
	if input.DailyPlanItemID != nil && *input.DailyPlanItemID != "" {
		id, err := uuid.Parse(*input.DailyPlanItemID)
		if err != nil {
			return nil, StartSessionOutput{}, fmt.Errorf("invalid daily_plan_item_id: %w", err)
		}
		planItemID = &id
	}

	session, zombie, err := s.learn.StartSession(ctx, input.Domain, mode, planItemID)
	if err != nil {
		// On ErrActiveExists, surface the active session's id so the caller
		// can end it and retry without an extra dashboard query. The lookup
		// is one query on the error path only.
		if errors.Is(err, learning.ErrActiveExists) {
			if active, aErr := s.learn.ActiveSession(ctx); aErr == nil {
				return nil, StartSessionOutput{ZombieEnded: zombie}, fmt.Errorf("active session %s exists; end it first", active.ID)
			}
		}
		return nil, StartSessionOutput{ZombieEnded: zombie}, fmt.Errorf("starting session: %w", err)
	}

	if zombie != nil {
		s.logger.Info("start_session: zombie auto-ended",
			"zombie_id", zombie.ID, "zombie_started_at", zombie.StartedAt)
	}
	s.logger.Info("start_session", "id", session.ID, "domain", input.Domain, "mode", input.Mode)
	return nil, StartSessionOutput{Session: *session, ZombieEnded: zombie}, nil
}

// --- record_attempt ---

type RecordAttemptInput struct {
	SessionID      string               `json:"session_id" jsonschema:"required" jsonschema_description:"Active session UUID"`
	Target         AttemptTarget        `json:"target" jsonschema:"required" jsonschema_description:"Learning target"`
	Outcome        string               `json:"outcome" jsonschema:"required" jsonschema_description:"Semantic (got it, needed help, etc) or raw enum"`
	Duration       *FlexInt             `json:"duration_minutes,omitempty" jsonschema_description:"Time spent in minutes"`
	StuckAt        *string              `json:"stuck_at,omitempty" jsonschema_description:"Where you got stuck. Plain free-text — DO NOT wrap in extra quotes or JSON-escape the content. Example: sliding window pattern, didn't think about termination check on shrink. The MCP transport handles JSON escaping; sending '\"naive O(n^2)...\"' (with surrounding quotes) persists literal quotes in the DB."`
	Approach       *string              `json:"approach_used,omitempty" jsonschema_description:"Approach used. Plain free-text — same escape-level guidance as stuck_at. Example: two-pointer opposite ends, with hashmap for dedup."`
	Observations   []ObservationInput   `json:"observations,omitempty" jsonschema_description:"Concept observations"`
	Metadata       json.RawMessage      `json:"metadata,omitempty" jsonschema_description:"Free-form JSON for 8-step checklist outputs: complexity {time,space}, pattern, related problem slugs, solve context. Persisted on attempts.metadata. Reserved keys by convention (not enforced): 'pattern' (string, feeds recommend_next_target interleaving filter), 'recommended_by' (string: 'tool' | 'coach' | 'self'; when the attempt follows a recommend_next_target suggestion, set 'tool' so recommendation effectiveness can be audited later)."`
	FSRSRating     *FlexInt             `json:"fsrs_rating,omitempty" jsonschema_description:"Optional FSRS recall-difficulty override. 1=Again, 2=Hard, 3=Good, 4=Easy. When set, this replaces the outcome-derived rating for spaced repetition scheduling. Use when recall difficulty diverges from solve outcome — e.g. solved but painful recall, or needed help but core concept is solid. Accepts int (2) or string (\"2\") for transports that stringify ints."`
	RelatedTargets []RelatedTargetInput `json:"related_targets,omitempty" jsonschema_description:"Learning targets related to the attempted target (variations, follow-ups, prerequisites). Each entry is find-or-created then linked via item_relations. Same-domain only; cross-domain relations are rejected with a warning."`
}

type AttemptTarget struct {
	Title      string  `json:"title" jsonschema:"required"`
	ExternalID *string `json:"external_id,omitempty"`
	Domain     *string `json:"domain,omitempty"`
	Difficulty *string `json:"difficulty,omitempty"`
}

// RelatedTargetInput describes a learning target related to the attempted target,
// used by record_attempt to record item_relations (variation graph).
// The target is resolved via find-or-create semantics (same as AttemptTarget),
// then a directed relation source→target is inserted with the given relation_type.
type RelatedTargetInput struct {
	Title        string  `json:"title" jsonschema:"required" jsonschema_description:"Target title"`
	ExternalID   *string `json:"external_id,omitempty" jsonschema_description:"Target provider ID (e.g. LeetCode number)"`
	Domain       *string `json:"domain,omitempty" jsonschema_description:"Target domain — defaults to the session/source domain; must match source domain"`
	Difficulty   *string `json:"difficulty,omitempty"`
	RelationType string  `json:"relation_type" jsonschema:"required" jsonschema_description:"How target relates to the attempted target. Allowed: easier_variant, harder_variant, prerequisite, follow_up, same_pattern, similar_structure"`
}

type ObservationInput struct {
	Concept    string  `json:"concept" jsonschema:"required" jsonschema_description:"Concept slug"`
	Signal     string  `json:"signal" jsonschema:"required" jsonschema_description:"weakness, improvement, or mastery"`
	Category   string  `json:"category" jsonschema:"required" jsonschema_description:"Domain-specific category"`
	Severity   *string `json:"severity,omitempty" jsonschema_description:"minor, moderate, or critical. WEAKNESS SIGNAL ONLY — setting severity on an improvement or mastery observation causes that observation to be rejected and not persisted, with a 'rejected and not persisted' warning naming the offending index in observation_warnings (the rest of the attempt still persists). Leave unset for non-weakness signals."`
	Detail     *string `json:"detail,omitempty"`
	Confidence string  `json:"confidence,omitempty" jsonschema_description:"high (default — directly evidenced) or low (coach inferred). Both persist; mastery and weakness views default to high only but accept confidence_filter='all'."`
}

// ConceptRef is the slug + id pair surfaced to callers in the
// record_attempt response so they can chain follow-up reads (mastery,
// FSRS, observations) without re-resolving slug → id. auto_created is
// intentionally omitted — distinguishing INSERT from UPDATE in
// PostgreSQL upsert RETURNING is fragile (the xmax trick does not work
// for ON CONFLICT DO UPDATE; the created_at = updated_at heuristic
// races with concurrent writes). Add later if a concrete consumer
// needs it.
type ConceptRef struct {
	Slug string `json:"slug"`
	ID   string `json:"id"`
}

// RelatedTargetRef is the resolved id + title for a related target
// successfully linked by record_attempt. Missing entries (resolution
// failed, link skipped) surface in relation_warnings; this slice only
// reports the linked ones.
type RelatedTargetRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// FSRSCardRef is the touched review_cards row's id + next due
// timestamp. Returned only when the FSRS scheduling step succeeded —
// on failure FSRSReviewFailed=true and this field is omitted (no
// null or zero-valued placeholder). Lets the coach surface "next
// review due Mon 10am" without a follow-up CardByLearningTarget
// query.
type FSRSCardRef struct {
	ID    string    `json:"id"`
	DueAt time.Time `json:"due_at"`
}

type RecordAttemptOutput struct {
	Attempt learning.Attempt `json:"attempt"`
	// CanonicalOutcome echoes the storage-form outcome that the caller's
	// input mapped to. record_attempt accepts semantic synonyms (e.g.
	// "needed help" → solved_with_hint); without this field the coach
	// must introspect Attempt.Outcome to see what got normalized. Always
	// populated; no omitempty.
	CanonicalOutcome     string `json:"canonical_outcome"`
	ObservationsRecorded int    `json:"observations_recorded"`
	// Slice and counter fields below intentionally omit `omitempty`:
	// when they are absent from a response, callers cannot distinguish
	// "the operation produced no warnings / no links" from "the field
	// got dropped because it was zero-valued." Always emitting the
	// canonical empty value (`[]` for slices, `0` for counters) makes
	// the response shape stable regardless of input.
	//
	// Partial-write contract: ObservationsRecorded < len(input.Observations)
	// is a legal state, not an error. Observations are validated per-element
	// (e.g. severity-on-mastery violations); a rejected element is named in
	// ObservationWarnings by its input index, sibling elements still try
	// independently, and the attempt row plus FSRS rating still persist.
	// Callers reconcile by comparing ObservationsRecorded against input
	// length and reading ObservationWarnings for rejected indices. Same
	// per-element semantics apply to RelatedTargets / RelationsLinked /
	// RelationWarnings.
	//
	// The partial-write contract above is also surfaced to MCP clients
	// via internal/mcp/ops/catalog.go::RecordAttempt() Description —
	// keep both in sync when changing the contract.
	ObservationWarnings []string           `json:"observation_warnings"`
	PlanContext         []PlanContextEntry `json:"plan_context"`
	RelationsLinked     int                `json:"relations_linked"`
	RelationWarnings    []string           `json:"relation_warnings"`
	// FSRSRatingApplied echoes the FSRS rating (1=Again, 2=Hard, 3=Good,
	// 4=Easy) the server actually used when advancing the spaced-repetition
	// queue for this attempt. When the caller supplied an fsrs_rating
	// override this field repeats that value back, so the coach can verify
	// the override reached the server without a follow-up query. When no
	// override was supplied the field shows the rating derived from
	// outcome via fsrs.RatingFromOutcome. nil only when the outcome was
	// unknown to the bridge (no rating could be determined).
	FSRSRatingApplied *int `json:"fsrs_rating_applied,omitempty"`
	// FSRSReviewFailed is true when the attempt was persisted but the
	// spaced-repetition review card update failed. The attempt itself is
	// still valid — surface this so the caller can retry or warn the user
	// instead of silently losing a review tick.
	FSRSReviewFailed bool `json:"fsrs_review_failed,omitempty"`
	// Concepts is one entry per observation that resolved to a concept
	// (slug + id). Lets the caller drill into mastery / FSRS for those
	// concepts without re-resolving slug → id. Empty when no
	// observations were submitted or every one was rejected; rejected
	// indices stay in ObservationWarnings.
	Concepts []ConceptRef `json:"concepts"`
	// FSRSCard is the touched review_cards row's id + next due
	// timestamp. Omitted when FSRSReviewFailed=true so callers never
	// receive stale or zero-valued card data — check FSRSReviewFailed
	// first, then read FSRSCard.
	FSRSCard *FSRSCardRef `json:"fsrs_card,omitempty"`
	// RelatedTargetsResolved is one entry per related_target that was
	// successfully linked (id + title). Rejected entries (cross-domain,
	// unknown relation_type, link failure) stay in RelationWarnings.
	// Always emitted as [] when empty — same partial-write contract as
	// ObservationWarnings.
	RelatedTargetsResolved []RelatedTargetRef `json:"related_targets_resolved"`
}

// maxMetadataBytes caps the attempts.metadata JSONB payload to keep
// attempt rows cheap to index and transfer. The 8-step checklist outputs
// this field holds are well under 1 KiB in practice; 32 KiB is a generous
// ceiling that still blocks obvious abuse without forcing a doc expansion.
const maxMetadataBytes = 32 * 1024

// PlanContextEntry represents a learning plan entry that contains the attempted target.
// Returned by record_attempt so Claude can decide whether to mark plan entries as completed.
type PlanContextEntry struct {
	PlanID    string `json:"plan_id"`
	PlanTitle string `json:"plan_title"`
	EntryID   string `json:"entry_id"`
	Position  int32  `json:"position"`
	Phase     string `json:"phase,omitempty"`
	Status    string `json:"status"`
}

// attemptPrep holds the inputs derived during validation — the values that
// aren't already on RecordAttemptInput. Metadata is intentionally absent;
// recordAttempt reads input.Metadata directly (it's validated in prepareAttempt
// but not copied here to avoid the duplicate field). Returned by value —
// six scalar fields, no benefit from a pointer.
type attemptPrep struct {
	sessionID uuid.UUID
	paradigm  learning.Paradigm
	outcome   string
	domain    string
	itemID    uuid.UUID
	duration  *int32
}

//nolint:gocritic // hugeParam: input passed by value per addTool[I,O] generic contract
func (s *Server) recordAttempt(ctx context.Context, _ *mcp.CallToolRequest, input RecordAttemptInput) (*mcp.CallToolResult, RecordAttemptOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "record_attempt"); err != nil {
		return nil, RecordAttemptOutput{}, err
	}
	prep, err := s.prepareAttempt(ctx, &input)
	if err != nil {
		return nil, RecordAttemptOutput{}, err
	}

	var attempt *learning.Attempt
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		var err error
		attempt, err = s.learn.WithTx(tx).RecordAttempt(ctx, prep.itemID, prep.sessionID, prep.paradigm, prep.outcome, prep.duration, input.StuckAt, input.Approach, input.Metadata)
		return err
	})
	if err != nil {
		return nil, RecordAttemptOutput{}, err
	}
	attempt.TargetTitle = input.Target.Title
	attempt.TargetExternalID = input.Target.ExternalID

	// Side effects: none of these fail the attempt — each helper logs its own
	// failures and returns a best-effort result so the caller still gets a
	// persisted attempt record. updateFSRSReview returns the rating it
	// applied (so callers can verify a fsrs_rating override was received)
	// plus a failed flag (so callers can detect silent review-card data
	// loss) and, on success, the touched card's id + due timestamp so the
	// caller can surface fsrs_card.due_at without an extra query.
	recorded, obsWarnings, concepts := s.processObservations(ctx, attempt.ID, prep.domain, input.Observations)
	fsrsRating, fsrsFailed, fsrsCard := s.updateFSRSReview(ctx, prep.itemID, prep.outcome, input.FSRSRating)
	linked, relWarnings, relResolved := s.processRelatedTargets(ctx, prep.itemID, prep.domain, input.RelatedTargets)
	planCtx := s.lookupPlanContext(ctx, prep.itemID)

	// Ensure slice fields serialise as [] (not null) so callers can
	// distinguish "happened, no warnings/entries" from a field that was
	// dropped. The helpers above return nil when nothing fired (zero
	// observations / zero relations / no plan context) and the json-api
	// rule in this project forbids null on list fields. Concepts and
	// RelatedTargetsResolved follow the same rule.
	if obsWarnings == nil {
		obsWarnings = []string{}
	}
	if relWarnings == nil {
		relWarnings = []string{}
	}
	if planCtx == nil {
		planCtx = []PlanContextEntry{}
	}
	if concepts == nil {
		concepts = []ConceptRef{}
	}
	if relResolved == nil {
		relResolved = []RelatedTargetRef{}
	}

	s.logger.Info("record_attempt",
		"session", prep.sessionID, "target", input.Target.Title, "outcome", prep.outcome,
		"observations", recorded, "observation_warnings", len(obsWarnings),
		"plan_context", len(planCtx),
		"relations_linked", linked, "relation_warnings", len(relWarnings),
		"fsrs_review_failed", fsrsFailed)
	return nil, RecordAttemptOutput{
		Attempt:                *attempt,
		CanonicalOutcome:       prep.outcome,
		ObservationsRecorded:   recorded,
		ObservationWarnings:    obsWarnings,
		PlanContext:            planCtx,
		RelationsLinked:        linked,
		RelationWarnings:       relWarnings,
		FSRSRatingApplied:      fsrsRating,
		FSRSReviewFailed:       fsrsFailed,
		Concepts:               concepts,
		FSRSCard:               fsrsCard,
		RelatedTargetsResolved: relResolved,
	}, nil
}

// prepareAttempt validates and resolves everything record_attempt needs before
// writing the attempt row: parses the session ID, confirms it is the active
// session, maps the semantic outcome to its schema enum, resolves the learning
// target (find-or-create with domain fallback from the session), clamps the
// optional duration, and validates the optional metadata (size cap + JSON
// syntax check).
//
// All fallible lookups live here so recordAttempt itself contains no
// validation branches — the only error path in recordAttempt is the final
// RecordAttempt call on the core write path. Validation errors wrap
// learning.ErrInvalidInput so observability layers can classify them.
func (s *Server) prepareAttempt(ctx context.Context, input *RecordAttemptInput) (attemptPrep, error) {
	sessionID, err := uuid.Parse(input.SessionID)
	if err != nil {
		return attemptPrep{}, fmt.Errorf("%w: invalid session_id: %w", learning.ErrInvalidInput, err)
	}

	session, err := s.resolveAttemptSession(ctx, sessionID)
	if err != nil {
		return attemptPrep{}, err
	}

	paradigm, outcome, err := learning.MapOutcome(session.Mode, input.Outcome)
	if err != nil {
		return attemptPrep{}, err
	}

	// The primary attempt target inherits the session's domain. An explicit
	// input.Target.Domain is honored only when it equals session.Domain —
	// any mismatch is rejected up-front so the call cannot silently create
	// a target (and auto-create concepts) in a different domain than the
	// active session. Related targets keep their own explicit cross-domain
	// rules in processRelatedTargets; this guard is for the primary target.
	domain := session.Domain
	if input.Target.Domain != nil && *input.Target.Domain != "" && *input.Target.Domain != session.Domain {
		return attemptPrep{}, fmt.Errorf("%w: target.domain %q does not match active session domain %q; the primary attempt target inherits the session's domain (omit target.domain, or pass the session's domain). For cross-domain isomorphism use propose_hypothesis or write_agent_note(kind=context)", learning.ErrInvalidInput, *input.Target.Domain, session.Domain)
	}
	itemID, err := s.learn.FindOrCreateTarget(ctx, domain, input.Target.Title, input.Target.ExternalID, input.Target.Difficulty, s.callerIdentity(ctx))
	if err != nil {
		return attemptPrep{}, err
	}

	if len(input.Metadata) > maxMetadataBytes {
		return attemptPrep{}, fmt.Errorf("%w: metadata exceeds %d bytes (got %d)", learning.ErrInvalidInput, maxMetadataBytes, len(input.Metadata))
	}
	if len(input.Metadata) > 0 && !json.Valid(input.Metadata) {
		return attemptPrep{}, fmt.Errorf("%w: metadata is not valid JSON", learning.ErrInvalidInput)
	}

	// fsrs_rating is 1..4 per the FSRS spec (Again=1, Hard=2, Good=3, Easy=4).
	// FlexInt accepts any int; reject out-of-range values here so the attempt
	// fails up-front rather than writing an attempt row and then warning that
	// the FSRS review half-fired with an unusable rating.
	if input.FSRSRating != nil {
		r := int(*input.FSRSRating)
		if r < 1 || r > 4 {
			return attemptPrep{}, fmt.Errorf("%w: fsrs_rating must be 1..4, got %d", learning.ErrInvalidInput, r)
		}
	}

	return attemptPrep{
		sessionID: sessionID,
		paradigm:  paradigm,
		outcome:   outcome,
		domain:    domain,
		itemID:    itemID,
		duration:  clampDurationMinutes(input.Duration),
	}, nil
}

// clampDurationMinutes converts an optional duration (in minutes) to an int32
// pointer bounded to 1..1440 (24 hours). Nil, zero, or negative values return
// nil so the attempt row stores NULL rather than a fabricated 1-minute span.
// Values above 1440 are clamped down to the 24-hour ceiling.
func clampDurationMinutes(d *FlexInt) *int32 {
	if d == nil || *d <= 0 {
		return nil
	}
	m := clamp(int(*d), 1, 1440, 0)
	if m <= 0 {
		return nil
	}
	v := int32(m) // #nosec G115 — clamped to 1..1440 above
	return &v
}

// resolveDueWithinHours applies the retrieval-view window contract: nil input
// (caller did not supply due_within_hours) defaults to 24 hours — the typical
// morning-review window. An explicit FlexInt(0) survives as strict
// "due-right-now" because the *FlexInt indirection lets us distinguish unset
// from zero (a plain int would collapse the two). Negative values clamp to 0;
// values above 168 (one week) clamp to 168.
func resolveDueWithinHours(in *FlexInt) int {
	if in == nil {
		return 24
	}
	h := int(*in)
	if h < 0 {
		return 0
	}
	if h > 168 {
		return 168
	}
	return h
}

// lookupPlanContext returns the active plan entries that contain targetID, so
// record_attempt can expose plan membership to the caller. Lookup failures
// are logged and return an empty slice — plan context is auxiliary.
func (s *Server) lookupPlanContext(ctx context.Context, targetID uuid.UUID) []PlanContextEntry {
	planEntries, err := s.plans.EntriesByLearningTarget(ctx, targetID)
	if err != nil {
		s.logger.Warn("record_attempt: plan context lookup failed", "target_id", targetID, "error", err)
		return nil
	}
	out := make([]PlanContextEntry, 0, len(planEntries))
	for i := range planEntries {
		pe := &planEntries[i]
		pce := PlanContextEntry{
			PlanID:    pe.PlanID.String(),
			PlanTitle: pe.PlanTitle,
			EntryID:   pe.ID.String(),
			Position:  pe.Position,
			Status:    string(pe.Status),
		}
		if pe.Phase != nil {
			pce.Phase = *pe.Phase
		}
		out = append(out, pce)
	}
	return out
}

// updateFSRSReview applies a spaced-repetition review for itemID. When
// override is non-nil it is used directly (1..4 rating); otherwise the
// outcome string is mapped to a rating via fsrs.RatingFromOutcome.
//
// Returns the rating actually applied, a "failed" flag, and (on success)
// the touched card's id + due timestamp.
//
//   - applied is non-nil whenever a rating was determined — even when the
//     subsequent ReviewByRating / ReviewByOutcome call failed, we still
//     surface the rating the caller's input would have produced so the
//     coach can verify "did the override I sent reach the server" without
//     a second query.
//   - applied is nil only on the unknown-outcome path (no override, and
//     the outcome string is outside the enum) — there is no rating to
//     echo because the bridge function rejected the outcome.
//   - failed=true means the FSRS queue was NOT advanced. The attempt row
//     is still persisted, and the card row is stamped via fsrs.MarkDrift
//     so the retrieval view raises a drift_suspect flag.
//   - card is non-nil only when failed=false; on failure we omit the card
//     entirely so the caller can rely on (failed=true ⇒ card=nil) and
//     surface fsrs_review_failed instead of garbage card data.
func (s *Server) updateFSRSReview(ctx context.Context, targetID uuid.UUID, outcome string, override *FlexInt) (applied *int, failed bool, card *FSRSCardRef) {
	now := time.Now()
	if override != nil {
		rating := int(*override)
		cardID, dueAt, err := s.fsrs.ReviewByRating(ctx, targetID, rating, now)
		if err != nil {
			s.logger.Warn("record_attempt: fsrs review (override) failed", "target_id", targetID, "rating", rating, "error", err)
			s.markFSRSDrift(ctx, targetID, "rating_override_failed")
			return &rating, true, nil
		}
		return &rating, false, &FSRSCardRef{ID: cardID.String(), DueAt: dueAt}
	}

	derived, derivErr := fsrs.RatingFromOutcome(outcome)
	if derivErr != nil {
		// Unknown outcome — no rating to echo. ReviewByOutcome will return
		// the same error; let it run so the drift marker still fires.
		s.logger.Warn("record_attempt: fsrs review failed", "target_id", targetID, "reason", "unknown_outcome", "error", derivErr)
		s.markFSRSDrift(ctx, targetID, "unknown_outcome")
		return nil, true, nil
	}

	cardID, dueAt, err := s.fsrs.ReviewByOutcome(ctx, targetID, outcome, now)
	if err != nil {
		// outcome is user-controlled — log only the sentinel branch so the
		// raw value never reaches the log stream.
		reason := "review_failed"
		if errors.Is(err, fsrs.ErrUnknownOutcome) {
			reason = "unknown_outcome"
		}
		s.logger.Warn("record_attempt: fsrs review failed", "target_id", targetID, "reason", reason, "error", err)
		s.markFSRSDrift(ctx, targetID, reason)
		return &derived, true, nil
	}
	return &derived, false, &FSRSCardRef{ID: cardID.String(), DueAt: dueAt}
}

// markFSRSDrift stamps the drift marker and logs any failure or silent
// no-op (no card row for the target yet) so drift on brand-new targets is
// still visible in operational telemetry.
func (s *Server) markFSRSDrift(ctx context.Context, targetID uuid.UUID, reason string) {
	rows, err := s.fsrs.MarkDrift(ctx, targetID, reason)
	if err != nil {
		s.logger.Warn("record_attempt: fsrs drift mark failed", "target_id", targetID, "reason", reason, "error", err)
		return
	}
	if rows == 0 {
		s.logger.Warn("record_attempt: fsrs drift silent — no card for target yet", "target_id", targetID, "reason", reason)
	}
}

// processRelatedTargets resolves each RelatedTargetInput to a learning target and
// links it to the source via item_relations. Per-entry errors become warnings
// — the caller still sees a successful attempt record.
//
// Domain handling: LinkItems in the store layer no longer enforces same-domain
// (to avoid N+1 lookups per attempt). This function is the enforcer. It uses
// sourceDomain as the default target domain; if the caller explicitly
// overrides with a different domain the entry is rejected as a cross-domain
// relation. Because the target is then resolved via FindOrCreateTarget with
// sourceDomain, the inserted row is guaranteed same-domain by construction.
func (s *Server) processRelatedTargets(ctx context.Context, sourceID uuid.UUID, sourceDomain string, items []RelatedTargetInput) (linked int, warnings []string, resolved []RelatedTargetRef) {
	if len(items) == 0 {
		return 0, nil, nil
	}
	caller := s.callerIdentity(ctx)
	for i := range items {
		ri := &items[i]
		if ri.Title == "" {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d]: title required", i))
			continue
		}
		if !learning.ValidRelationType(learning.RelationType(ri.RelationType)) {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): unknown relation_type %q (valid: easier_variant, harder_variant, prerequisite, follow_up, same_pattern, similar_structure)", i, ri.Title, ri.RelationType))
			continue
		}
		// Cross-domain rejection moved to this layer — source domain is already
		// in scope from prepareAttempt, no DB lookup needed.
		if ri.Domain != nil && *ri.Domain != "" && *ri.Domain != sourceDomain {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): cross-domain relation rejected (source=%q, target=%q). learning_target_relations is intentionally per-domain — for cross-domain isomorphism, use propose_hypothesis (if the connection is falsifiable) or write_agent_note(kind=context) (if it's an ad-hoc observation worth keeping)", i, ri.Title, sourceDomain, *ri.Domain))
			continue
		}
		targetID, err := s.learn.FindOrCreateTarget(ctx, sourceDomain, ri.Title, ri.ExternalID, ri.Difficulty, caller)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): find-or-create failed: %v", i, ri.Title, err))
			continue
		}
		if err := s.learn.LinkTargets(ctx, sourceID, targetID, learning.RelationType(ri.RelationType), caller); err != nil {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): link failed: %v", i, ri.Title, err))
			continue
		}
		linked++
		resolved = append(resolved, RelatedTargetRef{ID: targetID.String(), Title: ri.Title})
	}
	return linked, warnings, resolved
}

// --- end_session ---

type EndSessionInput struct {
	SessionID  string  `json:"session_id" jsonschema:"required" jsonschema_description:"Session UUID to end"`
	Reflection *string `json:"reflection,omitempty" jsonschema_description:"Optional reflection text (creates agent note)"`
}

type EndSessionOutput struct {
	Session  learning.Session   `json:"session"`
	Attempts []learning.Attempt `json:"attempts"`
	Duration string             `json:"duration"`
}

func (s *Server) endSession(ctx context.Context, _ *mcp.CallToolRequest, input EndSessionInput) (*mcp.CallToolResult, EndSessionOutput, error) {
	if err := s.requireRegisteredCaller(ctx, "end_session"); err != nil {
		return nil, EndSessionOutput{}, err
	}
	sessionID, err := uuid.Parse(input.SessionID)
	if err != nil {
		return nil, EndSessionOutput{}, fmt.Errorf("invalid session_id: %w", err)
	}

	// Pre-flight: ensure the session exists AND is active before
	// creating the reflection note. Without this, an end_session call
	// against a not-found or already-ended session would still write
	// the reflection text into agent_notes — producing orphan
	// reflections (no linked session) that pollute morning_context /
	// session_delta / query_agent_notes. Phase 3 audit found three
	// repeated end_session calls each created a reflection note even
	// though only the first succeeded.
	//
	// Race trade-off: another caller can end the session between this
	// check and EndSession below. That window is sub-millisecond. The
	// race is acceptable in this codebase because:
	//   1. No other cowork agent has a write path to learning_sessions
	//      — learning-studio is the sole MCP end_session caller. The
	//      admin HTTP handler in internal/learning/handler.go is the
	//      only other writer and is human-driven (Koopa via admin UI);
	//      cowork-vs-admin concurrency is rare and would resolve to
	//      the same already-ended error on either side.
	//   2. Conversation is serialised at the agent level — a single
	//      agent does not issue two concurrent end_session calls.
	//   3. The "one active session at a time" invariant (uq_learning_
	//      sessions_one_active) prevents fan-out concurrency.
	// A full fix would push note creation into the same tx as
	// EndSession (Design 2/3 in the F-NEW1 proposal). Both options
	// either couple learning.Store to agent_notes (violates
	// feedback_split_by_semantics) or add handler-level tx
	// orchestration for a never-observed race — not worth the coupling.
	// The orphan-by-race window is honest doc; the orphan-by-mistake
	// window (the actual Phase 3 finding) is closed.
	existing, err := s.learn.SessionByID(ctx, sessionID)
	switch {
	case errors.Is(err, learning.ErrNotFound):
		// Terminal translation: caller never branches on
		// learning.ErrNotFound past this point, so %s (not %w) is
		// deliberate — the message is the entire contract.
		return nil, EndSessionOutput{}, fmt.Errorf("session %s not found", sessionID)
	case err != nil:
		return nil, EndSessionOutput{}, fmt.Errorf("looking up session %s: %w", sessionID, err)
	case existing.EndedAt != nil:
		return nil, EndSessionOutput{}, fmt.Errorf("session %s was already ended at %s", sessionID, existing.EndedAt.Format(time.RFC3339))
	}

	// Optionally create reflection agent_note entry. Reached only when
	// the session above is active; orphan-by-mistake closed.
	var noteID *uuid.UUID
	if input.Reflection != nil && *input.Reflection != "" {
		entry, noteErr := s.agentNotes.Create(ctx, &agentnote.CreateParams{
			Kind:      agentnote.KindReflection,
			CreatedBy: s.callerIdentity(ctx),
			Content:   *input.Reflection,
			EntryDate: s.today(),
		})
		if noteErr == nil {
			v := entry.ID
			noteID = &v
		} else {
			// best-effort: the reflection note is annotation, not core
			// to ending the session. Log the failure and proceed
			// without a linked note — caller's EndSessionOutput.Session
			// will carry agent_note_id=nil; they may follow up with
			// write_agent_note(kind=reflection) if the reflection is
			// load-bearing. Hard-failing end_session on a note write
			// would couple the session lifecycle to agent_notes
			// availability without a payoff.
			s.logger.Warn("end_session: agent note creation failed", "error", noteErr)
		}
	}

	session, err := s.learn.EndSession(ctx, sessionID, noteID)
	if err != nil {
		switch {
		case errors.Is(err, learning.ErrNotFound):
			return nil, EndSessionOutput{}, fmt.Errorf("session %s not found", sessionID)
		case errors.Is(err, learning.ErrAlreadyEnded):
			// learning.Store.EndSession is documented to return a
			// non-nil session alongside ErrAlreadyEnded (both the
			// pre-flight branch and the race branch carry the loaded
			// row; handleEndSessionRace returns ErrNotFound separately
			// when the row was deleted). The nil guard below is
			// defensive against a future contract loosening — if it
			// fires we lose the timestamp but the caller still gets a
			// useful error message.
			endedAt := "unknown"
			if session != nil && session.EndedAt != nil {
				endedAt = session.EndedAt.Format(time.RFC3339)
				s.logger.Warn("end_session: raced with concurrent end after pre-flight passed",
					"session_id", sessionID, "ended_at", session.EndedAt)
			} else {
				s.logger.Warn("end_session: ErrAlreadyEnded with nil session — store contract violation",
					"session_id", sessionID)
			}
			return nil, EndSessionOutput{}, fmt.Errorf("session %s was already ended at %s", sessionID, endedAt)
		default:
			return nil, EndSessionOutput{}, fmt.Errorf("ending session: %w", err)
		}
	}

	attempts, _ := s.learn.AttemptsBySession(ctx, sessionID)

	duration := "unknown"
	if session.EndedAt != nil {
		dur := session.EndedAt.Sub(session.StartedAt)
		duration = fmt.Sprintf("%dm", int(dur.Minutes()))
	}

	s.logger.Info("end_session", "id", sessionID, "duration", duration, "attempts", len(attempts))
	return nil, EndSessionOutput{
		Session:  *session,
		Attempts: attempts,
		Duration: duration,
	}, nil
}

// --- learning_dashboard ---

type LearningDashboardInput struct {
	Domain           *string  `json:"domain,omitempty" jsonschema_description:"Filter by domain"`
	View             *string  `json:"view,omitempty" jsonschema_description:"View: overview (default), mastery, weaknesses, retrieval, timeline, variations"`
	WindowDays       FlexInt  `json:"window_days,omitempty" jsonschema_description:"Lookback window in days. Observations older than this are ignored. Defaults per view: mastery=60 (one Google interview prep cycle — avoids flicker for bursty practice), other views=30. Range 1..365."`
	ConfidenceFilter *string  `json:"confidence_filter,omitempty" jsonschema_description:"Only meaningful for mastery and weaknesses views. 'high' (default) restricts to directly-evidenced observations; 'all' includes coach-inferred (low confidence). Other views ignore this field."`
	DueWithinHours   *FlexInt `json:"due_within_hours,omitempty" jsonschema_description:"Retrieval view only. Extends the due cutoff into the future so the caller can preview what is due within the next N hours. Default 24 (today's review window — includes items due now plus those becoming due over the next day, the typical morning-review usage). Pass 0 for strict 'due-right-now' (use to confirm zero overdue items). Pass up to 168 (one week) for broader pre-review planning. Other views ignore this field."`
}

// LearningDashboardOutput is the dashboard tool's response.
//
// The struct tags on this type do NOT reflect the actual JSON output.
// MarshalJSON below is authoritative — it emits only the view-
// specific field (always as []T, never nil), plus view and total.
// Other views' fields are stripped to keep payload lean. When adding a
// field, update MarshalJSON's switch or the tests will skip coverage
// of the new view. The tags here are for Go-side scanning/reflection;
// the wire format is what MarshalJSON writes.
type LearningDashboardOutput struct {
	View          string                     `json:"view"`
	Total         int                        `json:"total"`
	DomainWarning string                     `json:"domain_warning,omitempty"`
	Sessions      []learning.Session         `json:"sessions,omitempty"`
	Mastery       []MasteryRow               `json:"mastery,omitempty"`
	Weaknesses    []learning.WeaknessRow     `json:"weaknesses,omitempty"`
	Retrieval     []learning.RetrievalTarget `json:"retrieval,omitempty"`
	Timeline      []learning.TimelineSession `json:"timeline,omitempty"`
	Variations    []learning.TargetRelation  `json:"variations,omitempty"`
}

// MarshalJSON emits {view, total, <view_key>: [...]} — the view-specific
// slice is always present (as [] on empty) and other view keys are
// absent. This keeps the wire shape stable regardless of whether the
// view has data, so a client iterating response.mastery never hits
// undefined or the wrong-key branch.
//
//nolint:gocritic // hugeParam: stdlib json.Marshaler interface takes value receiver
func (o LearningDashboardOutput) MarshalJSON() ([]byte, error) {
	base := map[string]any{"view": o.View, "total": o.Total}
	if o.DomainWarning != "" {
		base["domain_warning"] = o.DomainWarning
	}
	switch o.View {
	case "overview":
		base["sessions"] = ensureSlice(o.Sessions)
	case "mastery":
		base["mastery"] = ensureSlice(o.Mastery)
	case "weaknesses":
		base["weaknesses"] = ensureSlice(o.Weaknesses)
	case "retrieval":
		base["retrieval"] = ensureSlice(o.Retrieval)
	case "timeline":
		base["timeline"] = ensureSlice(o.Timeline)
	case "variations":
		base["variations"] = ensureSlice(o.Variations)
	}
	return json.Marshal(base)
}

// ensureSlice converts a nil slice to an empty one of the same type so
// encoding/json emits `[]` instead of `null`. Callers iterating the
// result must not hit a nil dereference.
func ensureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// MasteryRow is the MCP dashboard representation of a concept's mastery state —
// the raw signal counts from the learning store plus a derived stage.
type MasteryRow struct {
	ID                uuid.UUID             `json:"id"`
	Slug              string                `json:"slug"`
	Name              string                `json:"name"`
	Domain            string                `json:"domain"`
	Kind              string                `json:"kind"`
	WeaknessCount     int64                 `json:"weakness_count"`
	ImprovementCount  int64                 `json:"improvement_count"`
	MasteryCount      int64                 `json:"mastery_count"`
	TotalObservations int64                 `json:"total_observations"`
	Stage             learning.MasteryStage `json:"stage"`
	FirstObservedAt   time.Time             `json:"first_observed_at"`
	LastObservedAt    time.Time             `json:"last_observed_at"`
}

// toMasteryRows converts learning.ConceptMasteryRow slice (raw counts) to
// the dashboard MasteryRow shape with stage derivation.
func toMasteryRows(rows []learning.ConceptMasteryRow) []MasteryRow {
	out := make([]MasteryRow, len(rows))
	for i := range rows {
		r := &rows[i]
		out[i] = MasteryRow{
			ID:                r.ID,
			Slug:              r.Slug,
			Name:              r.Name,
			Domain:            r.Domain,
			Kind:              r.Kind,
			WeaknessCount:     r.WeaknessCount,
			ImprovementCount:  r.ImprovementCount,
			MasteryCount:      r.MasteryCount,
			TotalObservations: r.TotalObservations,
			Stage:             learning.DeriveMasteryStage(r.WeaknessCount, r.ImprovementCount, r.MasteryCount),
			FirstObservedAt:   r.FirstObservedAt,
			LastObservedAt:    r.LastObservedAt,
		}
	}
	return out
}

// defaultDaysForView is the per-view fallback for the lookback window when
// the caller doesn't pass `days`. Mastery defaults to 60 because that's
// the practitioner's mental horizon for "am I still good at this pattern" —
// roughly one Google interview prep cycle. The audit's reasoning was:
// 30-day window makes pattern stages flicker for someone whose practice
// is intentionally bursty (3 weeks of DP, 5 weeks of system design, then
// back). Other views use 30 because their data is more session-grained
// and a longer window adds noise without adding signal.
func defaultDaysForView(view string) int {
	if view == "mastery" {
		return 60
	}
	return 30
}

func (s *Server) learningDashboard(ctx context.Context, _ *mcp.CallToolRequest, input LearningDashboardInput) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	view := "overview"
	if input.View != nil && *input.View != "" {
		view = *input.View
	}

	windowDays := clamp(int(input.WindowDays), 1, 365, defaultDaysForView(view))
	since := time.Now().AddDate(0, 0, -windowDays)

	var domain *string
	var domainWarning string
	if input.Domain != nil && *input.Domain != "" {
		domain = input.Domain
		// Check the domain exists so an unknown slug surfaces as a warning
		// next to the empty result instead of looking like "you have no
		// activity in that domain". One extra query, but only when the
		// caller passed a domain filter — happy path is unaffected.
		exists, dErr := s.learn.DomainExists(ctx, *input.Domain)
		if dErr != nil {
			s.logger.Warn("learning_dashboard: domain existence check failed", "domain", *input.Domain, "error", dErr)
		} else if !exists {
			domainWarning = fmt.Sprintf("domain %q not found in learning_domains; result is empty because the slug is unknown, not because the domain has no activity", *input.Domain)
		}
	}

	// confidence_filter is meaningful only on mastery and weaknesses.
	// Pass the raw value (or empty) through to the store; normalization +
	// validation lives in learning.normalizeConfidenceFilter so there is
	// exactly one place that decides what is legal. Do NOT pre-coerce
	// invalid values to "high" here — that would silently swallow typos
	// like "hi" and make the store-side guard dead code. An invalid value
	// will come back as learning.ErrInvalidInput and surface as a normal
	// tool error to the caller.
	var confidenceFilter string
	if input.ConfidenceFilter != nil {
		confidenceFilter = *input.ConfidenceFilter
	}

	dueWithinHours := resolveDueWithinHours(input.DueWithinHours)

	var (
		result LearningDashboardOutput
		err    error
	)
	switch view {
	case "overview":
		result, err = s.dashboardOverview(ctx, domain, since)
	case "mastery":
		result, err = s.dashboardMastery(ctx, domain, since, confidenceFilter)
	case "weaknesses":
		result, err = s.dashboardWeaknesses(ctx, domain, since, confidenceFilter)
	case "retrieval":
		result, err = s.dashboardRetrieval(ctx, domain, dueWithinHours)
	case "timeline":
		result, err = s.dashboardTimeline(ctx, domain, since)
	case "variations":
		result, err = s.dashboardVariations(ctx, domain)
	default:
		return nil, LearningDashboardOutput{}, fmt.Errorf("unknown view %q", view)
	}
	if err == nil {
		result.DomainWarning = domainWarning
	}
	return nil, result, err
}

func (s *Server) dashboardOverview(ctx context.Context, domain *string, since time.Time) (LearningDashboardOutput, error) {
	sessions, err := s.learn.RecentSessions(ctx, domain, since, 50)
	if err != nil {
		return LearningDashboardOutput{}, fmt.Errorf("querying sessions: %w", err)
	}
	return LearningDashboardOutput{
		View:     "overview",
		Sessions: sessions,
		Total:    len(sessions),
	}, nil
}

func (s *Server) dashboardMastery(ctx context.Context, domain *string, since time.Time, confidenceFilter string) (LearningDashboardOutput, error) {
	rows, err := s.learn.ConceptMastery(ctx, domain, since, nil, confidenceFilter)
	if err != nil {
		return LearningDashboardOutput{}, fmt.Errorf("querying concept mastery: %w", err)
	}
	mastery := toMasteryRows(rows)
	return LearningDashboardOutput{
		View:    "mastery",
		Mastery: mastery,
		Total:   len(mastery),
	}, nil
}

func (s *Server) dashboardWeaknesses(ctx context.Context, domain *string, since time.Time, confidenceFilter string) (LearningDashboardOutput, error) {
	rows, err := s.learn.WeaknessAnalysis(ctx, domain, since, confidenceFilter)
	if err != nil {
		return LearningDashboardOutput{}, fmt.Errorf("querying weakness analysis: %w", err)
	}
	return LearningDashboardOutput{
		View:       "weaknesses",
		Weaknesses: rows,
		Total:      len(rows),
	}, nil
}

func (s *Server) dashboardRetrieval(ctx context.Context, domain *string, dueWithinHours int) (LearningDashboardOutput, error) {
	// due_within_hours extends the cutoff into the future — 0 keeps the
	// original behavior (only cards already due). Clamp happens at the
	// caller; this method just applies it.
	dueBefore := time.Now().Add(time.Duration(dueWithinHours) * time.Hour)
	items, err := s.learn.RetrievalQueue(ctx, domain, dueBefore, 50)
	if err != nil {
		return LearningDashboardOutput{}, fmt.Errorf("querying retrieval queue: %w", err)
	}
	return LearningDashboardOutput{
		View:      "retrieval",
		Retrieval: items,
		Total:     len(items),
	}, nil
}

func (s *Server) dashboardTimeline(ctx context.Context, domain *string, since time.Time) (LearningDashboardOutput, error) {
	sessions, err := s.learn.SessionTimeline(ctx, domain, since)
	if err != nil {
		return LearningDashboardOutput{}, fmt.Errorf("querying session timeline: %w", err)
	}
	return LearningDashboardOutput{
		View:     "timeline",
		Timeline: sessions,
		Total:    len(sessions),
	}, nil
}

func (s *Server) dashboardVariations(ctx context.Context, domain *string) (LearningDashboardOutput, error) {
	relations, err := s.learn.TargetVariations(ctx, domain, 100)
	if err != nil {
		return LearningDashboardOutput{}, fmt.Errorf("querying target variations: %w", err)
	}
	return LearningDashboardOutput{
		View:       "variations",
		Variations: relations,
		Total:      len(relations),
	}, nil
}

// resolveAttemptSession returns the active session iff sessionID matches it,
// otherwise produces a caller-facing error that distinguishes the three
// failure modes (id not found / id ended / wrong session is active). The
// extra SessionByID lookup runs only on error paths so the happy-path
// query count is unchanged.
func (s *Server) resolveAttemptSession(ctx context.Context, sessionID uuid.UUID) (*learning.Session, error) {
	active, err := s.learn.ActiveSession(ctx)
	if err != nil {
		// No active session at all. Look up sessionID directly so we can
		// say whether the caller has a stale id, an ended id, or really
		// hit the no-active-session path.
		looked, lookupErr := s.learn.SessionByID(ctx, sessionID)
		switch {
		case lookupErr == nil && looked.EndedAt != nil:
			return nil, fmt.Errorf("%w: session %s was ended at %s; start a new one", learning.ErrInvalidInput, sessionID, looked.EndedAt.Format(time.RFC3339))
		case errors.Is(lookupErr, learning.ErrNotFound):
			return nil, fmt.Errorf("%w: session %s not found", learning.ErrInvalidInput, sessionID)
		default:
			return nil, fmt.Errorf("no active session: %w", err)
		}
	}
	if active.ID == sessionID {
		return active, nil
	}
	// There IS an active session, just not the one the caller named.
	// Surface the active session id so the caller can self-correct.
	looked, lookupErr := s.learn.SessionByID(ctx, sessionID)
	switch {
	case errors.Is(lookupErr, learning.ErrNotFound):
		return nil, fmt.Errorf("%w: session %s not found (active session is %s)", learning.ErrInvalidInput, sessionID, active.ID)
	case lookupErr == nil && looked.EndedAt != nil:
		return nil, fmt.Errorf("%w: session %s was ended at %s (active session is %s)", learning.ErrInvalidInput, sessionID, looked.EndedAt.Format(time.RFC3339), active.ID)
	default:
		return nil, fmt.Errorf("%w: session %s is not the active session (active session is %s)", learning.ErrInvalidInput, sessionID, active.ID)
	}
}

// processObservations persists every observation. Confidence is an attribute,
// not a gate — high (default) and low both write to attempt_observations and
// the dashboard reads filter at query time via confidence_filter. This
// replaces the prior pending-observations roundtrip which silently dropped
// low-confidence signals on the next conversation turn.
//
// Per-observation failures (concept lookup, invalid confidence, insert) are
// logged and skipped; they do not fail the surrounding attempt. Confidence
// validation lives in learning.normalizeObservationConfidence — this path
// passes the raw value through (empty becomes "high" inside the store) so
// a typo like "hig" surfaces as a skipped observation with a clear warning
// rather than being silently rewritten to "high" here.
//
// Pre-validation: concept slug format and observation category membership
// are checked at this boundary so a malformed input produces an actionable
// warning ("category 'X' not valid for domain 'Y'; valid: ...") rather
// than a raw SQLSTATE 23514 / 23503 leak from the store. The category set
// is fetched once per call.
func (s *Server) processObservations(ctx context.Context, attemptID uuid.UUID, domain string, observations []ObservationInput) (recorded int, warnings []string, concepts []ConceptRef) {
	caller := s.callerIdentity(ctx)
	validCategories, catErr := s.learn.ObservationCategoriesByDomain(ctx, domain)
	if catErr != nil {
		// Failure here means the category list is unknown for this call;
		// fall back to allowing every category and let any FK violation
		// surface as a wrapped warning per-observation. Surface the skip
		// as a top-level warning so the caller doesn't silently pay the
		// raw-DB-error cost without knowing why pre-validation didn't
		// catch a typo.
		s.logger.Warn("observation: failed to load category list, skipping pre-validation", "domain", domain, "error", catErr)
		warnings = append(warnings, fmt.Sprintf("category pre-validation skipped for domain %q: %v — typo'd categories will reach the DB and may surface as raw FK errors instead of named values", domain, catErr))
		validCategories = nil
	}

	// Dedupe concepts by slug — a coach typically lists the same concept
	// across multiple observations of the same attempt, but the response
	// shouldn't repeat the (slug, id) pair.
	seen := make(map[string]struct{}, len(observations))

	for i := range observations {
		obs := &observations[i]

		if err := validateSlug("concept slug", obs.Concept); err != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): rejected and not persisted — %v", i, obs.Concept, err))
			continue
		}

		if validCategories != nil && !slices.Contains(validCategories, obs.Category) {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): rejected and not persisted — category %q not valid for domain %q. Valid categories: %v", i, obs.Concept, obs.Category, domain, validCategories))
			continue
		}

		conceptID, err := s.learn.FindOrCreateConcept(ctx, obs.Concept, obs.Concept, domain, "skill", caller)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): rejected and not persisted — concept creation failed: %v", i, obs.Concept, err))
			s.logger.Warn("observation: concept creation failed", "concept", obs.Concept, "error", err)
			continue
		}
		if _, err := s.learn.RecordObservation(ctx, attemptID, conceptID, obs.Signal, obs.Category, obs.Severity, obs.Detail, obs.Confidence, int32(i)); err != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): rejected and not persisted — recording failed: %v", i, obs.Concept, err))
			s.logger.Warn("observation: recording failed", "concept", obs.Concept, "confidence", obs.Confidence, "error", err)
			continue
		}
		recorded++
		if _, dup := seen[obs.Concept]; !dup {
			seen[obs.Concept] = struct{}{}
			concepts = append(concepts, ConceptRef{Slug: obs.Concept, ID: conceptID.String()})
		}
	}
	return recorded, warnings, concepts
}
