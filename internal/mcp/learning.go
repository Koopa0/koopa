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
	StuckAt        *string              `json:"stuck_at,omitempty" jsonschema_description:"Where you got stuck (free text)"`
	Approach       *string              `json:"approach_used,omitempty" jsonschema_description:"Approach used (free text)"`
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
	Severity   *string `json:"severity,omitempty" jsonschema_description:"minor, moderate, or critical. WEAKNESS SIGNAL ONLY — setting severity on an improvement or mastery observation causes that observation to be skipped with a message in observation_warnings (the rest of the attempt still persists). Leave unset for non-weakness signals."`
	Detail     *string `json:"detail,omitempty"`
	Confidence string  `json:"confidence,omitempty" jsonschema_description:"high (default — directly evidenced) or low (coach inferred). Both persist; mastery and weakness views default to high only but accept confidence_filter='all'."`
}

type RecordAttemptOutput struct {
	Attempt learning.Attempt `json:"attempt"`
	// CanonicalOutcome echoes the storage-form outcome that the caller's
	// input mapped to. record_attempt accepts semantic synonyms (e.g.
	// "needed help" → solved_with_hint); without this field the coach
	// must introspect Attempt.Outcome to see what got normalized. Always
	// populated; no omitempty.
	CanonicalOutcome     string             `json:"canonical_outcome"`
	ObservationsRecorded int                `json:"observations_recorded"`
	ObservationWarnings  []string           `json:"observation_warnings,omitempty"`
	PlanContext          []PlanContextEntry `json:"plan_context,omitempty"`
	RelationsLinked      int                `json:"relations_linked,omitempty"`
	RelationWarnings     []string           `json:"relation_warnings,omitempty"`
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
	// loss).
	recorded, obsWarnings := s.processObservations(ctx, attempt.ID, prep.domain, input.Observations)
	fsrsRating, fsrsFailed := s.updateFSRSReview(ctx, prep.itemID, prep.outcome, input.FSRSRating)
	linked, relWarnings := s.processRelatedTargets(ctx, prep.itemID, prep.domain, input.RelatedTargets)
	planCtx := s.lookupPlanContext(ctx, prep.itemID)

	s.logger.Info("record_attempt",
		"session", prep.sessionID, "target", input.Target.Title, "outcome", prep.outcome,
		"observations", recorded, "observation_warnings", len(obsWarnings),
		"plan_context", len(planCtx),
		"relations_linked", linked, "relation_warnings", len(relWarnings),
		"fsrs_review_failed", fsrsFailed)
	return nil, RecordAttemptOutput{
		Attempt:              *attempt,
		CanonicalOutcome:     prep.outcome,
		ObservationsRecorded: recorded,
		ObservationWarnings:  obsWarnings,
		PlanContext:          planCtx,
		RelationsLinked:      linked,
		RelationWarnings:     relWarnings,
		FSRSRatingApplied:    fsrsRating,
		FSRSReviewFailed:     fsrsFailed,
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

	session, err := s.learn.ActiveSession(ctx)
	if err != nil {
		return attemptPrep{}, fmt.Errorf("no active session: %w", err)
	}
	if session.ID != sessionID {
		return attemptPrep{}, fmt.Errorf("%w: session %s is not the active session", learning.ErrInvalidInput, sessionID)
	}

	paradigm, outcome, err := learning.MapOutcome(session.Mode, input.Outcome)
	if err != nil {
		return attemptPrep{}, err
	}

	domain := session.Domain
	if input.Target.Domain != nil && *input.Target.Domain != "" {
		domain = *input.Target.Domain
	}
	itemID, err := s.learn.FindOrCreateTarget(ctx, domain, input.Target.Title, input.Target.ExternalID, input.Target.Difficulty)
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
// Returns the rating actually applied and a "failed" flag.
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
func (s *Server) updateFSRSReview(ctx context.Context, targetID uuid.UUID, outcome string, override *FlexInt) (applied *int, failed bool) {
	now := time.Now()
	if override != nil {
		rating := int(*override)
		if _, err := s.fsrs.ReviewByRating(ctx, targetID, rating, now); err != nil {
			s.logger.Warn("record_attempt: fsrs review (override) failed", "target_id", targetID, "rating", rating, "error", err)
			s.markFSRSDrift(ctx, targetID, "rating_override_failed")
			return &rating, true
		}
		return &rating, false
	}

	derived, derivErr := fsrs.RatingFromOutcome(outcome)
	if derivErr != nil {
		// Unknown outcome — no rating to echo. ReviewByOutcome will return
		// the same error; let it run so the drift marker still fires.
		s.logger.Warn("record_attempt: fsrs review failed", "target_id", targetID, "reason", "unknown_outcome", "error", derivErr)
		s.markFSRSDrift(ctx, targetID, "unknown_outcome")
		return nil, true
	}

	if _, err := s.fsrs.ReviewByOutcome(ctx, targetID, outcome, now); err != nil {
		// outcome is user-controlled — log only the sentinel branch so the
		// raw value never reaches the log stream.
		reason := "review_failed"
		if errors.Is(err, fsrs.ErrUnknownOutcome) {
			reason = "unknown_outcome"
		}
		s.logger.Warn("record_attempt: fsrs review failed", "target_id", targetID, "reason", reason, "error", err)
		s.markFSRSDrift(ctx, targetID, reason)
		return &derived, true
	}
	return &derived, false
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
func (s *Server) processRelatedTargets(ctx context.Context, sourceID uuid.UUID, sourceDomain string, items []RelatedTargetInput) (linked int, warnings []string) {
	if len(items) == 0 {
		return 0, nil
	}
	for i := range items {
		ri := &items[i]
		if ri.Title == "" {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d]: title required", i))
			continue
		}
		if !learning.ValidRelationType(learning.RelationType(ri.RelationType)) {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): unknown relation_type %q", i, ri.Title, ri.RelationType))
			continue
		}
		// Cross-domain rejection moved to this layer — source domain is already
		// in scope from prepareAttempt, no DB lookup needed.
		if ri.Domain != nil && *ri.Domain != "" && *ri.Domain != sourceDomain {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): cross-domain relation rejected (source=%q, target=%q)", i, ri.Title, sourceDomain, *ri.Domain))
			continue
		}
		targetID, err := s.learn.FindOrCreateTarget(ctx, sourceDomain, ri.Title, ri.ExternalID, ri.Difficulty)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): find-or-create failed: %v", i, ri.Title, err))
			continue
		}
		if err := s.learn.LinkTargets(ctx, sourceID, targetID, learning.RelationType(ri.RelationType)); err != nil {
			warnings = append(warnings, fmt.Sprintf("related_targets[%d] (%q): link failed: %v", i, ri.Title, err))
			continue
		}
		linked++
	}
	return linked, warnings
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
	sessionID, err := uuid.Parse(input.SessionID)
	if err != nil {
		return nil, EndSessionOutput{}, fmt.Errorf("invalid session_id: %w", err)
	}

	// Optionally create reflection agent_note entry.
	var noteID *uuid.UUID
	if input.Reflection != nil && *input.Reflection != "" {
		entry, err := s.agentNotes.Create(ctx, &agentnote.CreateParams{
			Kind:      agentnote.KindReflection,
			CreatedBy: s.callerIdentity(ctx),
			Content:   *input.Reflection,
			EntryDate: s.today(),
		})
		if err == nil {
			v := entry.ID
			noteID = &v
		} else {
			s.logger.Warn("end_session: agent note creation failed", "error", err)
		}
	}

	session, err := s.learn.EndSession(ctx, sessionID, noteID)
	if err != nil {
		return nil, EndSessionOutput{}, fmt.Errorf("ending session: %w", err)
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
	Domain           *string `json:"domain,omitempty" jsonschema_description:"Filter by domain"`
	View             *string `json:"view,omitempty" jsonschema_description:"View: overview (default), mastery, weaknesses, retrieval, timeline, variations"`
	WindowDays       FlexInt `json:"window_days,omitempty" jsonschema_description:"Lookback window in days. Observations older than this are ignored. Defaults per view: mastery=60 (one Google interview prep cycle — avoids flicker for bursty practice), other views=30. Range 1..365."`
	ConfidenceFilter *string `json:"confidence_filter,omitempty" jsonschema_description:"Only meaningful for mastery and weaknesses views. 'high' (default) restricts to directly-evidenced observations; 'all' includes coach-inferred (low confidence). Other views ignore this field."`
	DueWithinHours   FlexInt `json:"due_within_hours,omitempty" jsonschema_description:"Retrieval view only. Extends the due cutoff into the future so the caller can preview what is due within the next N hours — e.g. 24 to find cards due by tomorrow. Default 0 = only cards already due now. Range 0..168 (one week). Other views ignore this field."`
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
	View       string                     `json:"view"`
	Total      int                        `json:"total"`
	Sessions   []learning.Session         `json:"sessions,omitempty"`
	Mastery    []MasteryRow               `json:"mastery,omitempty"`
	Weaknesses []learning.WeaknessRow     `json:"weaknesses,omitempty"`
	Retrieval  []learning.RetrievalTarget `json:"retrieval,omitempty"`
	Timeline   []learning.TimelineSession `json:"timeline,omitempty"`
	Variations []learning.TargetRelation  `json:"variations,omitempty"`
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
	if input.Domain != nil && *input.Domain != "" {
		domain = input.Domain
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

	dueWithinHours := clamp(int(input.DueWithinHours), 0, 168, 0)

	switch view {
	case "overview":
		return s.dashboardOverview(ctx, domain, since)
	case "mastery":
		return s.dashboardMastery(ctx, domain, since, confidenceFilter)
	case "weaknesses":
		return s.dashboardWeaknesses(ctx, domain, since, confidenceFilter)
	case "retrieval":
		return s.dashboardRetrieval(ctx, domain, dueWithinHours)
	case "timeline":
		return s.dashboardTimeline(ctx, domain, since)
	case "variations":
		return s.dashboardVariations(ctx, domain)
	default:
		return nil, LearningDashboardOutput{}, fmt.Errorf("unknown view %q", view)
	}
}

func (s *Server) dashboardOverview(ctx context.Context, domain *string, since time.Time) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	sessions, err := s.learn.RecentSessions(ctx, domain, since, 50)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying sessions: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:     "overview",
		Sessions: sessions,
		Total:    len(sessions),
	}, nil
}

func (s *Server) dashboardMastery(ctx context.Context, domain *string, since time.Time, confidenceFilter string) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	rows, err := s.learn.ConceptMastery(ctx, domain, since, confidenceFilter)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying concept mastery: %w", err)
	}
	mastery := toMasteryRows(rows)
	return nil, LearningDashboardOutput{
		View:    "mastery",
		Mastery: mastery,
		Total:   len(mastery),
	}, nil
}

func (s *Server) dashboardWeaknesses(ctx context.Context, domain *string, since time.Time, confidenceFilter string) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	rows, err := s.learn.WeaknessAnalysis(ctx, domain, since, confidenceFilter)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying weakness analysis: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:       "weaknesses",
		Weaknesses: rows,
		Total:      len(rows),
	}, nil
}

func (s *Server) dashboardRetrieval(ctx context.Context, domain *string, dueWithinHours int) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	// due_within_hours extends the cutoff into the future — 0 keeps the
	// original behavior (only cards already due). Clamp happens at the
	// caller; this method just applies it.
	dueBefore := time.Now().Add(time.Duration(dueWithinHours) * time.Hour)
	items, err := s.learn.RetrievalQueue(ctx, domain, dueBefore, 50)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying retrieval queue: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:      "retrieval",
		Retrieval: items,
		Total:     len(items),
	}, nil
}

func (s *Server) dashboardTimeline(ctx context.Context, domain *string, since time.Time) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	sessions, err := s.learn.SessionTimeline(ctx, domain, since)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying session timeline: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:     "timeline",
		Timeline: sessions,
		Total:    len(sessions),
	}, nil
}

func (s *Server) dashboardVariations(ctx context.Context, domain *string) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	relations, err := s.learn.TargetVariations(ctx, domain, 100)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying target variations: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:       "variations",
		Variations: relations,
		Total:      len(relations),
	}, nil
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
func (s *Server) processObservations(ctx context.Context, attemptID uuid.UUID, domain string, observations []ObservationInput) (recorded int, warnings []string) {
	for i := range observations {
		obs := &observations[i]
		conceptID, err := s.learn.FindOrCreateConcept(ctx, obs.Concept, obs.Concept, domain, "skill")
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): concept creation failed: %v", i, obs.Concept, err))
			s.logger.Warn("observation: concept creation failed", "concept", obs.Concept, "error", err)
			continue
		}
		if _, err := s.learn.RecordObservation(ctx, attemptID, conceptID, obs.Signal, obs.Category, obs.Severity, obs.Detail, obs.Confidence, int32(i)); err != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): record failed: %v", i, obs.Concept, err))
			s.logger.Warn("observation: recording failed", "concept", obs.Concept, "confidence", obs.Confidence, "error", err)
			continue
		}
		recorded++
	}
	return recorded, warnings
}
