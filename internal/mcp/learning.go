package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/journal"
	"github.com/Koopa0/koopa0.dev/internal/learning"
)

// --- start_session ---

type StartSessionInput struct {
	Domain          string  `json:"domain" jsonschema:"required" jsonschema_description:"Learning domain (e.g. leetcode, japanese, system-design)"`
	Mode            string  `json:"mode" jsonschema:"required" jsonschema_description:"Session mode: retrieval, practice, mixed, review, reading"`
	DailyPlanItemID *string `json:"daily_plan_item_id,omitempty" jsonschema_description:"Optional UUID linking to daily plan"`
}

type StartSessionOutput struct {
	Session learning.Session `json:"session"`
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

	session, err := s.learn.StartSession(ctx, input.Domain, mode, planItemID)
	if err != nil {
		return nil, StartSessionOutput{}, fmt.Errorf("starting session: %w", err)
	}

	s.logger.Info("start_session", "id", session.ID, "domain", input.Domain, "mode", input.Mode)
	return nil, StartSessionOutput{Session: *session}, nil
}

// --- record_attempt ---

type RecordAttemptInput struct {
	SessionID    string             `json:"session_id" jsonschema:"required" jsonschema_description:"Active session UUID"`
	Item         AttemptItem        `json:"item" jsonschema:"required" jsonschema_description:"Learning item"`
	Outcome      string             `json:"outcome" jsonschema:"required" jsonschema_description:"Semantic (got it, needed help, etc) or raw enum"`
	Duration     *FlexInt           `json:"duration_minutes,omitempty" jsonschema_description:"Time spent in minutes"`
	StuckAt      *string            `json:"stuck_at,omitempty" jsonschema_description:"Where you got stuck (free text)"`
	Approach     *string            `json:"approach_used,omitempty" jsonschema_description:"Approach used (free text)"`
	Observations []ObservationInput `json:"observations,omitempty" jsonschema_description:"Concept observations"`
	Metadata     json.RawMessage    `json:"metadata,omitempty" jsonschema_description:"Free-form JSON for 8-step checklist outputs: complexity {time,space}, pattern, related problem slugs, solve context. Persisted on attempts.metadata."`
	FSRSRating   *int               `json:"fsrs_rating,omitempty" jsonschema_description:"Optional FSRS recall-difficulty override (1=Again, 2=Hard, 3=Good, 4=Easy). When set, this replaces the outcome-derived rating for spaced repetition scheduling. Use when recall difficulty diverges from solve outcome — e.g. solved but painful recall, or needed help but core concept is solid."`
	RelatedItems []RelatedItemInput `json:"related_items,omitempty" jsonschema_description:"Learning items related to the attempted item (variations, follow-ups, prerequisites). Each entry is find-or-created then linked via item_relations. Same-domain only; cross-domain relations are rejected with a warning."`
}

type AttemptItem struct {
	Title      string  `json:"title" jsonschema:"required"`
	ExternalID *string `json:"external_id,omitempty"`
	Domain     *string `json:"domain,omitempty"`
	Difficulty *string `json:"difficulty,omitempty"`
}

// RelatedItemInput describes a learning item related to the attempted item,
// used by record_attempt to record item_relations (variation graph).
// The target item is resolved via find-or-create semantics (same as AttemptItem),
// then a directed relation source→target is inserted with the given relation_type.
type RelatedItemInput struct {
	Title        string  `json:"title" jsonschema:"required" jsonschema_description:"Target item title"`
	ExternalID   *string `json:"external_id,omitempty" jsonschema_description:"Target item provider ID (e.g. LeetCode number)"`
	Domain       *string `json:"domain,omitempty" jsonschema_description:"Target item domain — defaults to the session/source domain; must match source domain"`
	Difficulty   *string `json:"difficulty,omitempty"`
	RelationType string  `json:"relation_type" jsonschema:"required" jsonschema_description:"How target relates to the attempted item. Allowed: easier_variant, harder_variant, prerequisite, follow_up, same_pattern, similar_structure"`
}

type ObservationInput struct {
	Concept    string  `json:"concept" jsonschema:"required" jsonschema_description:"Concept slug"`
	Signal     string  `json:"signal" jsonschema:"required" jsonschema_description:"weakness, improvement, or mastery"`
	Category   string  `json:"category" jsonschema:"required" jsonschema_description:"Domain-specific category"`
	Severity   *string `json:"severity,omitempty" jsonschema_description:"minor, moderate, critical (weakness only)"`
	Detail     *string `json:"detail,omitempty"`
	Confidence string  `json:"confidence,omitempty" jsonschema_description:"high (default — directly evidenced) or low (coach inferred). Both persist; mastery and weakness views default to high only but accept confidence_filter='all'."`
}

type RecordAttemptOutput struct {
	Attempt              learning.Attempt  `json:"attempt"`
	ObservationsRecorded int               `json:"observations_recorded"`
	ObservationWarnings  []string          `json:"observation_warnings,omitempty"`
	PlanContext          []PlanContextItem `json:"plan_context,omitempty"`
	RelationsLinked      int               `json:"relations_linked,omitempty"`
	RelationWarnings     []string          `json:"relation_warnings,omitempty"`
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

// PlanContextItem represents a learning plan item that contains the attempted item.
// Returned by record_attempt so Claude can decide whether to mark plan items as completed.
type PlanContextItem struct {
	PlanID    string `json:"plan_id"`
	PlanTitle string `json:"plan_title"`
	ItemID    string `json:"item_id"`
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

	attempt, err := s.learn.RecordAttempt(ctx, prep.itemID, prep.sessionID, prep.outcome, prep.duration, input.StuckAt, input.Approach, input.Metadata)
	if err != nil {
		return nil, RecordAttemptOutput{}, err
	}
	attempt.ItemTitle = input.Item.Title
	attempt.ItemExternalID = input.Item.ExternalID

	// Side effects: none of these fail the attempt — each helper logs its own
	// failures and returns a best-effort result so the caller still gets a
	// persisted attempt record. updateFSRSReview returns a bool surfaced in
	// the output so callers can detect silent review-card data loss.
	recorded, obsWarnings := s.processObservations(ctx, attempt.ID, prep.domain, input.Observations)
	fsrsFailed := s.updateFSRSReview(ctx, prep.itemID, prep.outcome, input.FSRSRating)
	linked, relWarnings := s.processRelatedItems(ctx, prep.itemID, prep.domain, input.RelatedItems)
	planCtx := s.lookupPlanContext(ctx, prep.itemID)

	s.logger.Info("record_attempt",
		"session", prep.sessionID, "item", input.Item.Title, "outcome", prep.outcome,
		"observations", recorded, "observation_warnings", len(obsWarnings),
		"plan_context", len(planCtx),
		"relations_linked", linked, "relation_warnings", len(relWarnings),
		"fsrs_review_failed", fsrsFailed)
	return nil, RecordAttemptOutput{
		Attempt:              *attempt,
		ObservationsRecorded: recorded,
		ObservationWarnings:  obsWarnings,
		PlanContext:          planCtx,
		RelationsLinked:      linked,
		RelationWarnings:     relWarnings,
		FSRSReviewFailed:     fsrsFailed,
	}, nil
}

// prepareAttempt validates and resolves everything record_attempt needs before
// writing the attempt row: parses the session ID, confirms it is the active
// session, maps the semantic outcome to its schema enum, resolves the learning
// item (find-or-create with domain fallback from the session), clamps the
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

	outcome, err := learning.MapOutcome(session.Mode, input.Outcome)
	if err != nil {
		return attemptPrep{}, err
	}

	domain := session.Domain
	if input.Item.Domain != nil && *input.Item.Domain != "" {
		domain = *input.Item.Domain
	}
	itemID, err := s.learn.FindOrCreateItem(ctx, domain, input.Item.Title, input.Item.ExternalID, input.Item.Difficulty)
	if err != nil {
		return attemptPrep{}, err
	}

	if len(input.Metadata) > maxMetadataBytes {
		return attemptPrep{}, fmt.Errorf("%w: metadata exceeds %d bytes (got %d)", learning.ErrInvalidInput, maxMetadataBytes, len(input.Metadata))
	}
	if len(input.Metadata) > 0 && !json.Valid(input.Metadata) {
		return attemptPrep{}, fmt.Errorf("%w: metadata is not valid JSON", learning.ErrInvalidInput)
	}

	return attemptPrep{
		sessionID: sessionID,
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

// lookupPlanContext returns the active plan items that contain itemID, so
// record_attempt can expose plan membership to the caller. Lookup failures
// are logged and return an empty slice — plan context is auxiliary.
func (s *Server) lookupPlanContext(ctx context.Context, itemID uuid.UUID) []PlanContextItem {
	planItems, err := s.plans.ItemsByLearningItem(ctx, itemID)
	if err != nil {
		s.logger.Warn("record_attempt: plan context lookup failed", "item_id", itemID, "error", err)
		return nil
	}
	out := make([]PlanContextItem, 0, len(planItems))
	for i := range planItems {
		pi := &planItems[i]
		pci := PlanContextItem{
			PlanID:    pi.PlanID.String(),
			PlanTitle: pi.PlanTitle,
			ItemID:    pi.ID.String(),
			Position:  pi.Position,
			Status:    string(pi.Status),
		}
		if pi.Phase != nil {
			pci.Phase = *pi.Phase
		}
		out = append(out, pci)
	}
	return out
}

// updateFSRSReview applies a spaced-repetition review for itemID. When
// override is non-nil it is used directly (1..4 rating); otherwise the
// outcome string is mapped to a rating via the learning store.
//
// Returns true when the review card update failed — the attempt is still
// persisted, but the FSRS queue was not advanced. The caller should surface
// this bool in the tool response so agents can warn users or retry, instead
// of silently losing a review tick.
func (s *Server) updateFSRSReview(ctx context.Context, itemID uuid.UUID, outcome string, override *int) bool {
	now := time.Now()
	if override != nil {
		if _, err := s.learn.ReviewItemWithRating(ctx, itemID, *override, now); err != nil {
			s.logger.Warn("record_attempt: fsrs review (override) failed", "item_id", itemID, "rating", *override, "error", err)
			return true
		}
		return false
	}
	if _, err := s.learn.ReviewItem(ctx, itemID, outcome, now); err != nil {
		s.logger.Warn("record_attempt: fsrs review failed", "item_id", itemID, "error", err)
		return true
	}
	return false
}

// processRelatedItems resolves each RelatedItemInput to a learning item and
// links it to the source via item_relations. Per-entry errors become warnings
// — the caller still sees a successful attempt record.
//
// Domain handling: LinkItems in the store layer no longer enforces same-domain
// (to avoid N+1 lookups per attempt). This function is the enforcer. It uses
// sourceDomain as the default target domain; if the caller explicitly
// overrides with a different domain the entry is rejected as a cross-domain
// relation. Because the target is then resolved via FindOrCreateItem with
// sourceDomain, the inserted row is guaranteed same-domain by construction.
func (s *Server) processRelatedItems(ctx context.Context, sourceID uuid.UUID, sourceDomain string, items []RelatedItemInput) (linked int, warnings []string) {
	if len(items) == 0 {
		return 0, nil
	}
	for i := range items {
		ri := &items[i]
		if ri.Title == "" {
			warnings = append(warnings, fmt.Sprintf("related_items[%d]: title required", i))
			continue
		}
		if !learning.ValidRelationType(learning.RelationType(ri.RelationType)) {
			warnings = append(warnings, fmt.Sprintf("related_items[%d] (%q): unknown relation_type %q", i, ri.Title, ri.RelationType))
			continue
		}
		// Cross-domain rejection moved to this layer — source domain is already
		// in scope from prepareAttempt, no DB lookup needed.
		if ri.Domain != nil && *ri.Domain != "" && *ri.Domain != sourceDomain {
			warnings = append(warnings, fmt.Sprintf("related_items[%d] (%q): cross-domain relation rejected (source=%q, target=%q)", i, ri.Title, sourceDomain, *ri.Domain))
			continue
		}
		targetID, err := s.learn.FindOrCreateItem(ctx, sourceDomain, ri.Title, ri.ExternalID, ri.Difficulty)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("related_items[%d] (%q): find-or-create failed: %v", i, ri.Title, err))
			continue
		}
		if err := s.learn.LinkItems(ctx, sourceID, targetID, learning.RelationType(ri.RelationType)); err != nil {
			warnings = append(warnings, fmt.Sprintf("related_items[%d] (%q): link failed: %v", i, ri.Title, err))
			continue
		}
		linked++
	}
	return linked, warnings
}

// --- end_session ---

type EndSessionInput struct {
	SessionID  string  `json:"session_id" jsonschema:"required" jsonschema_description:"Session UUID to end"`
	Reflection *string `json:"reflection,omitempty" jsonschema_description:"Optional reflection text (creates journal entry)"`
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

	// Optionally create reflection journal entry.
	var journalID *int64
	if input.Reflection != nil && *input.Reflection != "" {
		entry, jErr := s.journal.Create(ctx, &journal.CreateParams{
			Kind:      journal.KindReflection,
			Source:    s.callerIdentity(ctx),
			Content:   *input.Reflection,
			EntryDate: s.today(),
		})
		if jErr == nil {
			journalID = &entry.ID
		} else {
			s.logger.Warn("end_session: journal creation failed", "error", jErr)
		}
	}

	session, err := s.learn.EndSession(ctx, sessionID, journalID)
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
}

type LearningDashboardOutput struct {
	View       string                     `json:"view"`
	Total      int                        `json:"total"`
	Sessions   []learning.Session         `json:"sessions,omitempty"`
	Mastery    []MasteryRow               `json:"mastery,omitempty"`
	Weaknesses []learning.WeaknessRow     `json:"weaknesses,omitempty"`
	Retrieval  []learning.RetrievalItem   `json:"retrieval,omitempty"`
	Timeline   []learning.TimelineSession `json:"timeline,omitempty"`
	Variations []learning.ItemRelation    `json:"variations,omitempty"`
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

	switch view {
	case "overview":
		return s.dashboardOverview(ctx, domain, since)
	case "mastery":
		return s.dashboardMastery(ctx, domain, since, confidenceFilter)
	case "weaknesses":
		return s.dashboardWeaknesses(ctx, domain, since, confidenceFilter)
	case "retrieval":
		return s.dashboardRetrieval(ctx, domain)
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

func (s *Server) dashboardRetrieval(ctx context.Context, domain *string) (*mcp.CallToolResult, LearningDashboardOutput, error) {
	items, err := s.learn.RetrievalQueue(ctx, domain, time.Now(), 50)
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
	relations, err := s.learn.ItemVariations(ctx, domain, 100)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying item variations: %w", err)
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
		conceptID, cErr := s.learn.FindOrCreateConcept(ctx, obs.Concept, obs.Concept, domain, "skill")
		if cErr != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): concept creation failed: %v", i, obs.Concept, cErr))
			s.logger.Warn("observation: concept creation failed", "concept", obs.Concept, "error", cErr)
			continue
		}
		if _, oErr := s.learn.RecordObservation(ctx, attemptID, conceptID, obs.Signal, obs.Category, obs.Severity, obs.Detail, obs.Confidence); oErr != nil {
			warnings = append(warnings, fmt.Sprintf("observations[%d] (%q): record failed: %v", i, obs.Concept, oErr))
			s.logger.Warn("observation: recording failed", "concept", obs.Concept, "confidence", obs.Confidence, "error", oErr)
			continue
		}
		recorded++
	}
	return recorded, warnings
}
