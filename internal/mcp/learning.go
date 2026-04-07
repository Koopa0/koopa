package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

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

func (s *Server) startSession(ctx context.Context, _ *sdkmcp.CallToolRequest, input StartSessionInput) (*sdkmcp.CallToolResult, StartSessionOutput, error) {
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
}

type AttemptItem struct {
	Title      string  `json:"title" jsonschema:"required"`
	ExternalID *string `json:"external_id,omitempty"`
	Domain     *string `json:"domain,omitempty"`
	Difficulty *string `json:"difficulty,omitempty"`
}

type ObservationInput struct {
	Concept    string  `json:"concept" jsonschema:"required" jsonschema_description:"Concept slug"`
	Signal     string  `json:"signal" jsonschema:"required" jsonschema_description:"weakness, improvement, or mastery"`
	Category   string  `json:"category" jsonschema:"required" jsonschema_description:"Domain-specific category"`
	Severity   *string `json:"severity,omitempty" jsonschema_description:"minor, moderate, critical (weakness only)"`
	Detail     *string `json:"detail,omitempty"`
	Confidence string  `json:"confidence,omitempty" jsonschema_description:"high or low (default high)"`
}

type RecordAttemptOutput struct {
	Attempt              learning.Attempt `json:"attempt"`
	ObservationsRecorded int                  `json:"observations_recorded"`
	PendingObservations  []ObservationInput   `json:"pending_observations,omitempty"`
}

//nolint:gocritic // hugeParam: input passed by value per addTool[I,O] generic contract
func (s *Server) recordAttempt(ctx context.Context, _ *sdkmcp.CallToolRequest, input RecordAttemptInput) (*sdkmcp.CallToolResult, RecordAttemptOutput, error) {
	sessionID, err := uuid.Parse(input.SessionID)
	if err != nil {
		return nil, RecordAttemptOutput{}, fmt.Errorf("invalid session_id: %w", err)
	}

	// Verify session is active.
	session, err := s.learn.ActiveSession(ctx)
	if err != nil {
		return nil, RecordAttemptOutput{}, fmt.Errorf("no active session: %w", err)
	}
	if session.ID != sessionID {
		return nil, RecordAttemptOutput{}, fmt.Errorf("session %s is not the active session", sessionID)
	}

	// Map outcome.
	outcome, err := learning.MapOutcome(session.Mode, input.Outcome)
	if err != nil {
		return nil, RecordAttemptOutput{}, err
	}

	// Find or create item.
	domain := session.Domain
	if input.Item.Domain != nil && *input.Item.Domain != "" {
		domain = *input.Item.Domain
	}
	itemID, err := s.learn.FindOrCreateItem(ctx, domain, input.Item.Title, input.Item.ExternalID, input.Item.Difficulty)
	if err != nil {
		return nil, RecordAttemptOutput{}, err
	}

	// Record attempt.
	var dur *int32
	if input.Duration != nil {
		d := clamp(int(*input.Duration), 1, 1440, 0) // cap at 24 hours
		if d > 0 {
			v := int32(d) // #nosec G115 — clamped above
			dur = &v
		}
	}
	var metadata json.RawMessage
	attempt, err := s.learn.RecordAttempt(ctx, itemID, sessionID, outcome, dur, input.StuckAt, input.Approach, metadata)
	if err != nil {
		return nil, RecordAttemptOutput{}, err
	}
	attempt.ItemTitle = input.Item.Title
	attempt.ItemExternalID = input.Item.ExternalID

	recorded, pending := s.processObservations(ctx, attempt.ID, domain, input.Observations)

	s.logger.Info("record_attempt", "session", sessionID, "item", input.Item.Title, "outcome", outcome,
		"observations", recorded, "pending", len(pending))
	return nil, RecordAttemptOutput{
		Attempt:              *attempt,
		ObservationsRecorded: recorded,
		PendingObservations:  pending,
	}, nil
}

// --- end_session ---

type EndSessionInput struct {
	SessionID  string  `json:"session_id" jsonschema:"required" jsonschema_description:"Session UUID to end"`
	Reflection *string `json:"reflection,omitempty" jsonschema_description:"Optional reflection text (creates journal entry)"`
}

type EndSessionOutput struct {
	Session  learning.Session   `json:"session"`
	Attempts []learning.Attempt `json:"attempts"`
	Duration string                 `json:"duration"`
}

func (s *Server) endSession(ctx context.Context, _ *sdkmcp.CallToolRequest, input EndSessionInput) (*sdkmcp.CallToolResult, EndSessionOutput, error) {
	sessionID, err := uuid.Parse(input.SessionID)
	if err != nil {
		return nil, EndSessionOutput{}, fmt.Errorf("invalid session_id: %w", err)
	}

	// Optionally create reflection journal entry.
	var journalID *int64
	if input.Reflection != nil && *input.Reflection != "" {
		entry, jErr := s.journal.Create(ctx, &journal.CreateParams{
			Kind:      journal.KindReflection,
			Source:    s.participant,
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
	Domain *string `json:"domain,omitempty" jsonschema_description:"Filter by domain"`
	View   *string `json:"view,omitempty" jsonschema_description:"View: overview (default), mastery, weaknesses, retrieval, timeline, variations"`
	Days   FlexInt `json:"days,omitempty" jsonschema_description:"Lookback period in days (default 30)"`
}

type LearningDashboardOutput struct {
	View       string                           `json:"view"`
	Total      int                              `json:"total"`
	Sessions   []learning.Session           `json:"sessions,omitempty"`
	Mastery    []learning.ConceptMasteryRow `json:"mastery,omitempty"`
	Weaknesses []learning.WeaknessRow       `json:"weaknesses,omitempty"`
	Retrieval  []learning.RetrievalItem     `json:"retrieval,omitempty"`
	Timeline   []learning.TimelineSession   `json:"timeline,omitempty"`
	Variations []learning.ItemRelation      `json:"variations,omitempty"`
}

func (s *Server) learningDashboard(ctx context.Context, _ *sdkmcp.CallToolRequest, input LearningDashboardInput) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
	days := clamp(int(input.Days), 1, 365, 30)
	since := time.Now().AddDate(0, 0, -days)

	view := "overview"
	if input.View != nil && *input.View != "" {
		view = *input.View
	}

	var domain *string
	if input.Domain != nil && *input.Domain != "" {
		domain = input.Domain
	}

	switch view {
	case "overview":
		return s.dashboardOverview(ctx, domain, since)
	case "mastery":
		return s.dashboardMastery(ctx, domain, since)
	case "weaknesses":
		return s.dashboardWeaknesses(ctx, domain, since)
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

func (s *Server) dashboardOverview(ctx context.Context, domain *string, since time.Time) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
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

func (s *Server) dashboardMastery(ctx context.Context, domain *string, since time.Time) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
	rows, err := s.learn.ConceptMastery(ctx, domain, since)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying concept mastery: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:    "mastery",
		Mastery: rows,
		Total:   len(rows),
	}, nil
}

func (s *Server) dashboardWeaknesses(ctx context.Context, domain *string, since time.Time) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
	rows, err := s.learn.WeaknessAnalysis(ctx, domain, since)
	if err != nil {
		return nil, LearningDashboardOutput{}, fmt.Errorf("querying weakness analysis: %w", err)
	}
	return nil, LearningDashboardOutput{
		View:       "weaknesses",
		Weaknesses: rows,
		Total:      len(rows),
	}, nil
}

func (s *Server) dashboardRetrieval(ctx context.Context, domain *string) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
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

func (s *Server) dashboardTimeline(ctx context.Context, domain *string, since time.Time) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
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

func (s *Server) dashboardVariations(ctx context.Context, domain *string) (*sdkmcp.CallToolResult, LearningDashboardOutput, error) {
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

// processObservations records high-confidence observations and returns low-confidence ones as pending.
func (s *Server) processObservations(ctx context.Context, attemptID uuid.UUID, domain string, observations []ObservationInput) (int, []ObservationInput) {
	var recorded int
	var pending []ObservationInput
	for i := range observations {
		obs := &observations[i]
		confidence := obs.Confidence
		if confidence == "" {
			confidence = "high"
		}
		if confidence == "low" {
			pending = append(pending, *obs)
			continue
		}

		conceptID, cErr := s.learn.FindOrCreateConcept(ctx, obs.Concept, obs.Concept, domain, "skill")
		if cErr != nil {
			s.logger.Warn("observation: concept creation failed", "concept", obs.Concept, "error", cErr)
			continue
		}
		if _, oErr := s.learn.RecordObservation(ctx, attemptID, conceptID, obs.Signal, obs.Category, obs.Severity, obs.Detail); oErr != nil {
			s.logger.Warn("observation: recording failed", "concept", obs.Concept, "error", oErr)
			continue
		}
		recorded++
	}
	return recorded, pending
}
