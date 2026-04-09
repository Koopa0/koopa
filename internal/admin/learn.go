package admin

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa0.dev/internal/api"
	"github.com/Koopa0/koopa0.dev/internal/learning"
)

// LearnDashboard handles GET /api/admin/learn/dashboard.
func (h *Handler) LearnDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	since30d := now.AddDate(0, 0, -30)

	type resp struct {
		DueReviewsCount int                          `json:"due_reviews_count"`
		DueReviewsToday int                          `json:"due_reviews_today"`
		RecentSessions  []learning.Session           `json:"recent_sessions"`
		WeaknessSpot    []learning.WeaknessRow       `json:"weakness_spotlight"`
		MasteryByDomain []learning.ConceptMasteryRow `json:"mastery_by_domain"`
		Streak          struct {
			CurrentDays int `json:"current_days"`
		} `json:"streak"`
	}

	var out resp

	if n, err := h.learn.DueReviewCount(ctx, now); err == nil {
		out.DueReviewsCount = n
	}
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, h.loc)
	if n, err := h.learn.DueReviewCount(ctx, endOfDay); err == nil {
		out.DueReviewsToday = n
	}

	if sessions, err := h.learn.RecentSessions(ctx, nil, since30d, 10); err == nil {
		out.RecentSessions = sessions
	} else {
		out.RecentSessions = []learning.Session{}
	}

	if ws, err := h.learn.WeaknessAnalysis(ctx, nil, since30d); err == nil {
		out.WeaknessSpot = ws
	} else {
		out.WeaknessSpot = []learning.WeaknessRow{}
	}

	if ms, err := h.learn.ConceptMastery(ctx, nil, since30d); err == nil {
		out.MasteryByDomain = ms
	} else {
		out.MasteryByDomain = []learning.ConceptMasteryRow{}
	}

	if s, err := h.learn.Streak(ctx); err == nil {
		out.Streak.CurrentDays = s
	}

	api.Encode(w, http.StatusOK, out)
}

// SessionStartRequest is the request body for POST /api/admin/learn/sessions/start.
type SessionStartRequest struct {
	Domain      string  `json:"domain"`
	SessionMode string  `json:"session_mode"`
	PlanItemID  *string `json:"daily_plan_item_id,omitempty"`
}

// SessionStart handles POST /api/admin/learn/sessions/start.
func (h *Handler) SessionStart(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[SessionStartRequest](w, r)
	if err != nil {
		return
	}
	if req.Domain == "" || req.SessionMode == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain and session_mode are required")
		return
	}

	var planItemID *uuid.UUID
	if req.PlanItemID != nil {
		id, pErr := uuid.Parse(*req.PlanItemID)
		if pErr != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid daily_plan_item_id")
			return
		}
		planItemID = &id
	}

	ctx := r.Context()
	session, err := h.learn.StartSession(ctx, req.Domain, learning.Mode(req.SessionMode), planItemID)
	if err != nil {
		h.logger.Error("session start", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	// Suggest items from retrieval queue.
	endOfDay := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 23, 59, 59, 0, h.loc)
	suggested, _ := h.learn.RetrievalQueue(ctx, &req.Domain, endOfDay, 10)
	if suggested == nil {
		suggested = []learning.RetrievalItem{}
	}

	api.Encode(w, http.StatusCreated, map[string]any{
		"session_id":      session.ID.String(),
		"suggested_items": suggested,
	})
}

// AttemptRequest is the request body for POST /api/admin/learn/sessions/{id}/attempt.
type AttemptRequest struct {
	ItemID          string             `json:"item_id"`
	ItemTitle       string             `json:"item_title,omitempty"`
	ItemDomain      string             `json:"item_domain,omitempty"`
	Outcome         string             `json:"outcome"`
	DurationMinutes *int32             `json:"duration_minutes,omitempty"`
	StuckAt         *string            `json:"stuck_at,omitempty"`
	ApproachUsed    *string            `json:"approach_used,omitempty"`
	Observations    []ObservationInput `json:"observations,omitempty"`
}

// ObservationInput is a single observation in an attempt request.
type ObservationInput struct {
	ConceptSlug string  `json:"concept_slug"`
	ConceptName string  `json:"concept_name,omitempty"`
	ConceptKind string  `json:"concept_kind,omitempty"`
	SignalType  string  `json:"signal_type"`
	Category    string  `json:"category"`
	Severity    *string `json:"severity,omitempty"`
	Detail      *string `json:"detail,omitempty"`
	Confidence  string  `json:"confidence"`
}

// SessionAttempt handles POST /api/admin/learn/sessions/{id}/attempt.
func (h *Handler) SessionAttempt(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid session id")
		return
	}

	req, err := api.Decode[AttemptRequest](w, r)
	if err != nil {
		return
	}

	ctx := r.Context()

	// Resolve item ID.
	itemID, pErr := uuid.Parse(req.ItemID)
	if pErr != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid item_id")
		return
	}

	attempt, err := h.learn.RecordAttempt(ctx, itemID, sessionID, req.Outcome,
		req.DurationMinutes, req.StuckAt, req.ApproachUsed, nil)
	if err != nil {
		h.logger.Error("record attempt", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	// Process observations.
	var confirmed []learning.Observation
	var pending []ObservationInput

	for _, obs := range req.Observations {
		if obs.Confidence == "low" {
			pending = append(pending, obs)
			continue
		}
		domain := req.ItemDomain
		if domain == "" {
			domain = "leetcode"
		}
		kind := obs.ConceptKind
		if kind == "" {
			kind = "pattern"
		}
		name := obs.ConceptName
		if name == "" {
			name = obs.ConceptSlug
		}
		conceptID, cErr := h.learn.FindOrCreateConcept(ctx, obs.ConceptSlug, name, domain, kind)
		if cErr != nil {
			h.logger.Warn("find/create concept", "slug", obs.ConceptSlug, "error", cErr)
			continue
		}
		o, oErr := h.learn.RecordObservation(ctx, attempt.ID, conceptID,
			obs.SignalType, obs.Category, obs.Severity, obs.Detail)
		if oErr != nil {
			h.logger.Warn("record observation", "error", oErr)
			continue
		}
		confirmed = append(confirmed, *o)
	}
	if confirmed == nil {
		confirmed = []learning.Observation{}
	}
	if pending == nil {
		pending = []ObservationInput{}
	}

	api.Encode(w, http.StatusCreated, map[string]any{
		"attempt_id":             attempt.ID.String(),
		"confirmed_observations": confirmed,
		"pending_observations":   pending,
	})
}

// SessionEnd handles POST /api/admin/learn/sessions/{id}/end.
func (h *Handler) SessionEnd(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid session id")
		return
	}

	ctx := r.Context()

	// Get attempts before ending.
	attempts, _ := h.learn.AttemptsBySession(ctx, sessionID)

	session, err := h.learn.EndSession(ctx, sessionID, nil)
	if err != nil {
		h.logger.Error("session end", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal error")
		return
	}

	var durationMin int
	if session.EndedAt != nil {
		durationMin = int(session.EndedAt.Sub(session.StartedAt).Minutes())
	}

	solved := 0
	for i := range attempts {
		switch attempts[i].Outcome {
		case "solved_independent", "completed":
			solved++
		}
	}

	if attempts == nil {
		attempts = []learning.Attempt{}
	}

	api.Encode(w, http.StatusOK, map[string]any{
		"session_id":       session.ID.String(),
		"duration_minutes": durationMin,
		"attempts_count":   len(attempts),
		"solved_count":     solved,
		"attempts":         attempts,
	})
}

// ConceptDrilldown handles GET /api/admin/learn/concepts/{slug}.
func (h *Handler) ConceptDrilldown(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "leetcode"
	}

	ctx := r.Context()

	concept, err := h.learn.ConceptBySlug(ctx, domain, slug)
	if err != nil {
		h.logger.Error("concept drilldown", "slug", slug, "error", err)
		api.Error(w, http.StatusNotFound, "NOT_FOUND", "concept not found")
		return
	}

	observations, _ := h.learn.ObservationsByConcept(ctx, concept.ID, 50)
	if observations == nil {
		observations = []learning.ConceptObservation{}
	}

	attempts, _ := h.learn.AttemptsByConcept(ctx, concept.ID, 20)
	if attempts == nil {
		attempts = []learning.ConceptAttempt{}
	}

	items, _ := h.learn.ItemsByConcept(ctx, concept.ID)
	if items == nil {
		items = []learning.ConceptItem{}
	}

	// Build observation trend (group by month).
	type trendPoint struct {
		Date             string `json:"date"`
		WeaknessCount    int    `json:"weakness_count"`
		ImprovementCount int    `json:"improvement_count"`
		MasteryCount     int    `json:"mastery_count"`
	}
	trendMap := map[string]*trendPoint{}
	for i := range observations {
		month := observations[i].CreatedAt.Format("2006-01")
		pt, ok := trendMap[month]
		if !ok {
			pt = &trendPoint{Date: month}
			trendMap[month] = pt
		}
		switch observations[i].SignalType {
		case "weakness":
			pt.WeaknessCount++
		case "improvement":
			pt.ImprovementCount++
		case "mastery":
			pt.MasteryCount++
		}
	}
	trend := make([]trendPoint, 0, len(trendMap))
	for _, pt := range trendMap {
		trend = append(trend, *pt)
	}

	api.Encode(w, http.StatusOK, map[string]any{
		"concept":           concept,
		"observation_trend": trend,
		"recent_attempts":   attempts,
		"observations":      observations,
		"related_items":     items,
	})
}

// ReviewQueue handles GET /api/admin/learn/review-queue.
func (h *Handler) ReviewQueue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 0, h.loc)
	endOfWeek := endOfDay.AddDate(0, 0, 7)

	dueToday, _ := h.learn.RetrievalQueue(ctx, nil, endOfDay, 50)
	if dueToday == nil {
		dueToday = []learning.RetrievalItem{}
	}

	dueWeekCount := 0
	if weekItems, err := h.learn.RetrievalQueue(ctx, nil, endOfWeek, 200); err == nil {
		dueWeekCount = len(weekItems)
	}

	overdueCount := 0
	if overdueItems, err := h.learn.RetrievalQueue(ctx, nil, now, 200); err == nil {
		overdueCount = len(overdueItems)
	}

	api.Encode(w, http.StatusOK, map[string]any{
		"due_today":     dueToday,
		"due_this_week": dueWeekCount,
		"overdue":       overdueCount,
	})
}
