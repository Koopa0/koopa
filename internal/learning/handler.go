package learning

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/google/uuid"
)

// ReviewCounter counts due review cards. Defined here (consumer-side)
// to avoid importing internal/learning/fsrs.
type ReviewCounter interface {
	DueCount(ctx context.Context, before time.Time) (int, error)
}

// storeErrors maps learning sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "learning entity not found"},
	{Target: ErrActiveExists, Status: http.StatusConflict, Code: "ACTIVE_SESSION_EXISTS", Message: "an active session already exists"},
	{Target: ErrNoActive, Status: http.StatusNotFound, Code: "NO_ACTIVE_SESSION", Message: "no active session"},
	{Target: ErrAlreadyEnded, Status: http.StatusConflict, Code: "SESSION_ENDED", Message: "session already ended"},
}

// Handler handles learning HTTP requests for the admin workbench.
type Handler struct {
	store   *Store
	reviews ReviewCounter
	logger  *slog.Logger
}

// NewHandler returns a learning Handler.
func NewHandler(store *Store, reviews ReviewCounter, logger *slog.Logger) *Handler {
	return &Handler{store: store, reviews: reviews, logger: logger}
}

// learningSummaryResponse is the response shape for GET /api/admin/learning/summary.
type learningSummaryResponse struct {
	StreakDays int             `json:"streak_days"`
	DueReviews int             `json:"due_reviews"`
	Domains    []DomainMastery `json:"domains"`
}

// masteryLookback is the window for mastery aggregation.
const masteryLookback = 90 * 24 * time.Hour

// Summary handles GET /api/admin/learning/summary.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	streak, err := h.store.Streak(ctx)
	if err != nil {
		h.logger.Error("querying streak", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query streak")
		return
	}

	dueReviews := 0
	if h.reviews != nil {
		if n, dueErr := h.reviews.DueCount(ctx, time.Now()); dueErr != nil {
			h.logger.Error("counting due reviews", "error", dueErr)
			// non-fatal: continue with 0
		} else {
			dueReviews = n
		}
	}

	since := time.Now().Add(-masteryLookback)
	rows, err := h.store.ConceptMastery(ctx, nil, since, "high")
	if err != nil {
		h.logger.Error("querying concept mastery", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query mastery")
		return
	}

	domains := AggregateMasteryByDomain(rows)
	if domains == nil {
		domains = []DomainMastery{}
	}

	resp := learningSummaryResponse{
		StreakDays: streak,
		DueReviews: dueReviews,
		Domains:    domains,
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// mustAdminTx extracts the per-request tx for mutation endpoints.
func (h *Handler) mustAdminTx(w http.ResponseWriter, r *http.Request) (*Store, bool) {
	tx, ok := api.TxFromContext(r.Context())
	if !ok {
		h.logger.Error("learning mutation without tx",
			"event", "middleware_not_wired",
			"method", r.Method, "path", r.URL.Path)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "internal server error")
		return nil, false
	}
	return h.store.WithTx(tx), true
}

// --- Dashboard ---

// DashboardResponse is the wire shape for /learning/dashboard view=overview.
// Richer views (mastery, weaknesses, retrieval, timeline, variations) are
// accepted but currently return the same overview payload.
type DashboardResponse struct {
	StreakDays         int                  `json:"streak_days"`
	DueReviewsCount    int                  `json:"due_reviews_count"`
	Concepts           []ConceptMasteryRow  `json:"concepts"`
	DueTodayItems      []RetrievalTarget    `json:"due_today_items"`
	RecentObservations []ConceptObservation `json:"recent_observations"`
}

// Dashboard handles GET /api/admin/learning/dashboard.
// Query params: view, domain, confidence_filter, since (days).
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	confidenceFilter := q.Get("confidence_filter")
	if confidenceFilter == "" {
		confidenceFilter = "high"
	}
	var domain *string
	if v := q.Get("domain"); v != "" {
		domain = &v
	}
	since := time.Now().Add(-masteryLookback)

	resp := DashboardResponse{
		Concepts:           []ConceptMasteryRow{},
		DueTodayItems:      []RetrievalTarget{},
		RecentObservations: []ConceptObservation{},
	}

	if streak, err := h.store.Streak(ctx); err == nil {
		resp.StreakDays = streak
	}

	if rows, err := h.store.ConceptMastery(ctx, domain, since, confidenceFilter); err != nil {
		h.logger.Warn("dashboard: concept mastery failed", "error", err)
	} else {
		resp.Concepts = rows
	}

	if items, err := h.store.RetrievalQueue(ctx, domain, time.Now().Add(24*time.Hour), 50); err != nil {
		h.logger.Warn("dashboard: retrieval queue failed", "error", err)
	} else {
		resp.DueTodayItems = items
	}

	if h.reviews != nil {
		if n, err := h.reviews.DueCount(ctx, time.Now().Add(24*time.Hour)); err == nil {
			resp.DueReviewsCount = n
		}
	}

	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// --- Concepts ---

// ConceptsList handles GET /api/admin/learning/concepts.
// Query params: domain, mastery_stage (filtered in Go), confidence_filter.
func (h *Handler) ConceptsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	confidenceFilter := q.Get("confidence_filter")
	if confidenceFilter == "" {
		confidenceFilter = "high"
	}
	var domain *string
	if v := q.Get("domain"); v != "" {
		domain = &v
	}

	since := time.Now().Add(-masteryLookback)
	rows, err := h.store.ConceptMastery(r.Context(), domain, since, confidenceFilter)
	if err != nil {
		h.logger.Error("listing concepts", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list concepts")
		return
	}
	if rows == nil {
		rows = []ConceptMasteryRow{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rows})
}

// ConceptProfile is the detail shape for GET /concepts/:slug.
type ConceptProfile struct {
	*Concept
	Observations []ConceptObservation `json:"observations"`
	Attempts     []Attempt            `json:"attempts"`
	Targets      []ConceptTarget      `json:"targets"`
}

// ConceptDetail handles GET /api/admin/learning/concepts/{slug}.
// Query params: domain (optional; disambiguates slug across domains).
func (h *Handler) ConceptDetail(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain query param is required to disambiguate concept slug")
		return
	}

	c, err := h.store.ConceptBySlug(r.Context(), domain, slug)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	profile := ConceptProfile{
		Concept:      c,
		Observations: []ConceptObservation{},
		Attempts:     []Attempt{},
		Targets:      []ConceptTarget{},
	}
	if obs, oerr := h.store.ObservationsByConcept(r.Context(), c.ID, 50); oerr == nil {
		profile.Observations = obs
	}
	if atts, aerr := h.store.AttemptsByConcept(r.Context(), c.ID, 50); aerr == nil {
		profile.Attempts = atts
	}
	if tgts, err := h.store.TargetsByConcept(r.Context(), c.ID); err == nil {
		profile.Targets = tgts
	}
	api.Encode(w, http.StatusOK, api.Response{Data: profile})
}

// --- Sessions ---

// SessionsList handles GET /api/admin/learning/sessions.
// Query params: domain, since (days), limit.
func (h *Handler) SessionsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var domain *string
	if v := q.Get("domain"); v != "" {
		domain = &v
	}
	since := time.Now().Add(-30 * 24 * time.Hour)
	if d := q.Get("since"); d != "" {
		if t, err := time.Parse(time.DateOnly, d); err == nil {
			since = t
		}
	}
	limit := int32(50)

	rows, err := h.store.RecentSessions(r.Context(), domain, since, limit)
	if err != nil {
		h.logger.Error("listing sessions", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list sessions")
		return
	}
	if rows == nil {
		rows = []Session{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rows})
}

// SessionDetailResponse is the wire shape for GET /sessions/:id.
type SessionDetailResponse struct {
	*Session
	Attempts []Attempt `json:"attempts"`
}

// SessionDetail handles GET /api/admin/learning/sessions/{id}.
func (h *Handler) SessionDetail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid session id")
		return
	}
	session, err := h.store.SessionByID(r.Context(), id)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	resp := SessionDetailResponse{Session: session, Attempts: []Attempt{}}
	if atts, aerr := h.store.AttemptsBySession(r.Context(), id); aerr == nil {
		resp.Attempts = atts
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// StartSessionRequest is the POST body for starting a session.
type StartSessionRequest struct {
	Domain          string     `json:"domain"`
	Mode            string     `json:"mode"`
	DailyPlanItemID *uuid.UUID `json:"daily_plan_item_id,omitempty"`
}

// StartSession handles POST /api/admin/learning/sessions.
func (h *Handler) StartSession(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[StartSessionRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Domain == "" || req.Mode == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain and mode are required")
		return
	}
	mode := Mode(req.Mode)

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	session, zombie, err := store.StartSession(r.Context(), req.Domain, mode, req.DailyPlanItemID)
	if err != nil {
		if errors.Is(err, ErrActiveExists) {
			api.Error(w, http.StatusConflict, "ACTIVE_SESSION_EXISTS", "an active session already exists")
			return
		}
		h.logger.Error("starting session", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to start session")
		return
	}
	type startResp struct {
		Session     *Session `json:"session"`
		ZombieEnded *Session `json:"zombie_ended,omitempty"`
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: startResp{Session: session, ZombieEnded: zombie}})
}

// EndSessionRequest is the POST body for ending a session.
type EndSessionRequest struct {
	AgentNoteID *uuid.UUID `json:"agent_note_id,omitempty"`
}

// EndSession handles POST /api/admin/learning/sessions/{id}/end.
func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid session id")
		return
	}
	req, err := api.Decode[EndSessionRequest](w, r)
	if err != nil {
		// Empty body is acceptable — agent_note_id is optional.
		req = EndSessionRequest{}
	}
	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	session, err := store.EndSession(r.Context(), id, req.AgentNoteID)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: session})
}

// RecordAttemptRequest is the POST body for recording an attempt.
type RecordAttemptRequest struct {
	SessionID       uuid.UUID `json:"session_id"`
	TargetTitle     string    `json:"target_title"`
	Domain          string    `json:"domain"`
	ExternalID      *string   `json:"external_id,omitempty"`
	Difficulty      *string   `json:"difficulty,omitempty"`
	Paradigm        string    `json:"paradigm"`
	Outcome         string    `json:"outcome"`
	DurationMinutes *int32    `json:"duration_minutes,omitempty"`
	StuckAt         *string   `json:"stuck_at,omitempty"`
	ApproachUsed    *string   `json:"approach_used,omitempty"`
}

// RecordAttempt handles POST /api/admin/learning/sessions/{id}/attempts.
func (h *Handler) RecordAttempt(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid session id")
		return
	}
	req, err := api.Decode[RecordAttemptRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if strings.TrimSpace(req.TargetTitle) == "" || req.Domain == "" || req.Paradigm == "" || req.Outcome == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "target_title, domain, paradigm, and outcome are required")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	targetID, err := store.FindOrCreateTarget(r.Context(), req.Domain, req.TargetTitle, req.ExternalID, req.Difficulty)
	if err != nil {
		h.logger.Error("resolving learning target", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to resolve target")
		return
	}

	attempt, err := store.RecordAttempt(
		r.Context(),
		targetID, sessionID,
		Paradigm(req.Paradigm), req.Outcome,
		req.DurationMinutes, req.StuckAt, req.ApproachUsed,
		nil,
	)
	if err != nil {
		h.logger.Error("recording attempt", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to record attempt")
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: attempt})
}
