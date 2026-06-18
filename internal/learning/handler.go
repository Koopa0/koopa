// Copyright 2026 Koopa. All rights reserved.

package learning

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/google/uuid"
)

// storeErrors maps learning sentinel errors to HTTP responses.
var storeErrors = []api.ErrMap{
	{Target: ErrNotFound, Status: http.StatusNotFound, Code: "NOT_FOUND", Message: "learning entity not found"},
	{Target: ErrConflict, Status: http.StatusConflict, Code: "CONFLICT", Message: "learning entity conflict"},
	{Target: ErrActiveExists, Status: http.StatusConflict, Code: "ACTIVE_SESSION_EXISTS", Message: "an active session already exists"},
	{Target: ErrNoActive, Status: http.StatusNotFound, Code: "NO_ACTIVE_SESSION", Message: "no active session"},
	{Target: ErrAlreadyEnded, Status: http.StatusConflict, Code: "SESSION_ENDED", Message: "session already ended"},
}

// domainSlugPattern mirrors the chk_learning_domains_slug_format CHECK in
// migrations/001 (and the MCP-side slugPattern in internal/mcp/validate.go).
// Validating client-side lets the handler return a specific 400 instead of a
// generic CheckViolation 500 from PostgreSQL. Keep aligned with the schema
// rule: lowercase kebab-case, leading digits allowed, no trailing/consecutive
// hyphens.
var domainSlugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// containsControlChars reports whether s contains any control character.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// Handler handles learning HTTP requests for the admin workbench.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a learning Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// learningSummaryResponse is the response shape for GET /api/admin/learning/summary.
type learningSummaryResponse struct {
	StreakDays int             `json:"streak_days"`
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

	since := time.Now().Add(-masteryLookback)
	rows, err := h.store.ConceptMastery(ctx, nil, since, nil, "high")
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
		Domains:    domains,
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// NextTarget handles GET /api/admin/learning/next-target.
//
// It surfaces the single concept Koopa should practice next plus a one-line
// human reason, for the dashboard "Next up" card. Unlike the MCP
// recommend_next path it is session-independent: it reads the same
// severity-ordered weakness signal (WeaknessAnalysis over the 30-day window)
// and lets the pure SelectNextTarget picker choose the head and render the
// reason. "Nothing to recommend" is a 200 with {empty: true}, not a 404, so
// the card renders an empty state without special-casing a missing resource.
//
// Optional ?domain= scopes the recommendation to one practice track.
func (h *Handler) NextTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var domain *string
	if v := strings.TrimSpace(r.URL.Query().Get("domain")); v != "" {
		if containsControlChars(v) {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain contains control characters")
			return
		}
		domain = &v
	}

	now := time.Now()
	since := now.AddDate(0, 0, -NextTargetWindowDays)
	weaknesses, err := h.store.WeaknessAnalysis(ctx, domain, since, "high")
	if err != nil {
		h.logger.Error("querying weakness analysis for next target", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to compute next target")
		return
	}

	next := SelectNextTarget(weaknesses, now)
	api.Encode(w, http.StatusOK, api.Response{Data: next})
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

// --- Domains ---

// createDomainRequest is the JSON body for POST /api/admin/learning/domains —
// the owner decision-stamp that replaces the removed propose_learning_domain /
// commit MCP flow. slug and name are required; slug must be lowercase
// kebab-case (matches the learning_domains slug CHECK).
type createDomainRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// CreateDomain handles POST /api/admin/learning/domains.
func (h *Handler) CreateDomain(w http.ResponseWriter, r *http.Request) {
	req, err := api.Decode[createDomainRequest](w, r)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}
	if req.Slug == "" || req.Name == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug and name are required")
		return
	}
	if !domainSlugPattern.MatchString(req.Slug) {
		api.Error(w, http.StatusUnprocessableEntity, "INVALID_SLUG",
			"slug must be lowercase kebab-case (pattern: "+domainSlugPattern.String()+")")
		return
	}
	if containsControlChars(req.Name) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "name must not contain control characters")
		return
	}

	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}

	// Reject duplicates before the INSERT fires a unique-violation round
	// trip — the store wraps a unique violation as a generic error (no
	// ErrConflict mapping), so checking first yields a clean 409.
	exists, err := store.DomainExists(r.Context(), req.Slug)
	if err != nil {
		h.logger.Error("checking learning domain", "slug", req.Slug, "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to create domain")
		return
	}
	if exists {
		api.HandleError(w, h.logger, ErrConflict, storeErrors...)
		return
	}

	domain, err := store.CreateDomain(r.Context(), req.Slug, req.Name)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: domain})
}

// ListDomains handles GET /api/admin/learning/domains — every active learning
// domain, slug-ordered. Read-only (authMid); the admin UI uses it to populate
// the domain selector when creating a learning plan or domain. The list is
// always a JSON array, never null.
func (h *Handler) ListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.store.Domains(r.Context())
	if err != nil {
		h.logger.Error("listing learning domains", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list domains")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: domains})
}

// --- Dashboard ---

// DashboardResponse is the wire shape for GET /api/admin/learning/dashboard.
//
// Top-level streak_days plus the concepts and recent-observations
// envelopes give the frontend dashboard page the full picture in a
// single round-trip.
//
// Currently every value of the `view` query param returns the same
// payload; richer views (mastery, weaknesses, timeline, variations)
// are accepted for forward compatibility but not yet shaped.
type DashboardResponse struct {
	StreakDays         int                          `json:"streak_days"`
	Concepts           DashboardConcepts            `json:"concepts"`
	RecentObservations []DashboardRecentObservation `json:"recent_observations"`
	// WeekActivity is the last 7 UTC days of attempt-logging activity,
	// zero-filled, oldest first (today last).
	WeekActivity []WeekActivityDay `json:"week_activity"`
}

const (
	// dashboardRecentObsLimit caps the recent_observations slice.
	dashboardRecentObsLimit = 20
)

// emptyDashboardConcepts returns a zero-value DashboardConcepts with all
// slice/map fields initialised so encoded JSON contains `[]` / `{}`
// instead of `null`. Used as the default before populating from the
// store, and as the failure fallback when the query errors.
func emptyDashboardConcepts() DashboardConcepts {
	return DashboardConcepts{
		CountTotal:     0,
		CountsByDomain: map[string]int{},
		Rows:           []DashboardConceptRow{},
	}
}

// Dashboard handles GET /api/admin/learning/dashboard.
// Query params: view, domain, confidence_filter.
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
	now := time.Now()
	since := now.Add(-masteryLookback)

	resp := DashboardResponse{
		Concepts:           emptyDashboardConcepts(),
		RecentObservations: []DashboardRecentObservation{},
		WeekActivity:       []WeekActivityDay{},
	}

	if streak, err := h.store.Streak(ctx); err != nil {
		h.logger.Warn("dashboard: streak failed", "error", err)
	} else {
		resp.StreakDays = streak
	}

	if days, err := h.store.WeekActivity(ctx, now); err != nil {
		h.logger.Warn("dashboard: week activity failed", "error", err)
	} else {
		resp.WeekActivity = days
	}

	if rows, err := h.store.DashboardConceptRows(ctx, domain, since, confidenceFilter); err != nil {
		h.logger.Warn("dashboard: concept rows failed", "error", err)
	} else {
		resp.Concepts = DashboardConcepts{
			CountTotal:     len(rows),
			CountsByDomain: countConceptsByDomain(rows),
			Rows:           rows,
		}
	}

	if obs, err := h.store.DashboardRecentObservations(ctx, domain, confidenceFilter, dashboardRecentObsLimit); err != nil {
		h.logger.Warn("dashboard: recent observations failed", "error", err)
	} else {
		resp.RecentObservations = obs
	}

	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// countConceptsByDomain tallies rows per domain. Returns an empty map
// (never nil) so json.Marshal produces `{}` not `null`.
func countConceptsByDomain(rows []DashboardConceptRow) map[string]int {
	out := map[string]int{}
	for i := range rows {
		out[rows[i].Domain]++
	}
	return out
}

// --- Concepts ---

const (
	// conceptDetailRecentLimit caps recent_attempts + recent_observations
	// on the /concepts/{slug} detail response. 20 is plenty for the UI;
	// older entries are reachable through dedicated history endpoints.
	conceptDetailRecentLimit = 20
)

// validMasteryStages is the closed set the /concepts mastery_stage
// filter accepts. Anything outside it is a 400 — better than a silent
// "filter matches nothing because the typed value is unknown".
var validMasteryStages = map[string]struct{}{
	"struggling": {},
	"developing": {},
	"solid":      {},
}

// ConceptsList handles GET /api/admin/learning/concepts.
// Query params: domain, kind, mastery_stage (comma-list, filtered in
// Go after DeriveMasteryStage), q (substring match on name/slug),
// confidence_filter.
func (h *Handler) ConceptsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := ConceptListFilter{
		Domain:           q.Get("domain"),
		Kind:             q.Get("kind"),
		Q:                q.Get("q"),
		ConfidenceFilter: q.Get("confidence_filter"),
	}
	if filter.ConfidenceFilter == "" {
		filter.ConfidenceFilter = "high"
	}
	if v := strings.TrimSpace(q.Get("mastery_stage")); v != "" {
		raw := strings.Split(v, ",")
		stages := make([]string, 0, len(raw))
		for _, s := range raw {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := validMasteryStages[s]; !ok {
				api.Error(w, http.StatusBadRequest, "BAD_REQUEST",
					"mastery_stage must be a comma-separated subset of {struggling, developing, solid}")
				return
			}
			stages = append(stages, s)
		}
		filter.MasteryStages = stages
	}

	since := time.Now().Add(-masteryLookback)
	rows, err := h.store.ConceptsList(r.Context(), filter, since)
	if err != nil {
		h.logger.Error("listing concepts", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list concepts")
		return
	}
	if rows == nil {
		rows = []ConceptListRow{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rows})
}

// ConceptDetail handles GET /api/admin/learning/concepts/{slug}.
// Query params: domain (required), confidence_filter.
func (h *Handler) ConceptDetail(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}
	q := r.URL.Query()
	domain := q.Get("domain")
	if domain == "" {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "domain query param is required to disambiguate concept slug")
		return
	}
	confidenceFilter := q.Get("confidence_filter")
	if confidenceFilter == "" {
		confidenceFilter = "high"
	}

	resp, err := h.store.ConceptDetail(r.Context(), domain, slug, confidenceFilter, conceptDetailRecentLimit)
	if err != nil {
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
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
	Session  *Session  `json:"session"`
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

// --- Targets ---

// Bounds for the target attempts list (audit-gate picker page size).
const (
	targetAttemptsDefaultLimit = 20
	targetAttemptsMaxLimit     = 100
)

// TargetAttempts handles GET /api/admin/learning/targets/{id}/attempts.
// Lists attempts on one learning target, newest first — the picker source
// for the plan-detail audit-gate modal (candidate completed_by_attempt_id
// values). A target with no attempts — including an unknown target id —
// returns an empty list, not 404, so the picker renders empty instead of
// erroring. Query params: limit (1-100, default 20).
func (h *Handler) TargetAttempts(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid target id")
		return
	}

	limit := targetAttemptsDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > targetAttemptsMaxLimit {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "limit must be between 1 and 100")
			return
		}
		limit = n
	}

	atts, err := h.store.AttemptsByLearningTarget(r.Context(), id, int32(limit)) // #nosec G115 -- limit bounded to [1, 100]
	if err != nil {
		h.logger.Error("listing target attempts", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list attempts")
		return
	}
	if atts == nil {
		atts = []Attempt{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: atts})
}

// Bounds for the GET /api/admin/learning/targets picker list.
const (
	targetsListDefaultLimit = 50
	targetsListMaxLimit     = 100
)

// TargetsList handles GET /api/admin/learning/targets — the admin
// note-editor's target picker source. Query params: domain (optional),
// q (case-insensitive substring on title), limit (1-100, default 50).
func (h *Handler) TargetsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	query := q.Get("q")
	if containsControlChars(domain) || containsControlChars(query) {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "filter contains control characters")
		return
	}

	limit := targetsListDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > targetsListMaxLimit {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "limit must be between 1 and 100")
			return
		}
		limit = n
	}

	rows, err := h.store.Targets(r.Context(), TargetListFilter{
		Domain: domain,
		Q:      query,
		Limit:  int32(limit), // #nosec G115 -- limit bounded to [1, 100]
	})
	if err != nil {
		h.logger.Error("listing targets", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list targets")
		return
	}
	if rows == nil {
		rows = []TargetListRow{}
	}
	api.Encode(w, http.StatusOK, api.Response{Data: rows})
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

// EndSession handles POST /api/admin/learning/sessions/{id}/end.
func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid session id")
		return
	}
	store, ok := h.mustAdminTx(w, r)
	if !ok {
		return
	}
	session, err := store.EndSession(r.Context(), id)
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

	// Admin HTTP path = Koopa (human). The MCP path threads caller
	// identity from the `as` field; the admin path has no such field
	// because the REST endpoint is admin-only and Koopa is the sole
	// user (per the registry's single-human-platform invariant).
	targetID, err := store.FindOrCreateTarget(r.Context(), req.Domain, req.TargetTitle, req.ExternalID, req.Difficulty, "human")
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
		api.HandleError(w, h.logger, err, storeErrors...)
		return
	}
	api.Encode(w, http.StatusCreated, api.Response{Data: attempt})
}
