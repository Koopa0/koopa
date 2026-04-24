package stats

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa/internal/api"
)

// Handler handles admin stats HTTP requests.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler returns a stats Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// Overview handles GET /api/admin/stats.
func (h *Handler) Overview(w http.ResponseWriter, r *http.Request) {
	overview, err := h.store.Overview(r.Context())
	if err != nil {
		h.logger.Error("querying admin stats", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query stats")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: overview})
}

// Drift handles GET /api/admin/stats/drift.
// Query params: days (default 30, max 90).
func (h *Handler) Drift(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	report, err := h.store.Drift(r.Context(), days)
	if err != nil {
		h.logger.Error("querying drift report", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query drift")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: report})
}

// Learning handles GET /api/admin/stats/learning.
func (h *Handler) Learning(w http.ResponseWriter, r *http.Request) {
	dashboard, err := h.store.Learning(r.Context())
	if err != nil {
		h.logger.Error("querying learning dashboard", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query learning stats")
		return
	}
	api.Encode(w, http.StatusOK, api.Response{Data: dashboard})
}

// ProcessRunsCell is a {value, state, reason?} cell used in the
// process-runs summary — the same cell-state envelope the
// system-health surface uses.
type ProcessRunsCell struct {
	Value  float64 `json:"value"`
	State  string  `json:"state"`
	Reason string  `json:"reason,omitempty"`
}

// ProcessRunsSummary is the top-line metrics panel. Stages are
// intentionally left empty — see
// frontend/docs/decisions/process-runs-stages.md for the rationale.
type ProcessRunsSummary struct {
	SuccessRate24h    ProcessRunsCell `json:"success_rate_24h"`
	AvgLatencySeconds float64         `json:"avg_latency_seconds"`
	InRetry           ProcessRunsCell `json:"in_retry"`
	FailedLastHour    ProcessRunsCell `json:"failed_last_hour"`
}

// ProcessRunsResponse is the wire shape for GET /coordination/process-runs.
type ProcessRunsResponse struct {
	Summary ProcessRunsSummary `json:"summary"`
	Stages  []any              `json:"stages"`
	Runs    []RecentProcessRun `json:"runs"`
	Total   int                `json:"total"`
}

// ProcessRuns handles GET /api/admin/coordination/process-runs. Composes
// 24h success rate, failed-last-hour, in-retry counts, and a paginated
// recent-runs list from process_runs.
func (h *Handler) ProcessRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()

	q := r.URL.Query()
	kind := q.Get("kind")
	if kind == "" {
		kind = "crawl"
	}
	var subsystem, status *string
	if v := q.Get("subsystem"); v != "" {
		subsystem = &v
	}
	if v := q.Get("status"); v != "" {
		status = &v
	}

	// One summary call with status=nil populates every FILTER counter
	// (Completed / Failed / Running / Pending) over the last 24h. The
	// previous three-call shape filtered at the SQL layer and then
	// misread the zero-filled sibling columns — fixed by taking all
	// counts from a single 24h call, plus one narrow 1-hour call whose
	// Failed counter is what "failed_last_hour" actually means.
	summary24h, err := h.store.ProcessRunsSince(ctx, now.Add(-24*time.Hour), kind, subsystem, status)
	if err != nil {
		h.logger.Error("process-runs 24h summary", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query process runs")
		return
	}

	lastHour, err := h.store.ProcessRunsSince(ctx, now.Add(-time.Hour), kind, subsystem, nil)
	if err != nil {
		h.logger.Error("process-runs last-hour summary", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query process runs")
		return
	}

	recent, err := h.store.RecentProcessRuns(ctx, now.Add(-24*time.Hour), kind, subsystem, status, 100)
	if err != nil {
		h.logger.Error("process-runs recent list", "error", err)
		api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to query process runs")
		return
	}
	if recent == nil {
		recent = []RecentProcessRun{}
	}

	rate := 100.0
	if summary24h.Total > 0 {
		rate = float64(summary24h.Completed) * 100.0 / float64(summary24h.Total)
	}

	resp := ProcessRunsResponse{
		Summary: ProcessRunsSummary{
			SuccessRate24h: ProcessRunsCell{Value: rate, State: successRateState(rate)},
			InRetry:        ProcessRunsCell{Value: float64(summary24h.Pending), State: nonZeroState(summary24h.Pending, "warn")},
			FailedLastHour: ProcessRunsCell{Value: float64(lastHour.Failed), State: nonZeroState(lastHour.Failed, "error")},
		},
		Stages: []any{},
		Runs:   recent,
		Total:  summary24h.Total,
	}
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

func successRateState(pct float64) string {
	switch {
	case pct >= 95:
		return "ok"
	case pct >= 80:
		return "warn"
	default:
		return "error"
	}
}

func nonZeroState(n int, elevated string) string {
	if n == 0 {
		return "ok"
	}
	return elevated
}
