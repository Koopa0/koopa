package systemhealth

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa/internal/api"
)

// FeedHealthReader surfaces active + failing feed counts for
// knowledge.feeds_active.
type FeedHealthReader interface {
	FeedHealth(ctx context.Context) (enabled, failing int, err error)
}

// ProcessRunSuccessReader surfaces the 24h success rate for
// coordination.process_runs_24h_success_pct.
type ProcessRunSuccessReader interface {
	SuccessRate24h(ctx context.Context, now time.Time) (pct float64, hasTraffic bool, err error)
}

// ContentCountReader surfaces total content count for knowledge.contents_total.
type ContentCountReader interface {
	ContentsCount(ctx context.Context) (int, error)
}

// Handler composes the 4-domain envelope. Every source is optional; a
// nil source leaves that cell at its zero-initialized "ok" state so the
// wire shape is never missing a field.
type Handler struct {
	feeds       FeedHealthReader
	processRuns ProcessRunSuccessReader
	contents    ContentCountReader
	logger      *slog.Logger
}

// NewHandler returns a systemhealth Handler.
func NewHandler(feeds FeedHealthReader, processRuns ProcessRunSuccessReader, contents ContentCountReader, logger *slog.Logger) *Handler {
	return &Handler{feeds: feeds, processRuns: processRuns, contents: contents, logger: logger}
}

// Check handles GET /api/admin/system/health.
func (h *Handler) Check(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()

	resp := Response{
		Commitment: Commitment{
			TodosOpen:     intCell(0, "ok"),
			GoalsActive:   intCell(0, "ok"),
			TodayPlanDone: intCellWithTotal(0, 0, "ok"),
		},
		Knowledge: Knowledge{
			ContentsTotal:  intCell(0, "ok"),
			ReviewQueue:    intCell(0, "ok"),
			NotesTotal:     intCell(0, "ok"),
			BookmarksTotal: intCell(0, "ok"),
			FeedsActive:    intCell(0, "ok"),
		},
		Learning: Learning{
			ConceptsTotal:        intCell(0, "ok"),
			WeakConcepts:         intCell(0, "ok"),
			DueReviews:           intCell(0, "ok"),
			HypothesesUnverified: intCell(0, "ok"),
		},
		Coordination: Coordination{
			TasksAwaitingHuman:       intCell(0, "ok"),
			ProcessRuns24hSuccessPct: pctCell(100, "ok"),
			AgentsActive:             intCell(0, "ok"),
		},
	}

	h.loadFeedHealth(ctx, &resp)

	if h.processRuns != nil {
		if pct, hasTraffic, err := h.processRuns.SuccessRate24h(ctx, now); err != nil {
			h.logger.Warn("system-health: process-run rate failed", "error", err)
		} else if hasTraffic {
			resp.Coordination.ProcessRuns24hSuccessPct = pctCell(pct, successRateState(pct))
		}
	}

	if h.contents != nil {
		if n, err := h.contents.ContentsCount(ctx); err != nil {
			h.logger.Warn("system-health: contents count failed", "error", err)
		} else {
			resp.Knowledge.ContentsTotal = Cell{Count: intp(n), State: "ok"}
		}
	}

	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

// loadFeedHealth populates knowledge.feeds_active from the optional
// FeedHealthReader source.
func (h *Handler) loadFeedHealth(ctx context.Context, resp *Response) {
	if h.feeds == nil {
		return
	}
	enabled, failing, err := h.feeds.FeedHealth(ctx)
	if err != nil {
		h.logger.Warn("system-health: feed health failed", "error", err)
		return
	}
	state := "ok"
	reason := ""
	if failing > 0 {
		state = "error"
		reason = plural(failing, "failing feed")
	}
	resp.Knowledge.FeedsActive = Cell{Count: intp(enabled), State: state, Reason: reason}
}

// successRateState maps a 24h success-rate percentage to a state label
// matching the CellState vocabulary.
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

func plural(n int, singular string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + singular + "s"
}
