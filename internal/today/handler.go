package today

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Koopa0/koopa/internal/api"
	"github.com/Koopa0/koopa/internal/daily"
)

// --- Source interfaces ---

// PlanItemReader returns daily plan items for a given calendar date.
type PlanItemReader interface {
	ItemsByDate(ctx context.Context, date time.Time) ([]daily.Item, error)
}

// ContentReviewLister returns content rows currently in review — the
// human judgment queue.
type ContentReviewLister interface {
	ReviewQueue(ctx context.Context, limit int) ([]JudgmentContent, error)
}

// HypothesisUnverifiedLister returns unverified hypotheses awaiting
// judgment.
type HypothesisUnverifiedLister interface {
	UnverifiedForJudgment(ctx context.Context, limit int) ([]JudgmentHypothesis, error)
}

// TaskAwaitingApprovalLister returns tasks in completed state that the
// human has not yet acknowledged.
type TaskAwaitingApprovalLister interface {
	AwaitingApproval(ctx context.Context, limit int) ([]JudgmentTask, error)
}

// PlanningNoteReader returns the latest agent_note(kind=plan) for the
// date (or near it).
type PlanningNoteReader interface {
	PlanNoteForDate(ctx context.Context, date time.Time) (*PlanningNote, error)
}

// DueReviewCounter returns the number of FSRS cards due on/before
// `before`.
type DueReviewCounter interface {
	DueCount(ctx context.Context, before time.Time) (int, error)
}

// FeedHealthReader surfaces failing feeds for the warnings section.
type FeedHealthReader interface {
	FailingFeeds(ctx context.Context) ([]FailingFeedWarning, error)
}

// StaleGoalReader surfaces goals that have not progressed within the
// staleness window.
type StaleGoalReader interface {
	StaleGoals(ctx context.Context, before time.Time) ([]StaleGoalWarning, error)
}

// Handler handles the Today aggregate HTTP request.
type Handler struct {
	planItems     PlanItemReader
	contentQueue  ContentReviewLister
	hypotheses    HypothesisUnverifiedLister
	awaitingTasks TaskAwaitingApprovalLister
	plannings     PlanningNoteReader
	dueReviews    DueReviewCounter
	feeds         FeedHealthReader
	staleGoals    StaleGoalReader
	logger        *slog.Logger
}

// NewHandler returns a today Handler. planItems is required — every other
// reader is optional, and a nil reader leaves its section of the response
// at the initialized empty-slice / zero state.
func NewHandler(planItems PlanItemReader, logger *slog.Logger) *Handler {
	return &Handler{planItems: planItems, logger: logger}
}

// WithSources injects the cross-domain readers.
func (h *Handler) WithSources(
	contentQueue ContentReviewLister,
	hypotheses HypothesisUnverifiedLister,
	awaitingTasks TaskAwaitingApprovalLister,
	plannings PlanningNoteReader,
	dueReviews DueReviewCounter,
	feeds FeedHealthReader,
	staleGoals StaleGoalReader,
) *Handler {
	h.contentQueue = contentQueue
	h.hypotheses = hypotheses
	h.awaitingTasks = awaitingTasks
	h.plannings = plannings
	h.dueReviews = dueReviews
	h.feeds = feeds
	h.staleGoals = staleGoals
	return h
}

const (
	judgmentListLimit = 50
	warningsFeedMin   = 3  // surface a feed warning after 3 consecutive failures
	staleGoalDays     = 14 // mark goal as stale after this many days with no movement
)

// Today handles GET /api/admin/commitment/today.
func (h *Handler) Today(w http.ResponseWriter, r *http.Request) {
	date := time.Now().UTC()
	if d := r.URL.Query().Get("date"); d != "" {
		parsed, err := time.Parse(time.DateOnly, d)
		if err != nil {
			api.Error(w, http.StatusBadRequest, "BAD_REQUEST", "invalid date format, use YYYY-MM-DD")
			return
		}
		date = parsed
	}

	ctx := r.Context()
	resp := Response{
		Date: date.Format(time.DateOnly),
		AwaitingJudgment: AwaitingJudgment{
			ContentReview:                  []JudgmentContent{},
			UnverifiedHypotheses:           []JudgmentHypothesis{},
			CompletedTasksAwaitingApproval: []JudgmentTask{},
		},
		Plan:       PlanSection{Date: date.Format(time.DateOnly), Items: []daily.Item{}},
		DueReviews: DueReviewsSection{Items: []any{}},
		Warnings:   []Warning{},
	}
	h.loadAwaitingJudgment(ctx, &resp)
	h.loadPlanSection(ctx, date, &resp)
	h.loadDueReviews(ctx, date, &resp)
	h.loadWarnings(ctx, date, &resp)
	api.Encode(w, http.StatusOK, api.Response{Data: resp})
}

func (h *Handler) loadAwaitingJudgment(ctx context.Context, resp *Response) {
	if h.contentQueue != nil {
		if rows, err := h.contentQueue.ReviewQueue(ctx, judgmentListLimit); err != nil {
			h.logger.Warn("today: content review queue failed", "error", err)
		} else if rows != nil {
			resp.AwaitingJudgment.ContentReview = rows
		}
	}
	if h.hypotheses != nil {
		if rows, err := h.hypotheses.UnverifiedForJudgment(ctx, judgmentListLimit); err != nil {
			h.logger.Warn("today: unverified hypotheses failed", "error", err)
		} else if rows != nil {
			resp.AwaitingJudgment.UnverifiedHypotheses = rows
		}
	}
	if h.awaitingTasks != nil {
		if rows, err := h.awaitingTasks.AwaitingApproval(ctx, judgmentListLimit); err != nil {
			h.logger.Warn("today: tasks awaiting approval failed", "error", err)
		} else if rows != nil {
			resp.AwaitingJudgment.CompletedTasksAwaitingApproval = rows
		}
	}
}

func (h *Handler) loadPlanSection(ctx context.Context, date time.Time, resp *Response) {
	items, err := h.planItems.ItemsByDate(ctx, date)
	if err != nil {
		h.logger.Error("today: plan items failed", "error", err)
	} else if items != nil {
		resp.Plan.Items = items
		resp.Plan.Summary.Total = len(items)
		for i := range items {
			if items[i].Status == daily.StatusDone {
				resp.Plan.Summary.Done++
			}
		}
	}
	if h.plannings != nil {
		if note, err := h.plannings.PlanNoteForDate(ctx, date); err == nil && note != nil {
			resp.Plan.PlanningNote = note
		}
	}
}

func (h *Handler) loadDueReviews(ctx context.Context, date time.Time, resp *Response) {
	if h.dueReviews == nil {
		return
	}
	if n, err := h.dueReviews.DueCount(ctx, date.Add(24*time.Hour)); err != nil {
		h.logger.Warn("today: due-reviews count failed", "error", err)
	} else {
		resp.DueReviews.Count = n
	}
}

func (h *Handler) loadWarnings(ctx context.Context, date time.Time, resp *Response) {
	resp.Warnings = append(resp.Warnings, h.feedWarnings(ctx)...)
	resp.Warnings = append(resp.Warnings, h.goalWarnings(ctx, date)...)
}

func (h *Handler) feedWarnings(ctx context.Context) []Warning {
	if h.feeds == nil {
		return nil
	}
	rows, err := h.feeds.FailingFeeds(ctx)
	if err != nil {
		h.logger.Warn("today: failing feeds failed", "error", err)
		return nil
	}
	out := make([]Warning, 0, len(rows))
	for i := range rows {
		if rows[i].ConsecutiveFailures < warningsFeedMin {
			continue
		}
		out = append(out, Warning{
			Source:   "feed",
			Severity: severityForFailures(rows[i].ConsecutiveFailures),
			Message:  rows[i].Message,
		})
	}
	return out
}

func (h *Handler) goalWarnings(ctx context.Context, date time.Time) []Warning {
	if h.staleGoals == nil {
		return nil
	}
	cutoff := date.AddDate(0, 0, -staleGoalDays)
	rows, err := h.staleGoals.StaleGoals(ctx, cutoff)
	if err != nil {
		h.logger.Warn("today: stale goals failed", "error", err)
		return nil
	}
	out := make([]Warning, 0, len(rows))
	for i := range rows {
		out = append(out, Warning{
			Source:   "goal",
			Severity: "warn",
			Message:  rows[i].Title + " stale " + strconv.Itoa(rows[i].DaysSinceMove) + "d",
		})
	}
	return out
}

// severityForFailures maps consecutive_failures to a CellState-vocabulary
// severity label — 3-5 failures warn, 6+ escalate to error.
func severityForFailures(n int) string {
	if n >= 6 {
		return "error"
	}
	return "warn"
}
