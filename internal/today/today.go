// Package today composes the admin Today dashboard — a cross-domain
// aggregate over content review, hypothesis judgment, task approval,
// daily plan items, agent_note planning entries, FSRS due reviews, and
// feed / goal warnings. Every cross-domain source is expressed through
// a consumer-defined interface; this package does not import another
// feature's *Store directly.
package today

import (
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/daily"
)

// JudgmentContent is a content row queued for human review decision.
type JudgmentContent struct {
	ID          uuid.UUID `json:"id"`
	Title       string    `json:"title"`
	Type        string    `json:"type"`
	Actor       string    `json:"actor"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// JudgmentHypothesis is an unverified hypothesis awaiting decision.
type JudgmentHypothesis struct {
	ID        uuid.UUID `json:"id"`
	Claim     string    `json:"claim"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

// JudgmentTask is a completed task awaiting the human acknowledge.
type JudgmentTask struct {
	ID          uuid.UUID  `json:"id"`
	Title       string     `json:"title"`
	Source      string     `json:"source"`
	Assignee    string     `json:"assignee"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// PlanningNote is the latest agent_note(kind=plan) for a date.
type PlanningNote struct {
	ID        uuid.UUID `json:"id"`
	Kind      string    `json:"kind"`
	BodyMD    string    `json:"body_md"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

// FailingFeedWarning is a warnings-row entry for a feed that has been
// consecutive-failing beyond a threshold.
type FailingFeedWarning struct {
	Name                string `json:"name"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	Message             string `json:"message"`
}

// StaleGoalWarning is a warnings-row entry for a goal that has not
// progressed within the stale window.
type StaleGoalWarning struct {
	ID            uuid.UUID `json:"id"`
	Title         string    `json:"title"`
	DaysSinceMove int       `json:"days_since_move"`
}

// AwaitingJudgment bundles the three "human decision needed" inboxes.
type AwaitingJudgment struct {
	ContentReview                  []JudgmentContent    `json:"content_review"`
	UnverifiedHypotheses           []JudgmentHypothesis `json:"unverified_hypotheses"`
	CompletedTasksAwaitingApproval []JudgmentTask       `json:"completed_tasks_awaiting_approval"`
}

// PlanSection is the today's-plan projection used by the UI. Items mirror
// daily.Item exactly — the wire shape for today and /daily-plan stays the
// same row type so the frontend can reuse its row component.
type PlanSection struct {
	Date         string        `json:"date"`
	PlanningNote *PlanningNote `json:"planning_note,omitempty"`
	Items        []daily.Item  `json:"items"`
	Summary      PlanSummary   `json:"summary"`
}

// PlanSummary is the small counts panel above plan items.
type PlanSummary struct {
	Total   int `json:"total"`
	Done    int `json:"done"`
	Overdue int `json:"overdue"`
}

// DueReviewsSection is the FSRS due-today projection. Items are left
// empty; callers that need the full list hit /learning/dashboard. Today
// carries the count for the top-line badge only.
type DueReviewsSection struct {
	Count int   `json:"count"`
	Items []any `json:"items"`
}

// Warning is a single warnings-row entry. source identifies which
// subsystem surfaced it (feed, goal); severity is a closed set matching
// CellState vocabulary.
type Warning struct {
	Source   string `json:"source"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Response is the wire shape for GET /api/admin/commitment/today.
type Response struct {
	Date             string            `json:"date"`
	AwaitingJudgment AwaitingJudgment  `json:"awaiting_judgment"`
	Plan             PlanSection       `json:"plan"`
	DueReviews       DueReviewsSection `json:"due_reviews"`
	Warnings         []Warning         `json:"warnings"`
}
