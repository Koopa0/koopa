package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/admin"
	"github.com/Koopa0/koopa0.dev/internal/auth"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/note"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/review"
	"github.com/Koopa0/koopa0.dev/internal/stats"
	"github.com/Koopa0/koopa0.dev/internal/tag"
	"github.com/Koopa0/koopa0.dev/internal/topic"
	"github.com/Koopa0/koopa0.dev/internal/upload"
)

// handlers holds all handler dependencies for route registration.
type handlers struct {
	auth     *auth.Handler
	content  *content.Handler
	project  *project.Handler
	topic    *topic.Handler
	feed     *feed.Handler
	entry    *entry.Handler
	goal     *goal.Handler
	tag      *tag.Handler
	stats    *stats.Handler
	activity *activity.Handler
	review   *review.Handler
	upload   *upload.Handler
	note     *note.Handler
	adminV2  *admin.Handler

	pool   *pgxpool.Pool
	logger *slog.Logger
}

// registerRoutes registers all API routes on the given mux.
func registerRoutes(mux *http.ServeMux, h *handlers, authMid func(http.Handler) http.Handler) {
	// --- Health checks (no auth) ---
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := h.pool.Ping(ctx); err != nil {
			h.logger.Error("readiness check failed", "error", err)
			http.Error(w, "db not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})

	// --- Public API ---
	mux.HandleFunc("GET /api/contents", h.content.List)
	mux.HandleFunc("GET /api/contents/{slug}", h.content.BySlug)
	mux.HandleFunc("GET /api/contents/by-type/{type}", h.content.ByType)
	mux.HandleFunc("GET /api/contents/related/{slug}", h.content.Related)
	mux.HandleFunc("GET /api/search", h.content.Search)
	mux.HandleFunc("GET /api/knowledge-graph", h.content.KnowledgeGraph)
	mux.HandleFunc("GET /api/feed/rss", h.content.RSS)
	mux.HandleFunc("GET /api/feed/sitemap", h.content.Sitemap)
	mux.HandleFunc("GET /api/topics", h.topic.List)
	mux.HandleFunc("GET /api/topics/{slug}", h.topic.BySlug)
	mux.HandleFunc("GET /api/projects", h.project.PublicList)
	mux.HandleFunc("GET /api/projects/{slug}", h.project.BySlug)

	// --- Auth ---
	if h.auth != nil {
		mux.HandleFunc("GET /api/auth/google", h.auth.GoogleLogin)
		mux.HandleFunc("GET /api/auth/google/callback", h.auth.GoogleCallback)
		mux.HandleFunc("POST /api/auth/refresh", h.auth.Refresh)
	}

	// --- Admin: Content ---
	mux.Handle("GET /api/admin/contents", authMid(http.HandlerFunc(h.content.AdminList)))
	mux.Handle("GET /api/admin/contents/{id}", authMid(http.HandlerFunc(h.content.AdminGet)))
	mux.Handle("POST /api/admin/contents", authMid(http.HandlerFunc(h.content.Create)))
	mux.Handle("PUT /api/admin/contents/{id}", authMid(http.HandlerFunc(h.content.Update)))
	mux.Handle("DELETE /api/admin/contents/{id}", authMid(http.HandlerFunc(h.content.Delete)))
	mux.Handle("POST /api/admin/contents/{id}/publish", authMid(http.HandlerFunc(h.content.Publish)))
	mux.Handle("PATCH /api/admin/contents/{id}/is-public", authMid(http.HandlerFunc(h.content.SetIsPublic)))

	// --- Admin: Review ---
	mux.Handle("GET /api/admin/review", authMid(http.HandlerFunc(h.review.List)))
	mux.Handle("POST /api/admin/review/{id}/approve", authMid(http.HandlerFunc(h.review.Approve)))
	mux.Handle("POST /api/admin/review/{id}/reject", authMid(http.HandlerFunc(h.review.Reject)))
	mux.Handle("PUT /api/admin/review/{id}/edit", authMid(http.HandlerFunc(h.review.ApproveAfterEdit)))

	// --- Admin: Projects ---
	mux.Handle("GET /api/admin/projects", authMid(http.HandlerFunc(h.project.List)))
	mux.Handle("POST /api/admin/projects", authMid(http.HandlerFunc(h.project.Create)))
	mux.Handle("PUT /api/admin/projects/{id}", authMid(http.HandlerFunc(h.project.Update)))
	mux.Handle("DELETE /api/admin/projects/{id}", authMid(http.HandlerFunc(h.project.Delete)))

	// --- Admin: Goals ---
	mux.Handle("GET /api/admin/goals", authMid(http.HandlerFunc(h.goal.List)))
	mux.Handle("PUT /api/admin/goals/{id}/status", authMid(http.HandlerFunc(h.goal.UpdateStatus)))

	// --- Admin: Topics ---
	mux.Handle("POST /api/admin/topics", authMid(http.HandlerFunc(h.topic.Create)))
	mux.Handle("PUT /api/admin/topics/{id}", authMid(http.HandlerFunc(h.topic.Update)))
	mux.Handle("DELETE /api/admin/topics/{id}", authMid(http.HandlerFunc(h.topic.Delete)))

	// --- Admin: Tags ---
	mux.Handle("GET /api/admin/tags", authMid(http.HandlerFunc(h.tag.List)))
	mux.Handle("POST /api/admin/tags", authMid(http.HandlerFunc(h.tag.Create)))
	mux.Handle("PUT /api/admin/tags/{id}", authMid(http.HandlerFunc(h.tag.Update)))
	mux.Handle("DELETE /api/admin/tags/{id}", authMid(http.HandlerFunc(h.tag.Delete)))
	mux.Handle("POST /api/admin/tags/backfill", authMid(http.HandlerFunc(h.tag.Backfill)))
	mux.Handle("POST /api/admin/tags/merge", authMid(http.HandlerFunc(h.tag.Merge)))

	// --- Admin: Aliases ---
	mux.Handle("GET /api/admin/aliases", authMid(http.HandlerFunc(h.tag.ListAliases)))
	mux.Handle("POST /api/admin/aliases/{id}/map", authMid(http.HandlerFunc(h.tag.MapAlias)))
	mux.Handle("POST /api/admin/aliases/{id}/confirm", authMid(http.HandlerFunc(h.tag.ConfirmAlias)))
	mux.Handle("POST /api/admin/aliases/{id}/reject", authMid(http.HandlerFunc(h.tag.RejectAlias)))
	mux.Handle("DELETE /api/admin/aliases/{id}", authMid(http.HandlerFunc(h.tag.DeleteAlias)))

	// --- Admin: Feeds ---
	if h.feed != nil {
		mux.Handle("GET /api/admin/feeds", authMid(http.HandlerFunc(h.feed.List)))
		mux.Handle("POST /api/admin/feeds", authMid(http.HandlerFunc(h.feed.Create)))
		mux.Handle("PUT /api/admin/feeds/{id}", authMid(http.HandlerFunc(h.feed.Update)))
		mux.Handle("DELETE /api/admin/feeds/{id}", authMid(http.HandlerFunc(h.feed.Delete)))
		mux.Handle("POST /api/admin/feeds/{id}/fetch", authMid(http.HandlerFunc(h.feed.Fetch)))
	}

	// --- Admin: Collected ---
	mux.Handle("GET /api/admin/collected", authMid(http.HandlerFunc(h.entry.List)))
	mux.Handle("POST /api/admin/collected/{id}/curate", authMid(http.HandlerFunc(h.entry.Curate)))
	mux.Handle("POST /api/admin/collected/{id}/ignore", authMid(http.HandlerFunc(h.entry.Ignore)))
	mux.Handle("POST /api/admin/collected/{id}/feedback", authMid(http.HandlerFunc(h.entry.SubmitFeedback)))

	// --- Admin: Notes ---
	mux.Handle("GET /api/admin/notes", authMid(http.HandlerFunc(h.note.Search)))
	mux.Handle("GET /api/admin/decisions", authMid(http.HandlerFunc(h.note.DecisionLog)))

	// --- Admin: Activity ---
	mux.Handle("GET /api/admin/activity/sessions", authMid(http.HandlerFunc(h.activity.Sessions)))
	mux.Handle("GET /api/admin/activity/changelog", authMid(http.HandlerFunc(h.activity.Changelog)))

	// --- Admin: Stats ---
	mux.Handle("GET /api/admin/stats", authMid(http.HandlerFunc(h.stats.Overview)))
	mux.Handle("GET /api/admin/stats/drift", authMid(http.HandlerFunc(h.stats.Drift)))
	mux.Handle("GET /api/admin/stats/learning", authMid(http.HandlerFunc(h.stats.Learning)))

	// --- Admin: Upload ---
	if h.upload != nil {
		mux.Handle("POST /api/admin/upload", authMid(http.HandlerFunc(h.upload.Upload)))
	}

	// --- Admin v2: Aggregate workflow endpoints ---
	if h.adminV2 != nil {
		a := h.adminV2

		// Today
		mux.Handle("GET /api/admin/today", authMid(http.HandlerFunc(a.Today)))
		mux.Handle("POST /api/admin/today/plan", authMid(http.HandlerFunc(a.TodayPlan)))
		mux.Handle("POST /api/admin/today/items/{id}/resolve", authMid(http.HandlerFunc(a.ResolvePlanItem)))

		// Inbox
		mux.Handle("GET /api/admin/inbox", authMid(http.HandlerFunc(a.Inbox)))
		mux.Handle("POST /api/admin/inbox/capture", authMid(http.HandlerFunc(a.InboxCapture)))
		mux.Handle("POST /api/admin/inbox/{id}/clarify", authMid(http.HandlerFunc(a.InboxClarify)))

		// Goals
		mux.Handle("GET /api/admin/plan/goals", authMid(http.HandlerFunc(a.GoalsOverview)))
		mux.Handle("GET /api/admin/plan/goals/{id}", authMid(http.HandlerFunc(a.GoalDetail)))
		mux.Handle("POST /api/admin/plan/goals/propose", authMid(http.HandlerFunc(a.GoalPropose)))
		mux.Handle("POST /api/admin/plan/goals/propose/{proposal_id}/commit", authMid(http.HandlerFunc(a.GoalCommit)))
		mux.Handle("POST /api/admin/plan/goals/{id}/milestones", authMid(http.HandlerFunc(a.MilestoneCreate)))
		mux.Handle("POST /api/admin/plan/goals/{id}/milestones/{ms_id}/toggle", authMid(http.HandlerFunc(a.MilestoneToggle)))

		// Projects
		mux.Handle("GET /api/admin/plan/projects", authMid(http.HandlerFunc(a.ProjectsOverview)))
		mux.Handle("GET /api/admin/plan/projects/{id}", authMid(http.HandlerFunc(a.ProjectDetail)))

		// Tasks
		mux.Handle("GET /api/admin/plan/tasks", authMid(http.HandlerFunc(a.TasksBacklog)))
		mux.Handle("POST /api/admin/plan/tasks/{id}/advance", authMid(http.HandlerFunc(a.AdvanceTask)))

		// Library
		mux.Handle("GET /api/admin/library/pipeline", authMid(http.HandlerFunc(a.LibraryPipeline)))
	}
}
