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
	"github.com/Koopa0/koopa0.dev/internal/bookmark"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/note"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/stats"
	"github.com/Koopa0/koopa0.dev/internal/tag"
	"github.com/Koopa0/koopa0.dev/internal/topic"
	"github.com/Koopa0/koopa0.dev/internal/upload"
)

// handlers holds all handler dependencies for route registration.
type handlers struct {
	auth     *auth.Handler
	content  *content.Handler
	bookmark *bookmark.Handler
	project  *project.Handler
	topic    *topic.Handler
	feed     *feed.Handler
	entry    *entry.Handler
	goal     *goal.Handler
	tag      *tag.Handler
	stats    *stats.Handler
	activity *activity.Handler
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
	mux.HandleFunc("GET /api/bookmarks", h.bookmark.List)
	mux.HandleFunc("GET /api/bookmarks/{slug}", h.bookmark.BySlug)
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
	mux.Handle("POST /api/admin/contents/{id}/reject", authMid(http.HandlerFunc(h.content.Reject)))
	mux.Handle("PATCH /api/admin/contents/{id}/is-public", authMid(http.HandlerFunc(h.content.SetIsPublic)))

	// --- Admin: Bookmarks (Track B M1) ---
	mux.Handle("GET /api/admin/bookmarks", authMid(http.HandlerFunc(h.bookmark.AdminList)))
	mux.Handle("GET /api/admin/bookmarks/{id}", authMid(http.HandlerFunc(h.bookmark.AdminGet)))
	mux.Handle("POST /api/admin/bookmarks", authMid(http.HandlerFunc(h.bookmark.Create)))
	mux.Handle("DELETE /api/admin/bookmarks/{id}", authMid(http.HandlerFunc(h.bookmark.Delete)))

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

	// --- Admin: System ---
	mux.Handle("GET /api/admin/system/health", authMid(http.HandlerFunc(h.stats.SystemHealth)))

	// --- Admin: Upload ---
	if h.upload != nil {
		mux.Handle("POST /api/admin/upload", authMid(http.HandlerFunc(h.upload.Upload)))
	}

	// --- Admin v2: Aggregate workflow endpoints ---
	if h.adminV2 != nil {
		a := h.adminV2

		// Admin frontend is read-only as of 2026-04-09. All write operations
		// (capture/plan/advance/start_session/record_attempt/write_journal/
		// propose_commitment/etc) move to MCP. The endpoints removed below
		// have been deleted from this routing tree per docs/ADMIN-API-REQUIREMENTS.md
		// Section A. Handler methods on the admin package remain for tests
		// and potential reuse by other clients.

		// Today / Overview
		mux.Handle("GET /api/admin/today", authMid(http.HandlerFunc(a.Today)))

		// Goals (read-only)
		mux.Handle("GET /api/admin/plan/goals", authMid(http.HandlerFunc(a.GoalsOverview)))
		mux.Handle("GET /api/admin/plan/goals/{id}", authMid(http.HandlerFunc(a.GoalDetail)))

		// Projects (read-only)
		mux.Handle("GET /api/admin/plan/projects", authMid(http.HandlerFunc(a.ProjectsOverview)))
		mux.Handle("GET /api/admin/plan/projects/{id}", authMid(http.HandlerFunc(a.ProjectDetail)))

		// Library
		mux.Handle("GET /api/admin/library/pipeline", authMid(http.HandlerFunc(a.LibraryPipeline)))

		// Learn (read-only)
		mux.Handle("GET /api/admin/learn/dashboard", authMid(http.HandlerFunc(a.LearnDashboard)))
		mux.Handle("GET /api/admin/learn/concepts/{slug}", authMid(http.HandlerFunc(a.ConceptDrilldown)))
		mux.Handle("GET /api/admin/learn/review-queue", authMid(http.HandlerFunc(a.ReviewQueue)))

		// Learn Plans (read-only)
		mux.Handle("GET /api/admin/learn/plans", authMid(http.HandlerFunc(a.LearnPlans)))
		mux.Handle("GET /api/admin/learn/plans/{id}", authMid(http.HandlerFunc(a.LearnPlanDetail)))

		// Reflect (read-only)
		mux.Handle("GET /api/admin/reflect/daily", authMid(http.HandlerFunc(a.ReflectDaily)))
		mux.Handle("GET /api/admin/reflect/weekly", authMid(http.HandlerFunc(a.ReflectWeekly)))
		mux.Handle("GET /api/admin/reflect/journal", authMid(http.HandlerFunc(a.JournalList)))
		mux.Handle("GET /api/admin/reflect/insights", authMid(http.HandlerFunc(a.InsightsList)))

		// Dashboard
		mux.Handle("GET /api/admin/dashboard/trends", authMid(http.HandlerFunc(a.DashboardTrends)))

		// Studio IPC (read-only — supports ?include_resolved=true)
		mux.Handle("GET /api/admin/studio/overview", authMid(http.HandlerFunc(a.StudioOverview)))

		// MCP tool metadata inventory (read-only — no dispatch)
		mux.Handle("GET /api/admin/ops", authMid(http.HandlerFunc(a.Ops)))
	}
}
