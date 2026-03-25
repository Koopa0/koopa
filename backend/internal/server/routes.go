package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/goal"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/stats"
	"github.com/koopa0/blog-backend/internal/tag"
	"github.com/koopa0/blog-backend/internal/task"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/tracking"
	"github.com/koopa0/blog-backend/internal/upload"
)

// Pinger checks database connectivity.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps holds all handler dependencies for route registration.
type Deps struct {
	Auth         *auth.Handler
	Topic        *topic.Handler
	Content      *content.Handler
	Project      *project.Handler
	Review       *review.Handler
	Collected    *collected.Handler
	Tracking     *tracking.Handler
	Pipeline     *pipeline.Handler
	FlowRun      *flowrun.Handler
	Flow         *flow.Handler
	Upload       *upload.Handler
	Feed         *feed.Handler
	Notion       *notion.Handler
	Tag          *tag.Handler
	NotionSource *notion.SourceHandler
	Goal         *goal.Handler
	Task         *task.Handler
	Stats        *stats.Handler
	Note         *note.Handler
	Activity     *activity.Handler
	Session      *session.Handler
	Pool         Pinger
	Logger       *slog.Logger
}

// RegisterRoutes registers all API routes on the given mux.
func RegisterRoutes(mux *http.ServeMux, d *Deps, authMid, rlMid func(http.Handler) http.Handler) {
	// health checks — no auth, no middleware
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := d.Pool.Ping(ctx); err != nil {
			d.Logger.Error("readiness check failed", "error", err)
			http.Error(w, "db not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})

	// public
	mux.HandleFunc("GET /api/contents", d.Content.List)
	mux.HandleFunc("GET /api/contents/{slug}", d.Content.BySlug)
	mux.HandleFunc("GET /api/contents/by-type/{type}", d.Content.ByType)
	mux.HandleFunc("GET /api/topics", d.Topic.List)
	mux.HandleFunc("GET /api/topics/{slug}", d.Topic.BySlug)
	mux.HandleFunc("GET /api/projects", d.Project.PublicList)
	mux.HandleFunc("GET /api/projects/{slug}", d.Project.BySlug)
	mux.HandleFunc("GET /api/contents/related/{slug}", d.Content.Related)
	mux.Handle("GET /api/knowledge-graph", rlMid(http.HandlerFunc(d.Content.KnowledgeGraph)))
	mux.HandleFunc("GET /api/search", d.Content.Search)
	mux.HandleFunc("GET /api/feed/rss", d.Content.RSS)
	mux.HandleFunc("GET /api/feed/sitemap", d.Content.Sitemap)

	// auth — Google OAuth (rate limited)
	mux.HandleFunc("GET /api/auth/google", d.Auth.GoogleLogin)
	mux.Handle("GET /api/auth/google/callback", rlMid(http.HandlerFunc(d.Auth.GoogleCallback)))
	mux.Handle("POST /api/auth/refresh", rlMid(http.HandlerFunc(d.Auth.Refresh)))

	// admin — content
	mux.Handle("GET /api/admin/contents", authMid(http.HandlerFunc(d.Content.AdminList)))
	mux.Handle("POST /api/admin/contents", authMid(http.HandlerFunc(d.Content.Create)))
	mux.Handle("PUT /api/admin/contents/{id}", authMid(http.HandlerFunc(d.Content.Update)))
	mux.Handle("DELETE /api/admin/contents/{id}", authMid(http.HandlerFunc(d.Content.Delete)))
	mux.Handle("POST /api/admin/contents/{id}/publish", authMid(http.HandlerFunc(d.Content.Publish)))
	mux.Handle("PATCH /api/admin/contents/{id}/visibility", authMid(http.HandlerFunc(d.Content.SetVisibility)))

	// admin — review
	mux.Handle("GET /api/admin/review", authMid(http.HandlerFunc(d.Review.List)))
	mux.Handle("POST /api/admin/review/{id}/approve", authMid(http.HandlerFunc(d.Review.Approve)))
	mux.Handle("POST /api/admin/review/{id}/reject", authMid(http.HandlerFunc(d.Review.Reject)))
	mux.Handle("PUT /api/admin/review/{id}/edit", authMid(http.HandlerFunc(d.Review.Edit)))

	// admin — collected
	mux.Handle("GET /api/admin/collected", authMid(http.HandlerFunc(d.Collected.List)))
	mux.Handle("POST /api/admin/collected/{id}/curate", authMid(http.HandlerFunc(d.Collected.Curate)))
	mux.Handle("POST /api/admin/collected/{id}/ignore", authMid(http.HandlerFunc(d.Collected.Ignore)))

	// admin — projects
	mux.Handle("GET /api/admin/projects", authMid(http.HandlerFunc(d.Project.List)))
	mux.Handle("POST /api/admin/projects", authMid(http.HandlerFunc(d.Project.Create)))
	mux.Handle("PUT /api/admin/projects/{id}", authMid(http.HandlerFunc(d.Project.Update)))
	mux.Handle("DELETE /api/admin/projects/{id}", authMid(http.HandlerFunc(d.Project.Delete)))

	// admin — goals
	mux.Handle("GET /api/admin/goals", authMid(http.HandlerFunc(d.Goal.List)))
	mux.Handle("PUT /api/admin/goals/{id}/status", authMid(http.HandlerFunc(d.Goal.UpdateStatus)))

	// admin — tasks
	mux.Handle("GET /api/admin/tasks", authMid(http.HandlerFunc(d.Task.List)))
	mux.Handle("GET /api/admin/tasks/pending", authMid(http.HandlerFunc(d.Task.Pending)))
	mux.Handle("POST /api/admin/tasks", authMid(http.HandlerFunc(d.Task.Create)))
	mux.Handle("PUT /api/admin/tasks/{id}", authMid(http.HandlerFunc(d.Task.Update)))
	mux.Handle("POST /api/admin/tasks/{id}/complete", authMid(http.HandlerFunc(d.Task.Complete)))
	mux.Handle("POST /api/admin/tasks/batch-my-day", authMid(http.HandlerFunc(d.Task.BatchMyDay)))

	// admin — topics
	mux.Handle("POST /api/admin/topics", authMid(http.HandlerFunc(d.Topic.Create)))
	mux.Handle("PUT /api/admin/topics/{id}", authMid(http.HandlerFunc(d.Topic.Update)))
	mux.Handle("DELETE /api/admin/topics/{id}", authMid(http.HandlerFunc(d.Topic.Delete)))

	// admin — tags
	mux.Handle("GET /api/admin/tags", authMid(http.HandlerFunc(d.Tag.List)))
	mux.Handle("POST /api/admin/tags", authMid(http.HandlerFunc(d.Tag.Create)))
	mux.Handle("PUT /api/admin/tags/{id}", authMid(http.HandlerFunc(d.Tag.Update)))
	mux.Handle("DELETE /api/admin/tags/{id}", authMid(http.HandlerFunc(d.Tag.Delete)))

	// admin — aliases
	mux.Handle("GET /api/admin/aliases", authMid(http.HandlerFunc(d.Tag.ListAliases)))
	mux.Handle("POST /api/admin/aliases/{id}/map", authMid(http.HandlerFunc(d.Tag.MapAlias)))
	mux.Handle("POST /api/admin/aliases/{id}/confirm", authMid(http.HandlerFunc(d.Tag.ConfirmAlias)))
	mux.Handle("POST /api/admin/aliases/{id}/reject", authMid(http.HandlerFunc(d.Tag.RejectAlias)))
	mux.Handle("DELETE /api/admin/aliases/{id}", authMid(http.HandlerFunc(d.Tag.DeleteAlias)))

	// admin — tag operations
	mux.Handle("POST /api/admin/tags/backfill", authMid(http.HandlerFunc(d.Tag.Backfill)))
	mux.Handle("POST /api/admin/tags/merge", authMid(http.HandlerFunc(d.Tag.Merge)))

	// admin — tracking
	mux.Handle("GET /api/admin/tracking", authMid(http.HandlerFunc(d.Tracking.List)))
	mux.Handle("POST /api/admin/tracking", authMid(http.HandlerFunc(d.Tracking.Create)))
	mux.Handle("PUT /api/admin/tracking/{id}", authMid(http.HandlerFunc(d.Tracking.Update)))
	mux.Handle("DELETE /api/admin/tracking/{id}", authMid(http.HandlerFunc(d.Tracking.Delete)))

	// admin — flow runs
	mux.Handle("GET /api/admin/flow-runs", authMid(http.HandlerFunc(d.FlowRun.List)))
	mux.Handle("GET /api/admin/flow-runs/{id}", authMid(http.HandlerFunc(d.FlowRun.ByID)))
	mux.Handle("POST /api/admin/flow-runs/{id}/retry", authMid(http.HandlerFunc(d.FlowRun.Retry)))

	// admin — flow polish
	mux.Handle("POST /api/admin/flow/polish/{content_id}", authMid(http.HandlerFunc(d.Flow.TriggerPolish)))
	mux.Handle("GET /api/admin/flow/polish/{content_id}/result", authMid(http.HandlerFunc(d.Flow.PolishResult)))
	mux.Handle("POST /api/admin/flow/polish/{content_id}/approve", authMid(http.HandlerFunc(d.Flow.ApprovePolish)))

	// admin — feeds
	mux.Handle("GET /api/admin/feeds", authMid(http.HandlerFunc(d.Feed.List)))
	mux.Handle("POST /api/admin/feeds", authMid(http.HandlerFunc(d.Feed.Create)))
	mux.Handle("PUT /api/admin/feeds/{id}", authMid(http.HandlerFunc(d.Feed.Update)))
	mux.Handle("DELETE /api/admin/feeds/{id}", authMid(http.HandlerFunc(d.Feed.Delete)))
	mux.Handle("POST /api/admin/feeds/{id}/fetch", authMid(http.HandlerFunc(d.Feed.Fetch)))

	// admin — collected feedback
	mux.Handle("POST /api/admin/collected/{id}/feedback", authMid(http.HandlerFunc(d.Collected.SubmitFeedback)))

	// admin — notion sources
	mux.Handle("GET /api/admin/notion-sources/discover", authMid(http.HandlerFunc(d.NotionSource.Discover)))
	mux.Handle("GET /api/admin/notion-sources", authMid(http.HandlerFunc(d.NotionSource.List)))
	mux.Handle("GET /api/admin/notion-sources/{id}", authMid(http.HandlerFunc(d.NotionSource.ByID)))
	mux.Handle("POST /api/admin/notion-sources", authMid(http.HandlerFunc(d.NotionSource.Create)))
	mux.Handle("PUT /api/admin/notion-sources/{id}", authMid(http.HandlerFunc(d.NotionSource.Update)))
	mux.Handle("DELETE /api/admin/notion-sources/{id}", authMid(http.HandlerFunc(d.NotionSource.Delete)))
	mux.Handle("POST /api/admin/notion-sources/{id}/toggle", authMid(http.HandlerFunc(d.NotionSource.Toggle)))
	mux.Handle("PUT /api/admin/notion-sources/{id}/role", authMid(http.HandlerFunc(d.NotionSource.SetRole)))

	// admin — notes (knowledge search)
	mux.Handle("GET /api/admin/notes", authMid(http.HandlerFunc(d.Note.Search)))
	mux.Handle("GET /api/admin/decisions", authMid(http.HandlerFunc(d.Note.DecisionLog)))

	// admin — activity
	mux.Handle("GET /api/admin/activity/sessions", authMid(http.HandlerFunc(d.Activity.Sessions)))
	mux.Handle("GET /api/admin/activity/changelog", authMid(http.HandlerFunc(d.Activity.Changelog)))

	// admin — session notes
	mux.Handle("GET /api/admin/session-notes", authMid(http.HandlerFunc(d.Session.List)))

	// admin — insights (session note subtype)
	mux.Handle("GET /api/admin/insights", authMid(http.HandlerFunc(d.Session.Insights)))
	mux.Handle("PUT /api/admin/insights/{id}", authMid(http.HandlerFunc(d.Session.UpdateInsight)))

	// admin — upload
	mux.Handle("POST /api/admin/upload", authMid(http.HandlerFunc(d.Upload.Upload)))

	// admin — pipeline
	mux.Handle("POST /api/admin/pipeline/sync", authMid(http.HandlerFunc(d.Pipeline.Sync)))
	mux.Handle("POST /api/admin/pipeline/notion-sync", authMid(http.HandlerFunc(d.Pipeline.NotionSync)))
	mux.Handle("POST /api/admin/pipeline/reconcile", authMid(http.HandlerFunc(d.Pipeline.Reconcile)))
	mux.Handle("POST /api/admin/pipeline/collect", authMid(http.HandlerFunc(d.Pipeline.Collect)))
	mux.Handle("POST /api/admin/pipeline/generate", authMid(http.HandlerFunc(d.Pipeline.Generate)))
	mux.Handle("POST /api/admin/pipeline/digest", authMid(http.HandlerFunc(d.Pipeline.Digest)))
	mux.Handle("POST /api/admin/pipeline/bookmark", authMid(http.HandlerFunc(d.Pipeline.Bookmark)))

	// webhooks — HMAC-verified, not JWT
	mux.HandleFunc("POST /api/webhook/github", d.Pipeline.WebhookGithub)

	// webhooks — Notion (HMAC-verified)
	mux.HandleFunc("POST /api/webhook/notion", d.Notion.Webhook)

	// admin — today
	mux.Handle("GET /api/admin/today/summary", authMid(http.HandlerFunc(d.Task.DailySummary)))

	// admin stats
	mux.Handle("GET /api/admin/stats", authMid(http.HandlerFunc(d.Stats.Overview)))
	mux.Handle("GET /api/admin/stats/drift", authMid(http.HandlerFunc(d.Stats.Drift)))
	mux.Handle("GET /api/admin/stats/learning", authMid(http.HandlerFunc(d.Stats.Learning)))
}
