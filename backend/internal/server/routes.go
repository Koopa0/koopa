package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/flow"
	"github.com/koopa0/blog-backend/internal/flowrun"
	"github.com/koopa0/blog-backend/internal/notion"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/review"
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
	Auth      *auth.Handler
	Topic     *topic.Handler
	Content   *content.Handler
	Project   *project.Handler
	Review    *review.Handler
	Collected *collected.Handler
	Tracking  *tracking.Handler
	Pipeline  *pipeline.Handler
	FlowRun   *flowrun.Handler
	Flow      *flow.Handler
	Upload    *upload.Handler
	Feed      *feed.Handler
	Notion    *notion.Handler
	Pool      Pinger
	Logger    *slog.Logger
}

// RegisterRoutes registers all API routes on the given mux.
func RegisterRoutes(mux *http.ServeMux, d Deps, authMid, rlMid func(http.Handler) http.Handler) {
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
	mux.HandleFunc("GET /api/contents/type/{type}", d.Content.ByType)
	mux.HandleFunc("GET /api/topics", d.Topic.List)
	mux.HandleFunc("GET /api/topics/{slug}", d.Topic.BySlug)
	mux.HandleFunc("GET /api/projects", d.Project.List)
	mux.HandleFunc("GET /api/projects/{slug}", d.Project.BySlug)
	mux.HandleFunc("GET /api/contents/{slug}/related", d.Content.Related)
	mux.Handle("GET /api/knowledge-graph", rlMid(http.HandlerFunc(d.Content.KnowledgeGraph)))
	mux.HandleFunc("GET /api/search", d.Content.Search)
	mux.HandleFunc("GET /api/feed/rss", d.Content.RSS)
	mux.HandleFunc("GET /api/feed/sitemap", d.Content.Sitemap)

	// auth — Google OAuth (rate limited)
	mux.HandleFunc("GET /api/auth/google", d.Auth.GoogleLogin)
	mux.Handle("GET /api/auth/google/callback", rlMid(http.HandlerFunc(d.Auth.GoogleCallback)))
	mux.Handle("POST /api/auth/refresh", rlMid(http.HandlerFunc(d.Auth.Refresh)))

	// admin — content
	mux.Handle("POST /api/admin/contents", authMid(http.HandlerFunc(d.Content.Create)))
	mux.Handle("PUT /api/admin/contents/{id}", authMid(http.HandlerFunc(d.Content.Update)))
	mux.Handle("DELETE /api/admin/contents/{id}", authMid(http.HandlerFunc(d.Content.Delete)))
	mux.Handle("POST /api/admin/contents/{id}/publish", authMid(http.HandlerFunc(d.Content.Publish)))

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
	mux.Handle("POST /api/admin/projects", authMid(http.HandlerFunc(d.Project.Create)))
	mux.Handle("PUT /api/admin/projects/{id}", authMid(http.HandlerFunc(d.Project.Update)))
	mux.Handle("DELETE /api/admin/projects/{id}", authMid(http.HandlerFunc(d.Project.Delete)))

	// admin — topics
	mux.Handle("POST /api/admin/topics", authMid(http.HandlerFunc(d.Topic.Create)))
	mux.Handle("PUT /api/admin/topics/{id}", authMid(http.HandlerFunc(d.Topic.Update)))
	mux.Handle("DELETE /api/admin/topics/{id}", authMid(http.HandlerFunc(d.Topic.Delete)))

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

	// admin — upload
	mux.Handle("POST /api/admin/upload", authMid(http.HandlerFunc(d.Upload.Upload)))

	// pipeline stubs
	mux.Handle("POST /api/pipeline/sync", authMid(http.HandlerFunc(d.Pipeline.Sync)))
	mux.Handle("POST /api/pipeline/collect", authMid(http.HandlerFunc(d.Pipeline.Collect)))
	mux.Handle("POST /api/pipeline/generate", authMid(http.HandlerFunc(d.Pipeline.Generate)))
	mux.Handle("POST /api/pipeline/digest", authMid(http.HandlerFunc(d.Pipeline.Digest)))
	mux.Handle("POST /api/pipeline/bookmark", authMid(http.HandlerFunc(d.Pipeline.Bookmark)))

	// webhooks — HMAC-verified, not JWT
	mux.HandleFunc("POST /api/webhook/github", d.Pipeline.WebhookGithub)

	// webhooks — Notion (HMAC-verified)
	mux.HandleFunc("POST /api/webhook/notion", d.Notion.Webhook)

	// webhooks — stubs (JWT-protected until implemented)
	mux.Handle("POST /api/webhook/obsidian", authMid(http.HandlerFunc(d.Pipeline.WebhookObsidian)))

	// admin stats
	mux.Handle("GET /api/admin/stats", authMid(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{"data":{"status":"ok"}}`); err != nil {
			d.Logger.Error("writing stats response", "error", err)
		}
	})))
}
