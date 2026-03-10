package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/koopa0/blog-backend/internal/auth"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/pipeline"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/review"
	"github.com/koopa0/blog-backend/internal/topic"
	"github.com/koopa0/blog-backend/internal/tracking"
	"github.com/koopa0/blog-backend/internal/upload"
)

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
	Upload    *upload.Handler
	Logger    *slog.Logger
}

// RegisterRoutes registers all API routes on the given mux.
func RegisterRoutes(mux *http.ServeMux, d Deps, authMid func(http.Handler) http.Handler) {
	// public
	mux.HandleFunc("GET /api/contents", d.Content.List)
	mux.HandleFunc("GET /api/contents/{slug}", d.Content.BySlug)
	mux.HandleFunc("GET /api/contents/type/{type}", d.Content.ByType)
	mux.HandleFunc("GET /api/topics", d.Topic.List)
	mux.HandleFunc("GET /api/topics/{slug}", d.Topic.BySlug)
	mux.HandleFunc("GET /api/projects", d.Project.List)
	mux.HandleFunc("GET /api/projects/{slug}", d.Project.BySlug)
	mux.HandleFunc("GET /api/search", d.Content.Search)
	mux.HandleFunc("GET /api/feed/rss", d.Content.RSS)
	mux.HandleFunc("GET /api/feed/sitemap", d.Content.Sitemap)

	// auth
	mux.HandleFunc("POST /api/auth/login", d.Auth.Login)
	mux.HandleFunc("POST /api/auth/refresh", d.Auth.Refresh)

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

	// admin — upload
	mux.Handle("POST /api/admin/upload", authMid(http.HandlerFunc(d.Upload.Upload)))

	// pipeline stubs
	mux.Handle("POST /api/pipeline/sync", authMid(http.HandlerFunc(d.Pipeline.Sync)))
	mux.Handle("POST /api/pipeline/collect", authMid(http.HandlerFunc(d.Pipeline.Collect)))
	mux.Handle("POST /api/pipeline/generate", authMid(http.HandlerFunc(d.Pipeline.Generate)))
	mux.Handle("POST /api/pipeline/digest", authMid(http.HandlerFunc(d.Pipeline.Digest)))

	// webhooks — HMAC-verified, not JWT
	mux.HandleFunc("POST /api/webhook/github", d.Pipeline.WebhookGithub)

	// webhooks — stubs (JWT-protected until implemented)
	mux.Handle("POST /api/webhook/obsidian", authMid(http.HandlerFunc(d.Pipeline.WebhookObsidian)))
	mux.Handle("POST /api/webhook/notion", authMid(http.HandlerFunc(d.Pipeline.WebhookNotion)))

	// admin stats
	mux.Handle("GET /api/admin/stats", authMid(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprint(w, `{"data":{"status":"ok"}}`); err != nil {
			d.Logger.Error("writing stats response", "error", err)
		}
	})))
}
